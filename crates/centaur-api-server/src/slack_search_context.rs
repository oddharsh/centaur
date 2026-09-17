//! Short-lived credentials for the transient Slack search operation. Only the
//! signed Slack ingress may register them. Claim requires the registered
//! session's principal, its active event binding, and the single-use context
//! UUID; it does not authenticate a particular sandbox process. Neither source
//! messages nor synthesized answers enter this store.

use std::time::Duration;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, AeadCore, OsRng, Payload},
};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use centaur_session_core::{ChatDestination, ThreadKey};
use centaur_session_sqlx::{
    PgSlackSearchContexts, RegisterSlackSearchContext, SlackSearchContextError,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    ApiError,
    auth::{AuthenticatedCaller, CallerClass},
    routes::AppState,
    slack_search::SearchContext,
};

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/slack/search-context", post(register))
        .route("/api/slack/search-answer", post(answer))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(no_store))
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    thread_key: String,
    message_id: String,
    team_id: String,
    user_id: String,
    channel_id: String,
    thread_ts: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerRequest {
    context_id: String,
    query: String,
}

fn denied() -> ApiError {
    ApiError::Forbidden("slack_search_access_denied".to_owned())
}

fn unavailable() -> ApiError {
    ApiError::ServiceUnavailable("slack_search_unavailable".to_owned())
}

fn invalid() -> ApiError {
    ApiError::BadRequest("slack_search_invalid_request".to_owned())
}

fn repository_error(error: SlackSearchContextError) -> ApiError {
    match error {
        SlackSearchContextError::Denied => denied(),
        SlackSearchContextError::Unavailable | SlackSearchContextError::Sqlx(_) => unavailable(),
    }
}

fn valid_id(value: &str, prefixes: &[u8]) -> bool {
    (2..=64).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| prefixes.contains(byte))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_ts(value: &str) -> bool {
    value.len() <= 32
        && value.split_once('.').is_some_and(|(seconds, fraction)| {
            !seconds.is_empty()
                && !fraction.is_empty()
                && seconds
                    .bytes()
                    .chain(fraction.bytes())
                    .all(|byte| byte.is_ascii_digit())
        })
}

fn validate_registration(request: &RegisterRequest) -> Result<(), ApiError> {
    // Legacy Slack DM sessions use the channel root with an empty thread suffix.
    // This is a reply destination only; live retrieval never uses DM history.
    let legacy_dm_root = request.channel_id.starts_with('D')
        && request.thread_ts.as_deref() == Some("")
        && request.thread_key == format!("slack:{}:", request.channel_id);
    if !valid_id(&request.team_id, b"TE")
        || !valid_id(&request.user_id, b"UW")
        || !valid_id(&request.channel_id, b"CGD")
        || !valid_ts(&request.message_id)
        || !(legacy_dm_root || request.thread_ts.as_deref().is_some_and(valid_ts))
    {
        return Err(invalid());
    }
    if legacy_dm_root {
        return Ok(());
    }
    let thread = ThreadKey::try_from(request.thread_key.clone()).map_err(|_| invalid())?;
    match thread.chat_destination() {
        Some(ChatDestination::Slack {
            channel_id,
            thread_ts,
        }) if channel_id == request.channel_id
            && Some(&thread_ts) == request.thread_ts.as_ref() =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

async fn register(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthenticatedCaller>,
    headers: HeaderMap,
    payload: Result<Json<RegisterRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    if caller.class() != CallerClass::Ingress || caller.identity() != "slackbot" {
        return Err(denied());
    }
    let Json(request) = payload.map_err(|_| invalid())?;
    validate_registration(&request)?;
    let token = headers
        .get("x-slack-action-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 4096)
        .ok_or_else(invalid)?;
    let context_id = Uuid::new_v4().to_string();
    let secret = crate::api_jwt::jwt_signing_secret().ok_or_else(unavailable)?;
    let ciphertext = seal(&secret, &context_id, token)?;
    let context_id = PgSlackSearchContexts::new(state.pool()?)
        .register(RegisterSlackSearchContext {
            context_id,
            thread_key: request.thread_key,
            message_id: request.message_id,
            team_id: request.team_id,
            user_id: request.user_id,
            channel_id: request.channel_id,
            thread_ts: request.thread_ts,
            encrypted_action_token: ciphertext,
        })
        .await
        .map_err(repository_error)?;
    Ok(Json(json!({"ok": true, "context_id": context_id})).into_response())
}

async fn answer(
    State(state): State<AppState>,
    Extension(caller): Extension<AuthenticatedCaller>,
    payload: Result<Json<AnswerRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, ApiError> {
    let principal = caller.principal_subject().ok_or_else(denied)?;
    let Json(request) = payload.map_err(|_| invalid())?;
    if Uuid::parse_str(&request.context_id).is_err()
        || request.query.trim().is_empty()
        || request.query.chars().count() > 4000
        || request.query.contains('\0')
    {
        return Err(invalid());
    }
    let secret = crate::api_jwt::jwt_signing_secret().ok_or_else(unavailable)?;
    let repository = PgSlackSearchContexts::new(state.pool()?);
    // Claim erases the stored credential before any external request. Crashes or
    // uncertain Slack delivery must never replay the action and double-send.
    let claimed = repository
        .claim(&request.context_id, principal)
        .await
        .map_err(repository_error)?;
    let result = match open(
        &secret,
        &request.context_id,
        &claimed.encrypted_action_token,
    ) {
        Ok(token) => {
            crate::slack_search::answer(
                &SearchContext {
                    team_id: claimed.team_id,
                    user_id: claimed.user_id,
                    channel_id: claimed.channel_id,
                    thread_ts: claimed.thread_ts.filter(|ts| !ts.is_empty()),
                },
                &token,
                &request.query,
            )
            .await
        }
        Err(error) => Err(error),
    };
    repository
        .finish(&request.context_id, result.is_ok())
        .await
        .map_err(repository_error)?;
    result?;
    Ok(Json(json!({"ok": true, "status": "accepted", "delivery": "ephemeral"})).into_response())
}

fn cipher(secret: &str) -> Result<Aes256Gcm, ApiError> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|_| unavailable())?;
    mac.update(b"centaur/slack-search/action-token/v1");
    Aes256Gcm::new_from_slice(&mac.finalize().into_bytes()).map_err(|_| unavailable())
}

fn seal(secret: &str, context_id: &str, token: &str) -> Result<Vec<u8>, ApiError> {
    let cipher = cipher(secret)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: token.as_bytes(),
                aad: context_id.as_bytes(),
            },
        )
        .map_err(|_| unavailable())?;
    let mut envelope = Vec::with_capacity(13 + ciphertext.len());
    envelope.push(1);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn open(secret: &str, context_id: &str, envelope: &[u8]) -> Result<String, ApiError> {
    if envelope.len() < 29 || envelope[0] != 1 {
        return Err(unavailable());
    }
    let plaintext = cipher(secret)?
        .decrypt(
            envelope[1..13].into(),
            Payload {
                msg: &envelope[13..],
                aad: context_id.as_bytes(),
            },
        )
        .map_err(|_| unavailable())?;
    String::from_utf8(plaintext).map_err(|_| unavailable())
}

/// Expiry is checked synchronously on every use. This task also removes unused
/// encrypted credentials after expiry and trims operational rows after a day.
pub fn spawn_slack_search_cleanup(pool: PgPool) {
    tokio::spawn(async move {
        let repository = PgSlackSearchContexts::new(pool);
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if repository.cleanup().await.is_err() {
                tracing::warn!("slack_search_credential_cleanup_failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_randomized_authenticated_and_context_bound() {
        let token = "SYNTHETIC-ACTION-TOKEN-CANARY";
        let one = seal("test-secret", "context-one", token).unwrap();
        let two = seal("test-secret", "context-one", token).unwrap();
        assert_ne!(one, two);
        assert!(
            !one.windows(token.len())
                .any(|window| window == token.as_bytes())
        );
        assert_eq!(open("test-secret", "context-one", &one).unwrap(), token);
        assert!(open("wrong-secret", "context-one", &one).is_err());
        assert!(open("test-secret", "context-two", &one).is_err());
        let mut tampered = one;
        tampered[20] ^= 1;
        assert!(open("test-secret", "context-one", &tampered).is_err());
        for malformed in [vec![], vec![1; 28], vec![0; 30]] {
            assert!(open("test-secret", "context-one", &malformed).is_err());
        }
    }

    #[test]
    fn registration_requires_the_exact_slack_thread() {
        let mut request = RegisterRequest {
            thread_key: "slack:C123:123.456".into(),
            message_id: "124.456".into(),
            team_id: "T123".into(),
            user_id: "U123".into(),
            channel_id: "C123".into(),
            thread_ts: Some("123.456".into()),
        };
        assert!(validate_registration(&request).is_ok());
        request.channel_id = "C456".into();
        assert!(validate_registration(&request).is_err());
        request.channel_id = "D123".into();
        request.thread_key = "slack:D123:123.456".into();
        assert!(validate_registration(&request).is_ok()); // DM destination, never a source.
        request.thread_key = "slack:D123:".into();
        request.thread_ts = Some("".into());
        assert!(validate_registration(&request).is_ok());
        request.thread_key = "slack:D456:".into();
        assert!(validate_registration(&request).is_err());
        request.thread_ts = Some("123.456".into());
        request.channel_id = "G123".into();
        request.thread_key = "slack:G123:123.456".into();
        assert!(validate_registration(&request).is_ok()); // Actual MPIM flags checked live.
        request.thread_ts = Some("123.457".into());
        assert!(validate_registration(&request).is_err());
        request.thread_ts = None;
        assert!(validate_registration(&request).is_err());
    }
}

#[cfg(test)]
mod integration;
