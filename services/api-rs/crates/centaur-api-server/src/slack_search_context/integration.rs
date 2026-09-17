use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    routing::post,
};
use centaur_sandbox_core::SandboxSpec;
use centaur_session_sqlx::PgSessionStore;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    ApiAuthConfig, SandboxRuntime, build_router_with_runtime,
    tests::{TestBackend, TestSessionPrincipalRegistrar, principal_token},
};

const ACTION_TOKEN: &str = "synthetic-bound-action-token-canary";
const SOURCE: &str = "synthetic-transient-source-canary";
const ANSWER: &str = "synthetic-transient-answer-canary";
const THREAD: &str = "slack:CORIGIN:90.000001";
const PRINCIPAL: &str = "prn-channel";

type Calls = Arc<Mutex<Vec<(String, Value)>>>;

async fn upstream(
    State(calls): State<Calls>,
    Path(method): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Json<Value> {
    assert_eq!(
        headers.get("authorization").unwrap(),
        if method == "responses" {
            "Bearer synthetic-model-key"
        } else {
            "Bearer synthetic-bot-token"
        }
    );
    calls.lock().unwrap().push((method.clone(), input.clone()));
    Json(match method.as_str() {
        "auth.test" => {
            json!({"ok": true, "team_id": "T1", "bot_id": "BBOT", "user_id": "UBOT", "url": "https://synthetic.slack.com/"})
        }
        "users.info" => json!({"ok": true, "user": {
            "id": "U1", "team_id": "T1", "is_bot": false, "deleted": false,
            "is_restricted": false, "is_ultra_restricted": false
        }}),
        "conversations.info" => json!({"ok": true, "channel": {
            "id": input["channel"], "context_team_id": "T1", "is_channel": true,
            "is_im": false, "is_mpim": false, "is_private": false,
            "is_member": input["channel"] == "CORIGIN", "is_shared": false,
            "is_ext_shared": false, "is_org_shared": false
        }}),
        "conversations.members" => json!({"ok": true, "members": ["U1", "UBOT"]}),
        "users.conversations" => json!({"ok": true, "channels": []}),
        "assistant.search.context" => json!({"ok": true, "results": {"messages": [{
            "channel_id": "CPUBLIC", "team_id": "T1", "message_ts": "100.000001", "content": SOURCE
        }]}}),
        "responses" => json!({"status": "completed", "output": [{
            "type": "message", "content": [{"type": "output_text", "text":
                json!({"answer": ANSWER, "citations": [1]}).to_string()
            }]
        }]}),
        "chat.postEphemeral" => json!({"ok": true, "message_ts": "300.000001"}),
        _ => panic!("unexpected upstream method: {method}"),
    })
}

struct EnvGuard(Vec<(&'static str, Option<String>)>);

impl EnvGuard {
    fn set(values: &[(&'static str, &str)]) -> Self {
        let saved = values
            .iter()
            .map(|(key, _)| (*key, std::env::var(key).ok()))
            .collect();
        for (key, value) in values {
            // SAFETY: the enclosing synchronous test holds MCP_ENV_LOCK until
            // this guard has restored all variables, matching the API tests.
            unsafe { std::env::set_var(key, value) };
        }
        Self(saved)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            // SAFETY: MCP_ENV_LOCK still belongs to the enclosing test.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

async fn request(
    app: &Router,
    path: &str,
    bearer: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("x-slack-action-token", token);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    if status == StatusCode::OK {
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    for canary in [ACTION_TOKEN, SOURCE, ANSWER] {
        assert!(!text.contains(canary));
    }
    (status, serde_json::from_str(&text).unwrap())
}

fn registration() -> Value {
    json!({
        "thread_key": THREAD, "message_id": "90.000002", "channel_id": "CORIGIN",
        "thread_ts": "90.000001", "team_id": "T1", "user_id": "U1"
    })
}

async fn isolated_pool(url: &str) -> (PgPool, PgPool, String) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap();
    let schema = format!("slack_search_api_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("create schema {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let path = path.clone();
            Box::pin(async move {
                sqlx::query(&format!("set search_path to {path}, public"))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    for migration in [
        include_str!("../../../centaur-session-sqlx/migrations/0001_session_control_plane.sql"),
        include_str!(
            "../../../centaur-session-sqlx/migrations/0003_session_iron_control_principal.sql"
        ),
        include_str!("../../../centaur-session-sqlx/migrations/0055_slack_search_contexts.sql"),
    ] {
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
    }
    sqlx::query("insert into sessions (thread_key, harness_type, status, iron_control_principal) values ($1, 'codex', 'ready', $2)")
        .bind(THREAD).bind(PRINCIPAL).execute(&pool).await.unwrap();
    (pool, admin, schema)
}

#[test]
fn slack_search_context_routes_bind_real_storage_to_transient_delivery() {
    let Ok(url) = std::env::var("SESSION_RUNTIME_TEST_DATABASE_URL") else {
        eprintln!("skipping: SESSION_RUNTIME_TEST_DATABASE_URL not set");
        return;
    };
    let _lock = crate::mcp::MCP_ENV_LOCK.lock().unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let (pool, admin, schema) = isolated_pool(&url).await;
        let calls: Calls = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", listener.local_addr().unwrap());
        let mock = Router::new().route("/{method}", post(upstream)).with_state(calls.clone());
        let mock_task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let _env = EnvGuard::set(&[
            ("CENTAUR_JWT_SIGNING_SECRET", "test-secret"),
            ("SLACK_API_URL", &upstream_url),
            ("SLACK_BOT_TOKEN", "synthetic-bot-token"),
            ("OPENAI_BASE_URL", &upstream_url),
            ("OPENAI_API_KEY", "synthetic-model-key"),
            ("SLACK_SEARCH_MODEL", "synthetic-model"),
        ]);
        let app = build_router_with_runtime(
            PgSessionStore::new(pool.clone()),
            SandboxRuntime::backend(Arc::new(TestBackend::default()), SandboxSpec::new("test")),
            TestSessionPrincipalRegistrar,
            ApiAuthConfig::testing_with_slack_ingress("ingress-key", "test-secret"),
        );
        let principal = principal_token(PRINCIPAL);
        let (status, _) = request(&app, "/api/slack/search-context", &principal, Some(ACTION_TOKEN), registration()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, registered) = request(&app, "/api/slack/search-context", "ingress-key", Some(ACTION_TOKEN), registration()).await;
        assert_eq!(status, StatusCode::OK);
        let id = registered["context_id"].as_str().unwrap();
        assert!(Uuid::parse_str(id).is_ok());
        let encrypted: Vec<u8> = sqlx::query_scalar("select encrypted_action_token from slack_search_contexts")
            .fetch_one(&pool).await.unwrap();
        assert!(!encrypted.windows(ACTION_TOKEN.len()).any(|bytes| bytes == ACTION_TOKEN.as_bytes()));
        let (status, retry) = request(&app, "/api/slack/search-context", "ingress-key", Some("replacement-token-must-not-replace"), registration()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retry, registered);
        let same_encrypted: Vec<u8> = sqlx::query_scalar("select encrypted_action_token from slack_search_contexts")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(same_encrypted, encrypted);

        let query = json!({"context_id": id, "query": "What was decided?"});
        let (status, _) = request(&app, "/api/slack/search-answer", &principal, None, query.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN); // No bound running execution yet.
        let metadata = json!({"slack_search_context_id": id, "slack_user_id": "U1", "slack_channel_id": "CORIGIN", "message_id": "90.000002", "slack_home_team_id": "T1"});
        sqlx::query("insert into session_executions (execution_id, thread_key, status, metadata) values ('execution-1', $1, 'running', $2)")
            .bind(THREAD).bind(metadata).execute(&pool).await.unwrap();
        let (status, _) = request(&app, "/api/slack/search-answer", &principal_token("prn-wrong"), None, query.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = request(&app, "/api/slack/search-answer", &principal, None, json!({"context_id": Uuid::new_v4(), "query": "What was decided?"})).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let mut forged = query.clone();
        forged["user_id"] = json!("UOTHER");
        let (status, _) = request(&app, "/api/slack/search-answer", &principal, None, forged).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(calls.lock().unwrap().is_empty());
        let (status, receipt) = request(&app, "/api/slack/search-answer", &principal, None, query.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(receipt, json!({"ok": true, "status": "accepted", "delivery": "ephemeral"}));
        let before_retry = calls.lock().unwrap().len();
        let (status, _) = request(&app, "/api/slack/search-answer", &principal, None, query).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(calls.lock().unwrap().len(), before_retry);

        let recorded = calls.lock().unwrap().clone();
        let search = recorded.iter().find(|(method, _)| method == "assistant.search.context").unwrap();
        assert_eq!(search.1["action_token"], ACTION_TOKEN);
        assert_eq!(search.1["channel_types"], json!(["public_channel"]));
        let model = recorded.iter().find(|(method, _)| method == "responses").unwrap();
        assert_eq!(model.1["store"], false);
        assert!(model.1.to_string().contains(SOURCE));
        assert!(!model.1.to_string().contains(ACTION_TOKEN));
        let delivered: Vec<_> = recorded.iter().filter(|(method, _)| method.starts_with("chat.")).collect();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, "chat.postEphemeral");
        assert_eq!(delivered[0].1["user"], "U1");
        assert_eq!(delivered[0].1["channel"], "CORIGIN");
        assert!(delivered[0].1.get("thread_ts").is_none());
        assert!(delivered[0].1["text"].as_str().unwrap().contains(ANSWER));
        assert!(!delivered[0].1.to_string().contains(ACTION_TOKEN));
        let persisted: (String, Option<Vec<u8>>) = sqlx::query_as("select state, encrypted_action_token from slack_search_contexts")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(persisted, ("accepted".to_owned(), None));
        for table in ["sessions", "session_executions", "session_messages", "session_events", "slack_search_contexts"] {
            let rows: Vec<Value> = sqlx::query_scalar(&format!("select to_jsonb(t) from {table} t"))
                .fetch_all(&pool).await.unwrap();
            let serialized = serde_json::to_string(&rows).unwrap();
            for canary in [ACTION_TOKEN, SOURCE, ANSWER] {
                assert!(!serialized.contains(canary), "canary retained in {table}");
            }
        }
        mock_task.abort();
        drop(app);
        pool.close().await;
        sqlx::query(&format!("drop schema {schema} cascade")).execute(&admin).await.unwrap();
        admin.close().await;
    });
}
