use super::*;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response as AxumResponse},
    routing::post,
};
use std::sync::{Arc, Mutex};

const PUBLIC_CANARY: &str = "synthetic-public-source-canary";
const PRIVATE_CANARY: &str = "synthetic-private-source-canary";
const BLOCKED_CANARY: &str = "synthetic-forbidden-context-canary";
const ANSWER_CANARY: &str = "synthetic-model-answer-canary";

struct Scenario {
    calls: Vec<(String, Value)>,
    public: Value,
    private_ids: Vec<String>,
    channels: BTreeMap<String, Value>,
    user: Value,
    revoked_after_model: Option<String>,
    changed_after_model: Option<String>,
    shared_after_model: Option<String>,
    bot_revoked_after_model: Option<String>,
    absent_member: Option<String>,
    failure: Option<(String, u16, Value)>,
    redirect: Option<String>,
    model_finished: bool,
    model_answer: Value,
    history: Value,
    replies: Value,
}

fn public_channel(id: &str, member: bool) -> Value {
    json!({ "id": id, "context_team_id": "T1", "is_channel": true, "is_group": false,
        "is_im": false, "is_mpim": false, "is_private": false, "is_member": member,
        "is_ext_shared": false, "is_shared": false, "is_org_shared": false })
}

fn private_channel(id: &str) -> Value {
    let mut value = public_channel(id, true);
    value["is_private"] = json!(true);
    value
}

fn fixture() -> Scenario {
    Scenario {
        calls: Vec::new(),
        public: json!({ "ok": true, "results": { "messages": [{
            "channel_id": "CPUBLIC", "team_id": "T1", "message_ts": "100.000001", "content": PUBLIC_CANARY,
            "context_messages": { "before": [{"ts": "100.000000", "text": "safe surrounding context"}] }
        }] } }),
        private_ids: vec!["GPRIVATE".to_owned()],
        channels: BTreeMap::from([
            ("CORIGIN".to_owned(), public_channel("CORIGIN", true)),
            ("CPUBLIC".to_owned(), public_channel("CPUBLIC", false)),
            ("GPRIVATE".to_owned(), private_channel("GPRIVATE")),
        ]),
        user: json!({ "id": "U1", "team_id": "T1", "is_bot": false, "deleted": false,
            "is_restricted": false, "is_ultra_restricted": false }),
        revoked_after_model: None,
        changed_after_model: None,
        shared_after_model: None,
        bot_revoked_after_model: None,
        absent_member: None,
        failure: None,
        redirect: None,
        model_finished: false,
        model_answer: json!({ "answer": ANSWER_CANARY, "citations": [1] }),
        history: json!({ "ok": true, "messages": [{"ts": "200.000001", "text": PRIVATE_CANARY, "reply_count": 1}] }),
        replies: json!({ "ok": true, "messages": [{"ts": "200.000001", "text": PRIVATE_CANARY},
            {"ts": "200.000002", "text": "safe private reply"}] }),
    }
}

fn context() -> SearchContext {
    SearchContext {
        team_id: "T1".to_owned(),
        user_id: "U1".to_owned(),
        channel_id: "CORIGIN".to_owned(),
        thread_ts: Some("90.000001".to_owned()),
    }
}

async fn mock_handler(
    State(state): State<Arc<Mutex<Scenario>>>,
    Path(method): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AxumResponse {
    let mut scenario = state.lock().unwrap();
    if method == "messages" {
        assert_eq!(headers.get("x-api-key").unwrap(), "synthetic-model-key");
        assert_eq!(headers.get("anthropic-version").unwrap(), "2023-06-01");
        assert!(headers.get("authorization").is_none());
    } else {
        let authorization = headers.get("authorization").unwrap().to_str().unwrap();
        assert_eq!(
            authorization,
            if method == "responses" {
                "Bearer synthetic-model-key"
            } else {
                "Bearer synthetic-bot-token"
            }
        );
        assert!(headers.get("x-api-key").is_none());
    }
    scenario.calls.push((method.clone(), body.clone()));
    if scenario.redirect.as_deref() == Some(&method) {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [("location", "/must-not-follow")],
            "redirect",
        )
            .into_response();
    }
    if let Some((name, code, value)) = &scenario.failure
        && name == &method
    {
        return (StatusCode::from_u16(*code).unwrap(), Json(value.clone())).into_response();
    }
    let value = match method.as_str() {
        "auth.test" => {
            json!({ "ok": true, "team_id": "T1", "bot_id": "B1", "user_id": "UBOT", "url": "https://synthetic.slack.com/" })
        }
        "users.info" => json!({ "ok": true, "user": scenario.user }),
        "conversations.info" => {
            let id = body["channel"].as_str().unwrap();
            let mut channel = scenario.channels.get(id).cloned().unwrap_or(Value::Null);
            if scenario.model_finished && scenario.changed_after_model.as_deref() == Some(id) {
                channel["is_private"] = json!(true);
            }
            if scenario.model_finished && scenario.shared_after_model.as_deref() == Some(id) {
                channel["is_shared"] = json!(true);
            }
            if scenario.model_finished && scenario.bot_revoked_after_model.as_deref() == Some(id) {
                channel["is_member"] = json!(false);
            }
            json!({ "ok": true, "channel": channel })
        }
        "conversations.members" => {
            let id = body["channel"].as_str().unwrap();
            let denied = scenario.absent_member.as_deref() == Some(id)
                || (scenario.model_finished && scenario.revoked_after_model.as_deref() == Some(id));
            json!({ "ok": true, "members": if denied { vec!["UBOT"] } else { vec!["U1", "UBOT"] }, "response_metadata": { "next_cursor": "" } })
        }
        "assistant.search.context" => scenario.public.clone(),
        "users.conversations" => {
            json!({ "ok": true, "channels": scenario.private_ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>() })
        }
        "conversations.history" => scenario.history.clone(),
        "conversations.replies" => scenario.replies.clone(),
        "responses" => {
            scenario.model_finished = true;
            json!({ "status": "completed", "output": [{ "type": "message", "content": [{ "type": "output_text", "text": scenario.model_answer.to_string() }] }] })
        }
        "messages" => {
            scenario.model_finished = true;
            json!({ "type": "message", "role": "assistant", "stop_reason": "end_turn",
                "content": [{ "type": "text", "text": scenario.model_answer.to_string() }] })
        }
        "chat.postEphemeral" => json!({ "ok": true, "message_ts": "300.000001" }),
        _ => panic!("unexpected method: {method}"),
    };
    Json(value).into_response()
}

struct Mock {
    state: Arc<Mutex<Scenario>>,
    task: tokio::task::JoinHandle<()>,
    engine: Engine,
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn mock(scenario: Scenario) -> Mock {
    mock_provider(scenario, ModelProvider::OpenAi).await
}

async fn mock_provider(scenario: Scenario, provider: ModelProvider) -> Mock {
    let state = Arc::new(Mutex::new(scenario));
    let app = Router::new()
        .route("/{method}", post(mock_handler))
        .route("/v1/{method}", post(mock_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let engine = Engine::new(Config {
        provider,
        slack_url: url.clone(),
        bot_token: "synthetic-bot-token".to_owned(),
        model_url: url,
        model_key: "synthetic-model-key".to_owned(),
        model: "synthetic-model".to_owned(),
    })
    .unwrap();
    Mock {
        state,
        task,
        engine,
    }
}

fn calls(state: &Arc<Mutex<Scenario>>, method: &str) -> Vec<Value> {
    state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|(name, _)| name == method)
        .map(|(_, value)| value.clone())
        .collect()
}

#[tokio::test]
async fn rejects_nonbot_or_malformed_bot_identity_before_any_retrieval() {
    for identity in [
        json!({"user_id": "U1"}),
        json!({"user_id": "UBOT", "bot_id": "U1"}),
        json!({"bot_id": "B1"}),
        json!({"user_id": "B1", "bot_id": "B1"}),
    ] {
        let mut auth = json!({"ok": true, "team_id": "T1", "url": "https://synthetic.slack.com/"});
        auth.as_object_mut()
            .unwrap()
            .extend(identity.as_object().unwrap().clone());
        let mut scenario = fixture();
        scenario.failure = Some(("auth.test".to_owned(), 200, auth));
        let mock = mock(scenario).await;
        assert!(
            mock.engine
                .answer(&context(), "synthetic-action-token", "query")
                .await
                .is_err()
        );
        assert_eq!(mock.state.lock().unwrap().calls.len(), 1);
        assert!(calls(&mock.state, "assistant.search.context").is_empty());
        assert!(calls(&mock.state, "conversations.history").is_empty());
        assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
    }
}

#[tokio::test]
async fn searches_unjoined_public_and_shared_private_history_then_delivers_only_ephemeral() {
    let mock = mock(fixture()).await;
    mock.engine
        .answer(&context(), "synthetic-action-token", "What was decided?")
        .await
        .unwrap();
    let search = calls(&mock.state, "assistant.search.context");
    assert_eq!(search.len(), 1);
    assert_eq!(search[0]["channel_types"], json!(["public_channel"]));
    assert_eq!(search[0]["content_types"], json!(["messages"]));
    assert_eq!(search[0]["context_channel_id"], "CORIGIN");
    assert_eq!(search[0]["action_token"], "synthetic-action-token");
    let private = calls(&mock.state, "users.conversations");
    assert_eq!(
        private[0],
        json!({ "user": "U1", "types": "private_channel", "exclude_archived": false, "limit": 10 })
    );
    assert_eq!(
        calls(&mock.state, "conversations.history")[0]["channel"],
        "GPRIVATE"
    );
    let model = calls(&mock.state, "responses");
    assert_eq!(model.len(), 1);
    assert_eq!(model[0]["store"], false);
    assert!(model[0].get("tools").is_none());
    assert!(model[0].get("previous_response_id").is_none());
    let input = model[0]["input"].as_str().unwrap();
    assert!(input.contains(PUBLIC_CANARY));
    assert!(input.contains(PRIVATE_CANARY));
    assert!(input.contains("safe private reply"));
    assert!(!input.contains("synthetic-action-token"));
    let delivery = calls(&mock.state, "chat.postEphemeral");
    assert_eq!(delivery.len(), 1);
    assert_eq!(delivery[0]["channel"], "CORIGIN");
    assert_eq!(delivery[0]["user"], "U1");
    assert!(delivery[0].get("thread_ts").is_none());
    let text = delivery[0]["text"].as_str().unwrap();
    assert!(text.contains(ANSWER_CANARY));
    assert!(text.contains("https://synthetic.slack.com/archives/CPUBLIC/p100000001"));
    assert!(text.contains(PRIVATE_COVERAGE));
    assert!(calls(&mock.state, "chat.postMessage").is_empty());
    assert_eq!(
        calls(&mock.state, "conversations.members")
            .iter()
            .filter(|body| body["channel"] == "GPRIVATE")
            .count(),
        2
    );
}

#[tokio::test]
async fn drops_cross_channel_cross_team_and_malformed_nested_context_before_inference() {
    for override_fields in [
        json!({"channel_id": "DSECRET"}),
        json!({"channel": "GSECRET"}),
        json!({"team_id": "TOTHER"}),
        json!({"channel_id": {"id": "CPUBLIC"}}),
        json!({"is_mpim": true}),
        json!({"is_private": true}),
    ] {
        let mut scenario = fixture();
        let mut item = json!({ "ts": "99.000001", "text": BLOCKED_CANARY });
        item.as_object_mut()
            .unwrap()
            .extend(override_fields.as_object().unwrap().clone());
        scenario.public["results"]["messages"][0]["context_messages"]["before"] = json!([item]);
        let mock = mock(scenario).await;
        mock.engine
            .answer(&context(), "synthetic-action-token", "What was decided?")
            .await
            .unwrap();
        assert!(
            !calls(&mock.state, "responses")[0]
                .to_string()
                .contains(BLOCKED_CANARY)
        );
    }
}

#[tokio::test]
async fn rejects_dm_mpim_private_and_malformed_public_search_sources_before_inference() {
    for kind in ["im", "mpim", "private", "malformed"] {
        let mut scenario = fixture();
        let channel = scenario.channels.get_mut("CPUBLIC").unwrap();
        match kind {
            "im" => {
                channel["is_im"] = json!(true);
            }
            "mpim" => {
                channel["is_mpim"] = json!(true);
            }
            "private" => {
                channel["is_private"] = json!(true);
            }
            _ => {
                channel.as_object_mut().unwrap().remove("is_im");
            }
        }
        let mock = mock(scenario).await;
        assert!(
            mock.engine
                .answer(&context(), "synthetic-action-token", "query")
                .await
                .is_err()
        );
        assert!(calls(&mock.state, "responses").is_empty());
        assert!(calls(&mock.state, "conversations.history").is_empty());
        assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
    }
}

#[tokio::test]
async fn rejects_cross_workspace_public_result() {
    let mut scenario = fixture();
    scenario.public["results"]["messages"][0]["team_id"] = json!("TOTHER");
    let mock = mock(scenario).await;
    assert!(
        mock.engine
            .answer(&context(), "synthetic-action-token", "query")
            .await
            .is_err()
    );
    assert!(calls(&mock.state, "responses").is_empty());
}

#[tokio::test]
async fn never_content_reads_dm_mpim_nonmember_or_unjoined_private_candidates() {
    for condition in ["im", "mpim", "bot_not_member", "user_not_member"] {
        let mut scenario = fixture();
        let channel = scenario.channels.get_mut("GPRIVATE").unwrap();
        match condition {
            "im" => channel["is_im"] = json!(true),
            "mpim" => channel["is_mpim"] = json!(true),
            "bot_not_member" => channel["is_member"] = json!(false),
            _ => scenario.absent_member = Some("GPRIVATE".to_owned()),
        }
        let mock = mock(scenario).await;
        assert!(
            mock.engine
                .answer(&context(), "synthetic-action-token", "query")
                .await
                .is_err()
        );
        assert!(calls(&mock.state, "conversations.history").is_empty());
        assert!(calls(&mock.state, "conversations.replies").is_empty());
        assert!(calls(&mock.state, "responses").is_empty());
    }
}

#[tokio::test]
async fn membership_revocation_or_source_access_change_blocks_delivery_after_model() {
    for condition in [
        "private_member",
        "private_bot",
        "origin_member",
        "public_type",
        "public_shared",
        "private_shared",
    ] {
        let mut scenario = fixture();
        match condition {
            "private_member" => scenario.revoked_after_model = Some("GPRIVATE".to_owned()),
            "origin_member" => scenario.revoked_after_model = Some("CORIGIN".to_owned()),
            "private_bot" => scenario.bot_revoked_after_model = Some("GPRIVATE".to_owned()),
            "public_shared" => scenario.shared_after_model = Some("CPUBLIC".to_owned()),
            "private_shared" => scenario.shared_after_model = Some("GPRIVATE".to_owned()),
            _ => scenario.changed_after_model = Some("CPUBLIC".to_owned()),
        }
        let mock = mock(scenario).await;
        assert!(
            mock.engine
                .answer(&context(), "synthetic-action-token", "query")
                .await
                .is_err()
        );
        assert_eq!(calls(&mock.state, "responses").len(), 1);
        assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
    }
}

#[tokio::test]
async fn rejects_mpim_origin_before_search_or_content_read() {
    let mut scenario = fixture();
    scenario.channels.insert(
        "GORIGIN".to_owned(),
        json!({"id": "GORIGIN", "is_im": false, "is_mpim": true, "is_member": true}),
    );
    let mock = mock(scenario).await;
    let mut context = context();
    context.channel_id = "GORIGIN".to_owned();
    assert!(
        mock.engine
            .answer(&context, "synthetic-action-token", "query")
            .await
            .is_err()
    );
    for method in [
        "assistant.search.context",
        "conversations.history",
        "conversations.replies",
        "responses",
        "chat.postEphemeral",
    ] {
        assert!(calls(&mock.state, method).is_empty());
    }
}

#[tokio::test]
async fn rejects_conflicting_private_message_source_metadata_before_model() {
    for conflicting in [
        json!({"is_im": true}),
        json!({"is_mpim": true}),
        json!({"is_private": false}),
        json!({"channel_type": "mpim"}),
        json!({"team_id": "TOTHER"}),
    ] {
        let mut scenario = fixture();
        scenario.history["messages"][0]
            .as_object_mut()
            .unwrap()
            .extend(conflicting.as_object().unwrap().clone());
        let mock = mock(scenario).await;
        assert!(
            mock.engine
                .answer(&context(), "synthetic-action-token", "query")
                .await
                .is_err()
        );
        assert!(calls(&mock.state, "responses").is_empty());
        assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
    }
}

#[tokio::test]
async fn rejects_guest_bot_deleted_and_foreign_recipients_before_search() {
    for condition in [
        "is_restricted",
        "is_ultra_restricted",
        "is_bot",
        "deleted",
        "team_id",
    ] {
        let mut scenario = fixture();
        scenario.user[condition] = if condition == "team_id" {
            json!("TOTHER")
        } else {
            json!(true)
        };
        let mock = mock(scenario).await;
        assert!(
            mock.engine
                .answer(&context(), "synthetic-action-token", "query")
                .await
                .is_err()
        );
        assert!(calls(&mock.state, "assistant.search.context").is_empty());
    }
}

#[tokio::test]
async fn verifies_direct_message_counterpart_without_reading_dm_history() {
    for matching in [true, false] {
        let mut scenario = fixture();
        scenario.channels.insert("DORIGIN".to_owned(), json!({"id": "DORIGIN", "is_im": true, "is_mpim": false, "user": if matching {"U1"} else {"UOTHER"}}));
        let mock = mock(scenario).await;
        let mut context = context();
        context.channel_id = "DORIGIN".to_owned();
        let result = mock
            .engine
            .answer(&context, "synthetic-action-token", "query")
            .await;
        assert_eq!(result.is_ok(), matching);
        assert!(
            calls(&mock.state, "conversations.history")
                .iter()
                .all(|body| body["channel"] != "DORIGIN")
        );
        assert!(
            calls(&mock.state, "conversations.replies")
                .iter()
                .all(|body| body["channel"] != "DORIGIN")
        );
    }
}

#[tokio::test]
async fn rejects_unknown_or_malformed_channel_sharing_status() {
    for channel_id in ["CORIGIN", "CPUBLIC"] {
        for field in [
            "missing_is_shared",
            "is_shared",
            "is_ext_shared",
            "is_org_shared",
            "is_pending_ext_shared",
        ] {
            let mut scenario = fixture();
            let channel = scenario.channels.get_mut(channel_id).unwrap();
            if field == "missing_is_shared" {
                channel.as_object_mut().unwrap().remove("is_shared");
            } else {
                channel[field] = json!("false");
            }
            let mock = mock(scenario).await;
            assert!(
                mock.engine
                    .answer(&context(), "synthetic-action-token", "query")
                    .await
                    .is_err()
            );
            if channel_id == "CORIGIN" {
                assert!(calls(&mock.state, "assistant.search.context").is_empty());
            }
            assert!(calls(&mock.state, "conversations.history").is_empty());
            assert!(calls(&mock.state, "responses").is_empty());
            assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
        }
    }
}

#[tokio::test]
async fn shared_origin_accepts_only_current_channel_and_skips_private_discovery() {
    for matching in [true, false] {
        let mut scenario = fixture();
        scenario.channels.get_mut("CORIGIN").unwrap()["is_ext_shared"] = json!(true);
        if matching {
            scenario.public["results"]["messages"][0]["channel_id"] = json!("CORIGIN");
        }
        let mock = mock(scenario).await;
        let result = mock
            .engine
            .answer(&context(), "synthetic-action-token", "query")
            .await;
        assert_eq!(result.is_ok(), matching);
        assert!(calls(&mock.state, "users.conversations").is_empty());
        assert!(calls(&mock.state, "conversations.history").is_empty());
    }
}

#[tokio::test]
async fn bounds_private_channel_root_and_thread_coverage() {
    let mut scenario = fixture();
    scenario.private_ids = (0..12).map(|index| format!("G{index}")).collect();
    for id in &scenario.private_ids {
        scenario.channels.insert(id.clone(), private_channel(id));
    }
    scenario.history["messages"] = json!((0..20).map(|index| json!({"ts": format!("200.{index:06}"), "text": PRIVATE_CANARY, "reply_count": 1})).collect::<Vec<_>>());
    scenario.replies["messages"] = json!(
        (0..70)
            .map(
                |index| json!({"ts": format!("300.{index:06}"), "text": "private thread evidence"})
            )
            .collect::<Vec<_>>()
    );
    let mock = mock(scenario).await;
    mock.engine
        .answer(&context(), "synthetic-action-token", "query")
        .await
        .unwrap();
    let history = calls(&mock.state, "conversations.history");
    assert_eq!(history.len(), PRIVATE_CHANNELS);
    assert!(
        history
            .iter()
            .all(|body| body["limit"] == ROOTS_PER_CHANNEL)
    );
    let replies = calls(&mock.state, "conversations.replies");
    assert_eq!(replies.len(), PRIVATE_THREADS);
    assert!(replies.iter().all(|body| body["limit"] == THREAD_REPLIES));
    let model = calls(&mock.state, "responses");
    assert!(model[0]["input"].as_str().unwrap().len() < 96_000);
}

#[tokio::test]
async fn upstream_echoed_content_never_appears_in_errors_or_normal_messages() {
    for (method, status) in [
        ("assistant.search.context", 500),
        ("assistant.search.context", 200),
        ("responses", 400),
        ("chat.postEphemeral", 200),
    ] {
        let mut scenario = fixture();
        scenario.failure = Some((
            method.to_owned(),
            status,
            json!({"ok": false, "error": format!("{BLOCKED_CANARY} {PRIVATE_CANARY}"), "body": ANSWER_CANARY}),
        ));
        let mock = mock(scenario).await;
        let error = mock
            .engine
            .answer(&context(), "synthetic-action-token", "query")
            .await
            .unwrap_err();
        let rendered = format!("{error} {error:?}");
        for canary in [BLOCKED_CANARY, PRIVATE_CANARY, ANSWER_CANARY] {
            assert!(!rendered.contains(canary));
        }
        assert!(calls(&mock.state, "chat.postMessage").is_empty());
        if method != "chat.postEphemeral" {
            assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
        }
    }
}

#[tokio::test]
async fn does_not_follow_upstream_redirects() {
    let mut scenario = fixture();
    scenario.redirect = Some("assistant.search.context".to_owned());
    let mock = mock(scenario).await;
    assert!(
        mock.engine
            .answer(&context(), "synthetic-action-token", "query")
            .await
            .is_err()
    );
    assert!(calls(&mock.state, "must-not-follow").is_empty());
    assert!(calls(&mock.state, "responses").is_empty());
}

#[tokio::test]
async fn oversized_upstream_response_is_rejected_without_echoing_it() {
    let mut scenario = fixture();
    scenario.public["padding"] =
        json!(BLOCKED_CANARY.repeat(MAX_RESPONSE_BYTES / BLOCKED_CANARY.len() + 1));
    let mock = mock(scenario).await;
    let error = mock
        .engine
        .answer(&context(), "synthetic-action-token", "query")
        .await
        .unwrap_err();
    assert!(!error.to_string().contains(BLOCKED_CANARY));
    assert!(calls(&mock.state, "responses").is_empty());
}

#[tokio::test]
async fn invalid_model_citation_prevents_delivery() {
    let mut scenario = fixture();
    scenario.model_answer["citations"] = json!([999]);
    let mock = mock(scenario).await;
    assert!(
        mock.engine
            .answer(&context(), "synthetic-action-token", "query")
            .await
            .is_err()
    );
    assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
}

#[test]
fn sensitive_errors_and_config_rejections_are_fixed_codes() {
    assert!(
        !api_base(format!("https://{BLOCKED_CANARY}@example.test"))
            .unwrap_err()
            .to_string()
            .contains(BLOCKED_CANARY)
    );
    assert!(workspace_url("https://slack.com.evil.test/").is_err());
    assert!(workspace_url("https://workspace.slack.com/?secret=value").is_err());
    assert!(!valid_id("G123&token=secret", b"CG"));
    assert!(!valid_ts("1.23&token=secret"));
}

#[tokio::test]
async fn anthropic_synthesizes_one_stateless_structured_answer_and_only_delivers_ephemeral() {
    let mock = mock_provider(fixture(), ModelProvider::Anthropic).await;
    mock.engine
        .answer(&context(), "synthetic-action-token", "What was decided?")
        .await
        .unwrap();
    let model = calls(&mock.state, "messages");
    assert_eq!(model.len(), 1);
    let request = &model[0];
    assert_eq!(request["max_tokens"], 1200);
    assert_eq!(request["stream"], false);
    assert_eq!(request["system"], MODEL_INSTRUCTIONS);
    assert_eq!(request["output_config"]["format"]["type"], "json_schema");
    let schema = &request["output_config"]["format"]["schema"];
    assert_eq!(schema["required"], json!(["answer", "citations"]));
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["citations"]["items"]["type"],
        "integer"
    );
    assert_eq!(request["messages"].as_array().unwrap().len(), 1);
    assert_eq!(request["messages"][0]["role"], "user");
    let input = request["messages"][0]["content"].as_str().unwrap();
    assert!(input.contains(PUBLIC_CANARY) && input.contains(PRIVATE_CANARY));
    assert!(!input.contains("synthetic-action-token"));
    for field in [
        "tools",
        "cache_control",
        "container",
        "previous_response_id",
        "metadata",
    ] {
        assert!(request.get(field).is_none());
    }
    assert!(calls(&mock.state, "responses").is_empty());
    let delivery = calls(&mock.state, "chat.postEphemeral");
    assert_eq!(delivery.len(), 1);
    assert_eq!(delivery[0]["channel"], "CORIGIN");
    assert_eq!(delivery[0]["user"], "U1");
    assert!(
        delivery[0]["text"]
            .as_str()
            .unwrap()
            .contains(ANSWER_CANARY)
    );
    assert!(calls(&mock.state, "chat.postMessage").is_empty());
}

#[tokio::test]
async fn anthropic_errors_refusals_truncation_and_invalid_citations_never_deliver_or_fallback() {
    let text = json!({ "answer": ANSWER_CANARY, "citations": [1] }).to_string();
    for (status, response) in [
        (401, json!({"error": {"message": BLOCKED_CANARY}})),
        (429, json!({"error": {"message": BLOCKED_CANARY}})),
        (
            200,
            json!({"type":"message","role":"assistant","stop_reason":"refusal","content":[{"type":"text","text":BLOCKED_CANARY}]}),
        ),
        (
            200,
            json!({"type":"message","role":"assistant","stop_reason":"max_tokens","content":[{"type":"text","text":text}]}),
        ),
        (
            200,
            json!({"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"tool_use","input":BLOCKED_CANARY}]}),
        ),
        (
            200,
            json!({"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":BLOCKED_CANARY}]}),
        ),
        (
            200,
            json!({"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":json!({"answer":ANSWER_CANARY,"citations":[999]}).to_string()}]}),
        ),
    ] {
        let mut scenario = fixture();
        scenario.failure = Some(("messages".to_owned(), status, response));
        let mock = mock_provider(scenario, ModelProvider::Anthropic).await;
        let error = mock
            .engine
            .answer(&context(), "synthetic-action-token", "query")
            .await
            .unwrap_err();
        assert!(!error.to_string().contains(BLOCKED_CANARY));
        assert!(!error.to_string().contains(ANSWER_CANARY));
        assert_eq!(calls(&mock.state, "messages").len(), 1);
        assert!(calls(&mock.state, "responses").is_empty());
        assert!(calls(&mock.state, "chat.postEphemeral").is_empty());
    }
}

#[test]
fn provider_config_is_explicit_and_never_uses_the_other_provider_key() {
    struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                // SAFETY: this test holds MCP_ENV_LOCK until restoration finishes.
                unsafe {
                    if let Some(value) = value {
                        std::env::set_var(key, value);
                    } else {
                        std::env::remove_var(key);
                    }
                }
            }
        }
    }
    let _lock = crate::mcp::MCP_ENV_LOCK.lock().unwrap();
    let keys = [
        "SLACK_SEARCH_PROVIDER",
        "SLACK_SEARCH_MODEL",
        "SLACK_API_URL",
        "SLACK_BOT_TOKEN",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
    ];
    let _restore = RestoreEnv(
        keys.into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
    );
    // SAFETY: environment-mutating API tests coordinate through MCP_ENV_LOCK.
    unsafe {
        for key in keys {
            std::env::remove_var(key);
        }
        std::env::set_var("SLACK_BOT_TOKEN", "synthetic-bot-token");
        std::env::set_var("OPENAI_API_KEY", "synthetic-openai-key");
        std::env::set_var("ANTHROPIC_API_KEY", "synthetic-anthropic-key");
    }
    let openai = Config::from_env().unwrap();
    assert!(openai.provider == ModelProvider::OpenAi);
    assert_eq!(openai.model, "gpt-5.4-mini");
    assert_eq!(openai.model_url, "https://api.openai.com/v1");
    assert_eq!(openai.model_key, "synthetic-openai-key");
    // SAFETY: the same lock covers all provider configurations in this test.
    unsafe {
        std::env::set_var("SLACK_SEARCH_PROVIDER", "anthropic");
    }
    let anthropic = Config::from_env().unwrap();
    assert!(anthropic.provider == ModelProvider::Anthropic);
    assert_eq!(anthropic.model, "claude-haiku-4-5-20251001");
    assert_eq!(anthropic.model_url, "https://api.anthropic.com");
    assert_eq!(anthropic.model_key, "synthetic-anthropic-key");
    // SAFETY: the same lock protects the override and missing-key checks.
    unsafe {
        std::env::set_var("ANTHROPIC_BASE_URL", "https://model.example.test/");
        std::env::set_var("SLACK_SEARCH_MODEL", "explicit-approved-model");
    }
    let custom = Config::from_env().unwrap();
    assert_eq!(custom.model_url, "https://model.example.test");
    assert_eq!(custom.model, "explicit-approved-model");
    unsafe {
        std::env::remove_var("ANTHROPIC_API_KEY");
    }
    assert!(
        matches!(Config::from_env(), Err(ApiError::ServiceUnavailable(code)) if code == "slack_search_not_configured")
    );
    unsafe {
        std::env::set_var("SLACK_SEARCH_PROVIDER", BLOCKED_CANARY);
    }
    assert!(
        matches!(Config::from_env(), Err(ApiError::ServiceUnavailable(code)) if code == "slack_search_not_configured")
    );
}
