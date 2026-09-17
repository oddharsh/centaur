//! Alternate entry points must not reactivate a retired Slack harness.
use super::*;

async fn seeded_running_slack(
    store: &PgSessionStore,
    enrolled: bool,
    execution_epoch: Option<&str>,
    recorded: Vec<String>,
) -> (SessionRuntime, ThreadKey, Arc<MockBackend>, String) {
    let thread = ThreadKey::parse(format!("slack:CALT:{}", uuid::Uuid::new_v4())).unwrap();
    store
        .create_or_get_session(
            &thread,
            &HarnessType::Codex,
            None,
            json!({}),
            BTreeMap::new(),
        )
        .await
        .unwrap();
    store
        .bind_iron_control_principal(&thread, "prn_test")
        .await
        .unwrap();
    store
        .set_slack_search_epoch(&thread, "test-epoch")
        .await
        .unwrap();
    store
        .update_sandbox_id(&thread, Some("old-slack-sandbox"))
        .await
        .unwrap();
    let metadata = execution_epoch.map_or_else(
        || json!({}),
        |epoch| json!({(centaur_iron_control::SLACK_SEARCH_EPOCH_LABEL): epoch}),
    );
    let created = store
        .create_execution(&thread, None, metadata)
        .await
        .unwrap();
    let id = created.execution.execution_id;
    store.mark_execution_running(&id).await.unwrap();
    let backend = Arc::new(MockBackend::new(SandboxStatus::Running, recorded));
    let mut runtime = SessionRuntime::new(
        store.clone(),
        SandboxRuntime::backend(backend.clone(), SandboxSpec::new("mock")),
        EpochRegistrar(Arc::new(AtomicBool::new(enrolled))),
    );
    runtime.slack_search_epoch = Some("test-epoch".to_owned());
    (runtime, thread, backend, id)
}

#[tokio::test]
async fn slack_search_alternate_paths_reject_legacy_execution_and_revoked_enrollment() {
    let Some(store) = test_store().await else {
        return;
    };
    let _serial = TEST_LOCK.lock().await;
    for (enrolled, epoch, expected_error) in [
        (true, None, "slack_search_pre_epoch_execution_denied"),
        (
            false,
            Some("test-epoch"),
            "slack_search_enrollment_required",
        ),
    ] {
        let canary = "synthetic-retired-harness-output-canary";
        let (runtime, thread, backend, id) =
            seeded_running_slack(&store, enrolled, epoch, completed_output_lines(canary)).await;
        runtime
            .append_messages(
                &thread,
                &[SessionMessageInput {
                    client_message_id: Some("live-steering-event".to_owned()),
                    role: MessageRole::User,
                    parts: vec![json!({"type":"text", "text":"current user message"})],
                    metadata: json!({}),
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            backend.opens(),
            0,
            "append must not open retired input pipe"
        );
        let rows = events(&store, &thread).await;
        assert!(
            rows.iter()
                .any(|event| event.event_type == "session.steering_failed"
                    && event.payload.to_string().contains(expected_error))
        );
        match runtime.stream_events(&thread, 0, Some(&id)).await {
            Ok(_) => panic!("event stream must not reattach retired harness"),
            Err(error) => assert!(error.to_string().contains(expected_error)),
        }
        let execution = store
            .active_execution_for_thread(&thread)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            runtime
                .adopt_orphaned_execution(&execution, false, None)
                .await
                .unwrap(),
            OrphanAdoption::Failed
        );
        assert_eq!(backend.opens(), 0);
        assert!(
            !events(&store, &thread)
                .await
                .iter()
                .any(|event| event.payload.to_string().contains(canary))
        );
        assert_eq!(
            store
                .latest_execution_for_thread(&thread)
                .await
                .unwrap()
                .unwrap()
                .status,
            ExecutionStatus::Failed
        );
    }
}

#[tokio::test]
async fn slack_search_current_epoch_orphan_still_recovers_recorded_output() {
    let Some(store) = test_store().await else {
        return;
    };
    let _serial = TEST_LOCK.lock().await;
    let canary = "synthetic-current-epoch-output";
    let (runtime, thread, backend, _id) = seeded_running_slack(
        &store,
        true,
        Some("test-epoch"),
        completed_output_lines(canary),
    )
    .await;
    let execution = store
        .active_execution_for_thread(&thread)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .adopt_orphaned_execution(&execution, false, None)
            .await
            .unwrap(),
        OrphanAdoption::Adopted
    );
    assert!(
        events(&store, &thread)
            .await
            .iter()
            .any(|event| event.payload.to_string().contains(canary))
    );
    assert_eq!(
        store
            .latest_execution_for_thread(&thread)
            .await
            .unwrap()
            .unwrap()
            .status,
        ExecutionStatus::Completed
    );
    assert_eq!(
        backend.opens(),
        0,
        "recorded terminal output needs no live attach"
    );
}
