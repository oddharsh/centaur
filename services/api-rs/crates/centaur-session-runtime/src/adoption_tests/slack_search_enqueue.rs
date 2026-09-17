//! HTTP enqueue admission must persist the same trusted epoch as direct calls.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slack_search_enqueue_stamps_before_persistence_and_completes() {
    let Some(store) = test_store().await else {
        return;
    };
    let _serial = TEST_LOCK.lock().await;
    let thread = ThreadKey::parse(format!("slack:CQUEUE:{}", uuid::Uuid::new_v4())).unwrap();
    let enrolled = Arc::new(AtomicBool::new(true));
    let backend = Arc::new(MockBackend::new(SandboxStatus::Running, Vec::new()));
    let create_gate = backend.hold_create();
    let (io, mut stdout, _stdin) = mock_io();
    backend.push_io(io).await;
    let mut runtime = SessionRuntime::new(
        store.clone(),
        SandboxRuntime::backend(backend.clone(), SandboxSpec::new("mock")),
        EpochRegistrar(enrolled.clone()),
    );
    runtime.slack_search_epoch = Some("test-epoch".to_owned());
    runtime
        .create_or_get_session(
            &thread,
            &HarnessType::Codex,
            None,
            None,
            HarnessConflictPolicy::Reject,
        )
        .await
        .expect("initialize enrolled Slack session");
    let mut input = epoch_input();
    input.metadata =
        Some(json!({"centaur.slack_search_epoch":"untrusted-epoch", "source":"queue-regression"}));
    let execution = timeout(
        Duration::from_secs(2),
        runtime.enqueue_session_execution(&thread, input.clone()),
    )
    .await
    .expect("enqueue returns before sandbox provisioning")
    .expect("admit enrolled turn");
    assert_eq!(execution.status, ExecutionStatus::Queued);
    assert_eq!(
        execution.metadata[centaur_iron_control::SLACK_SEARCH_EPOCH_LABEL],
        "test-epoch"
    );
    let request = store
        .execution_request(&execution.execution_id)
        .await
        .unwrap();
    assert_eq!(
        request["metadata"][centaur_iron_control::SLACK_SEARCH_EPOCH_LABEL],
        "test-epoch"
    );
    assert_eq!(request["metadata"]["source"], "queue-regression");
    timeout(Duration::from_secs(2), backend.create_started.notified())
        .await
        .expect("admitted request reaches sandbox creation");
    create_gate.notify_one();
    stdout
        .write_all(&completed_output_bytes("Enrolled queued turn completed."))
        .await
        .unwrap();
    wait_for_event(&store, &thread, "session.execution_completed").await;
    let replay = runtime
        .enqueue_session_execution(&thread, input)
        .await
        .expect("idempotent current-epoch replay");
    assert_eq!(replay.execution_id, execution.execution_id);
    assert_eq!(replay.status, ExecutionStatus::Completed);
    assert_eq!(backend.opens(), 1);

    enrolled.store(false, Ordering::SeqCst);
    let mut revoked_input = epoch_input();
    revoked_input.idempotency_key = Some("revoked-turn".to_owned());
    revoked_input.metadata = Some(json!({"centaur.slack_search_epoch":"test-epoch"}));
    let error = runtime
        .enqueue_session_execution(&thread, revoked_input)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("slack_search_enrollment_required")
    );
    let latest = store
        .latest_execution_for_thread(&thread)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        latest.execution_id, execution.execution_id,
        "revocation must reject before inserting any queued execution"
    );
    assert_eq!(backend.opens(), 1);
}

#[tokio::test]
async fn slack_search_enqueue_does_not_relabel_an_old_idempotent_request() {
    let Some(store) = test_store().await else {
        return;
    };
    let _serial = TEST_LOCK.lock().await;
    let thread = ThreadKey::parse(format!("slack:CQUEUEREPLAY:{}", uuid::Uuid::new_v4())).unwrap();
    let backend = Arc::new(MockBackend::new(SandboxStatus::Running, Vec::new()));
    let mut runtime = SessionRuntime::new(
        store.clone(),
        SandboxRuntime::backend(backend.clone(), SandboxSpec::new("mock")),
        EpochRegistrar(Arc::new(AtomicBool::new(true))),
    );
    runtime.slack_search_epoch = Some("test-epoch".to_owned());
    runtime
        .create_or_get_session(
            &thread,
            &HarnessType::Codex,
            None,
            None,
            HarnessConflictPolicy::Reject,
        )
        .await
        .unwrap();
    let input = epoch_input();
    let original_request = persisted_execute_request(&input).unwrap();
    let old = store
        .create_execution_with_request(
            &thread,
            input.idempotency_key.as_deref(),
            json!({}),
            original_request.clone(),
        )
        .await
        .unwrap()
        .execution;
    let error = runtime
        .enqueue_session_execution(&thread, input)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("slack_search_pre_epoch_execution_denied")
    );
    assert_eq!(
        store.execution_request(&old.execution_id).await.unwrap(),
        original_request
    );
    assert_eq!(backend.opens(), 0);
    assert!(backend.created_specs().is_empty());
    store.complete_execution(&old.execution_id).await.unwrap();
}
