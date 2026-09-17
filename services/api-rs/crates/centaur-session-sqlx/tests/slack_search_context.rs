use centaur_session_sqlx::{
    PgSlackSearchContexts, RegisterSlackSearchContext, SlackSearchContextError,
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::OffsetDateTime;
use uuid::Uuid;

const CONTEXT_ID: &str = "b13d6317-a3ea-4e8a-b9c6-9f048835124a";
const THREAD_KEY: &str = "slack:C123:100.001";
const PRINCIPAL: &str = "prn-channel";
const CIPHERTEXT: &[u8] = b"synthetic-encrypted-credential-canary";

struct TestDb {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl TestDb {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("SESSION_RUNTIME_TEST_DATABASE_URL") else {
            eprintln!("skipping: SESSION_RUNTIME_TEST_DATABASE_URL not set");
            return None;
        };
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect disposable database");
        let schema = format!("slack_search_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("create schema {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let path = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&format!("set search_path to {path}, public"))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        // Apply the real prerequisite schema, seed a pre-existing turn, then
        // upgrade with the real new migration. Unrelated ETL extensions are
        // intentionally outside this repository test's isolated schema.
        sqlx::raw_sql(include_str!("../migrations/0001_session_control_plane.sql"))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/0003_session_iron_control_principal.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into sessions (thread_key, harness_type, status, iron_control_principal) \
             values ($1, 'codex', 'ready', $2)",
        )
        .bind(THREAD_KEY)
        .bind(PRINCIPAL)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "insert into session_executions (execution_id, thread_key, status, metadata) \
             values ('execution-1', $1, 'running', $2)",
        )
        .bind(THREAD_KEY)
        .bind(metadata())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!("../migrations/0055_slack_search_contexts.sql"))
            .execute(&pool)
            .await
            .unwrap();
        Some(Self {
            pool,
            admin,
            schema,
        })
    }

    fn repo(&self) -> PgSlackSearchContexts {
        PgSlackSearchContexts::new(self.pool.clone())
    }

    async fn set_execution(&self, status: &str, metadata: Value) {
        sqlx::query("update session_executions set status = $1, metadata = $2")
            .bind(status)
            .bind(metadata)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn state(&self) -> (String, Option<Vec<u8>>) {
        sqlx::query_as("select state, encrypted_action_token from slack_search_contexts")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(&format!("drop schema {} cascade", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

fn input() -> RegisterSlackSearchContext {
    RegisterSlackSearchContext {
        context_id: CONTEXT_ID.to_owned(),
        thread_key: THREAD_KEY.to_owned(),
        message_id: "100.002".to_owned(),
        team_id: "T123".to_owned(),
        user_id: "U123".to_owned(),
        channel_id: "C123".to_owned(),
        thread_ts: Some("100.001".to_owned()),
        encrypted_action_token: CIPHERTEXT.to_vec(),
    }
}

fn metadata() -> Value {
    json!({
        "slack_search_context_id": CONTEXT_ID,
        "slack_user_id": "U123",
        "slack_channel_id": "C123",
        "message_id": "100.002",
        "slack_home_team_id": "T123",
        // The requester home team need not equal the installation team.
        "slack_team_id": "TREQUESTER"
    })
}

#[tokio::test]
async fn slack_search_registration_survives_recreation_without_refresh_or_replacement() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let first = db.repo().register(input()).await.unwrap();
    let initial: (OffsetDateTime, Vec<u8>) =
        sqlx::query_as("select expires_at, encrypted_action_token from slack_search_contexts")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let mut retry = input();
    retry.context_id = Uuid::new_v4().to_string();
    retry.encrypted_action_token = b"replacement-must-not-be-stored".to_vec();
    assert_eq!(db.repo().register(retry).await.unwrap(), first);
    let after: (OffsetDateTime, Vec<u8>) =
        sqlx::query_as("select expires_at, encrypted_action_token from slack_search_contexts")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(initial, after);
    for field in ["team", "user", "channel", "thread", "missing_thread"] {
        let mut changed = input();
        match field {
            "team" => changed.team_id = "TOTHER".to_owned(),
            "user" => changed.user_id = "UOTHER".to_owned(),
            "channel" => changed.channel_id = "COTHER".to_owned(),
            "thread" => changed.thread_ts = Some("200.001".to_owned()),
            _ => changed.thread_ts = None,
        }
        assert!(matches!(
            db.repo().register(changed).await,
            Err(SlackSearchContextError::Unavailable)
        ));
    }
    assert_eq!(
        db.state().await,
        ("ready".to_owned(), Some(CIPHERTEXT.to_vec()))
    );
    db.close().await;
}

#[tokio::test]
async fn slack_search_claim_requires_the_exact_running_requester_and_session() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let repo = db.repo();
    repo.register(input()).await.unwrap();
    assert!(matches!(
        repo.claim(CONTEXT_ID, "prn-other").await,
        Err(SlackSearchContextError::Denied)
    ));
    for status in ["queued", "completed", "failed", "cancelled"] {
        db.set_execution(status, metadata()).await;
        assert!(matches!(
            repo.claim(CONTEXT_ID, PRINCIPAL).await,
            Err(SlackSearchContextError::Denied)
        ));
    }
    for key in [
        "slack_search_context_id",
        "slack_user_id",
        "slack_channel_id",
        "message_id",
        "slack_home_team_id",
    ] {
        let mut changed = metadata();
        changed[key] = json!("wrong-binding");
        db.set_execution("running", changed).await;
        assert!(matches!(
            repo.claim(CONTEXT_ID, PRINCIPAL).await,
            Err(SlackSearchContextError::Denied)
        ));
        let mut missing = metadata();
        missing.as_object_mut().unwrap().remove(key);
        if key != "slack_home_team_id" {
            db.set_execution("running", missing).await;
            assert!(matches!(
                repo.claim(CONTEXT_ID, PRINCIPAL).await,
                Err(SlackSearchContextError::Denied)
            ));
        }
    }
    assert_eq!(
        db.state().await,
        ("ready".to_owned(), Some(CIPHERTEXT.to_vec()))
    );
    let mut no_home_team = metadata();
    no_home_team
        .as_object_mut()
        .unwrap()
        .remove("slack_home_team_id");
    db.set_execution("running", no_home_team).await;
    let claimed = repo.claim(CONTEXT_ID, PRINCIPAL).await.unwrap();
    assert_eq!(claimed.context_id, CONTEXT_ID);
    assert_eq!(claimed.execution_id, "execution-1");
    assert_eq!(claimed.thread_key, THREAD_KEY);
    assert_eq!(claimed.message_id, "100.002");
    assert_eq!(claimed.encrypted_action_token, CIPHERTEXT);
    assert_eq!(db.state().await, ("claimed".to_owned(), None));
    assert!(matches!(
        repo.claim(CONTEXT_ID, PRINCIPAL).await,
        Err(SlackSearchContextError::Unavailable)
    ));
    assert!(matches!(
        repo.register(input()).await,
        Err(SlackSearchContextError::Unavailable)
    ));
    repo.finish(CONTEXT_ID, true).await.unwrap();
    assert_eq!(db.state().await, ("accepted".to_owned(), None));
    assert!(repo.finish(CONTEXT_ID, false).await.is_err());
    db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slack_search_claim_is_single_use_across_concurrent_repository_instances() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let first = db.repo();
    let second = db.repo();
    let mut retry = input();
    retry.context_id = Uuid::new_v4().to_string();
    let (a, b) = tokio::join!(first.register(input()), second.register(retry));
    let context = a.unwrap();
    assert_eq!(b.unwrap(), context);
    let mut bound = metadata();
    bound["slack_search_context_id"] = json!(context);
    db.set_execution("running", bound).await;
    let (a, b) = tokio::join!(
        first.claim(&context, PRINCIPAL),
        second.claim(&context, PRINCIPAL)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(db.state().await, ("claimed".to_owned(), None));
    db.repo().finish(&context, false).await.unwrap();
    assert_eq!(db.state().await, ("failed".to_owned(), None));
    assert!(db.repo().claim(&context, PRINCIPAL).await.is_err());
    assert!(db.repo().register(input()).await.is_err());
    db.close().await;
}

#[tokio::test]
async fn slack_search_expiry_and_cleanup_erase_credentials_without_reviving_contexts() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let repo = db.repo();
    repo.register(input()).await.unwrap();
    assert!(repo.finish(CONTEXT_ID, true).await.is_err());
    sqlx::query("update slack_search_contexts set expires_at = now() - interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(repo.register(input()).await.is_err());
    assert!(matches!(
        repo.claim(CONTEXT_ID, PRINCIPAL).await,
        Err(SlackSearchContextError::Unavailable)
    ));
    assert_eq!(db.state().await, ("expired".to_owned(), None));
    repo.cleanup().await.unwrap();
    assert_eq!(db.state().await, ("expired".to_owned(), None));
    sqlx::query("update slack_search_contexts set expires_at = now() - interval '2 days'")
        .execute(&db.pool)
        .await
        .unwrap();
    repo.cleanup().await.unwrap();
    let count: i64 = sqlx::query_scalar("select count(*) from slack_search_contexts")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    // Test the cleanup worker's independent expiry path, without claim first.
    repo.register(input()).await.unwrap();
    sqlx::query("update slack_search_contexts set expires_at = now() - interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    repo.cleanup().await.unwrap();
    assert_eq!(db.state().await, ("expired".to_owned(), None));
    db.close().await;
}

#[tokio::test]
async fn slack_search_credentials_are_invisible_to_reader_roles_even_after_a_broad_grant() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db.repo().register(input()).await.unwrap();
    let role = format!("slack_search_reader_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(
        "create role {role} nologin nosuperuser nobypassrls noinherit"
    ))
    .execute(&db.admin)
    .await
    .unwrap();
    sqlx::query(&format!("grant usage on schema {} to {role}", db.schema))
        .execute(&db.admin)
        .await
        .unwrap();
    let initially_allowed: bool =
        sqlx::query_scalar("select has_table_privilege($1, $2, 'SELECT')")
            .bind(&role)
            .bind(format!("{}.slack_search_contexts", db.schema))
            .fetch_one(&db.admin)
            .await
            .unwrap();
    assert!(!initially_allowed);

    sqlx::query(&format!(
        "grant select on {}.slack_search_contexts to {role}",
        db.schema
    ))
    .execute(&db.admin)
    .await
    .unwrap();
    let mut tx = db.pool.begin().await.unwrap();
    sqlx::query(&format!("set local role {role}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let visible: Vec<Vec<u8>> =
        sqlx::query_scalar("select encrypted_action_token from slack_search_contexts")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    assert!(visible.is_empty());
    tx.rollback().await.unwrap();
    assert_eq!(
        db.state().await,
        ("ready".to_owned(), Some(CIPHERTEXT.to_vec()))
    );
    sqlx::query(&format!("drop owned by {role}"))
        .execute(&db.admin)
        .await
        .unwrap();
    sqlx::query(&format!("drop role {role}"))
        .execute(&db.admin)
        .await
        .unwrap();
    db.close().await;
}
