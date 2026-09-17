use sqlx::{FromRow, PgPool};
use thiserror::Error;

/// Only encrypted request credentials belong here, never search results or answers.
pub struct RegisterSlackSearchContext {
    pub context_id: String,
    pub thread_key: String,
    pub message_id: String,
    pub team_id: String,
    pub user_id: String,
    pub channel_id: String,
    pub thread_ts: Option<String>,
    pub encrypted_action_token: Vec<u8>,
}

// Deliberately no Debug/Serialize: encrypted credentials must not enter diagnostics.
pub struct ClaimedSlackSearchContext {
    pub context_id: String,
    pub thread_key: String,
    pub message_id: String,
    pub team_id: String,
    pub user_id: String,
    pub channel_id: String,
    pub thread_ts: Option<String>,
    pub encrypted_action_token: Vec<u8>,
    pub execution_id: String,
}

#[derive(Debug, Error)]
pub enum SlackSearchContextError {
    #[error("Slack search context unavailable")]
    Unavailable,
    #[error("Slack search context denied")]
    Denied,
    #[error("Slack search context storage unavailable")]
    Sqlx(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct PgSlackSearchContexts {
    pool: PgPool,
}

#[derive(FromRow)]
struct ContextRow {
    context_id: String,
    thread_key: String,
    message_id: String,
    team_id: String,
    user_id: String,
    channel_id: String,
    thread_ts: Option<String>,
    encrypted_action_token: Option<Vec<u8>>,
    state: String,
    unexpired: bool,
}

impl PgSlackSearchContexts {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Retry the same source event without replacing its credential or extending its TTL.
    pub async fn register(
        &self,
        input: RegisterSlackSearchContext,
    ) -> Result<String, SlackSearchContextError> {
        if input.encrypted_action_token.is_empty() {
            return Err(SlackSearchContextError::Unavailable);
        }
        let id = sqlx::query_scalar::<_, String>(
            r#"
            insert into slack_search_contexts
                (context_id, thread_key, message_id, team_id, user_id, channel_id, thread_ts, encrypted_action_token)
            values ($1, $2, $3, $4, $5, $6, $7, $8)
            on conflict (thread_key, message_id) do update
                set context_id = slack_search_contexts.context_id
            where slack_search_contexts.team_id = excluded.team_id
                and slack_search_contexts.user_id = excluded.user_id
                and slack_search_contexts.channel_id = excluded.channel_id
                and slack_search_contexts.thread_ts is not distinct from excluded.thread_ts
                and slack_search_contexts.state = 'ready'
                and slack_search_contexts.expires_at > now()
                and slack_search_contexts.encrypted_action_token is not null
            returning context_id
            "#,
        )
        .bind(input.context_id)
        .bind(input.thread_key)
        .bind(input.message_id)
        .bind(input.team_id)
        .bind(input.user_id)
        .bind(input.channel_id)
        .bind(input.thread_ts)
        .bind(input.encrypted_action_token)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(SlackSearchContextError::Unavailable)
    }

    /// Check the durable active turn and atomically remove its single-use credential.
    pub async fn claim(
        &self,
        context_id: &str,
        principal: &str,
    ) -> Result<ClaimedSlackSearchContext, SlackSearchContextError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, ContextRow>(
            r#"
            select context_id, thread_key, message_id, team_id, user_id, channel_id,
                thread_ts, encrypted_action_token, state, expires_at > now() as unexpired
            from slack_search_contexts where context_id = $1 for update
            "#,
        )
        .bind(context_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(SlackSearchContextError::Unavailable)?;
        if !row.unexpired {
            sqlx::query(
                "update slack_search_contexts set encrypted_action_token = null, \
                 state = case when state = 'ready' then 'expired' else state end where context_id = $1",
            )
            .bind(context_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(SlackSearchContextError::Unavailable);
        }
        if row.state != "ready" || row.encrypted_action_token.is_none() {
            return Err(SlackSearchContextError::Unavailable);
        }
        let execution_id = sqlx::query_scalar::<_, String>(
            r#"
            select execution.execution_id
            from sessions session
            join session_executions execution on execution.thread_key = session.thread_key
            where session.thread_key = $1 and session.iron_control_principal = $2
                and execution.status = 'running'
                and execution.metadata->>'slack_search_context_id' = $3
                and execution.metadata->>'slack_user_id' = $4
                and execution.metadata->>'slack_channel_id' = $5
                and execution.metadata->>'message_id' = $6
                and (not (execution.metadata ? 'slack_home_team_id')
                    or execution.metadata->>'slack_home_team_id' = $7)
            for share of session, execution
            "#,
        )
        .bind(&row.thread_key)
        .bind(principal)
        .bind(context_id)
        .bind(&row.user_id)
        .bind(&row.channel_id)
        .bind(&row.message_id)
        .bind(&row.team_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(SlackSearchContextError::Denied)?;
        sqlx::query(
            "update slack_search_contexts set state = 'claimed', encrypted_action_token = null \
             where context_id = $1",
        )
        .bind(context_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ClaimedSlackSearchContext {
            context_id: row.context_id,
            thread_key: row.thread_key,
            message_id: row.message_id,
            team_id: row.team_id,
            user_id: row.user_id,
            channel_id: row.channel_id,
            thread_ts: row.thread_ts,
            encrypted_action_token: row
                .encrypted_action_token
                .ok_or(SlackSearchContextError::Unavailable)?,
            execution_id,
        })
    }

    pub async fn finish(
        &self,
        context_id: &str,
        accepted: bool,
    ) -> Result<(), SlackSearchContextError> {
        let result = sqlx::query(
            "update slack_search_contexts set state = $2, encrypted_action_token = null \
             where context_id = $1 and state = 'claimed'",
        )
        .bind(context_id)
        .bind(if accepted { "accepted" } else { "failed" })
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(SlackSearchContextError::Unavailable);
        }
        Ok(())
    }

    pub async fn cleanup(&self) -> Result<(), SlackSearchContextError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "update slack_search_contexts set encrypted_action_token = null, \
             state = case when state = 'ready' then 'expired' else state end \
             where expires_at <= now() and (encrypted_action_token is not null or state = 'ready')",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "delete from slack_search_contexts where expires_at < now() - interval '1 day'",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
