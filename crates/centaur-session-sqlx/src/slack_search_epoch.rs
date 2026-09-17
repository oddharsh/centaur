//! Durable rollout boundary for Slack sessions. The ordinary session row is
//! the source of truth; historical messages and events are never deleted.
use centaur_session_core::ThreadKey;
use sqlx::PgConnection;

use crate::{PgSessionStore, SessionStoreError};

pub struct SlackSearchSessionLock {
    // Closing this unpooled connection releases its session advisory lock.
    // It must not occupy the query pool while runtime operations borrow it.
    _connection: PgConnection,
}

impl PgSessionStore {
    pub async fn lock_slack_search_session(
        &self,
        thread_key: &ThreadKey,
    ) -> Result<SlackSearchSessionLock, SessionStoreError> {
        let mut connection = self.pool.acquire().await?.detach();
        sqlx::query("select pg_advisory_lock(hashtextextended($1, 9172026))")
            .bind(thread_key.as_str())
            .execute(&mut connection)
            .await?;
        Ok(SlackSearchSessionLock {
            _connection: connection,
        })
    }

    pub async fn slack_search_epoch(
        &self,
        thread_key: &ThreadKey,
    ) -> Result<Option<String>, SessionStoreError> {
        Ok(sqlx::query_scalar::<_, Option<String>>(
            "select slack_search_epoch from sessions where thread_key = $1",
        )
        .bind(thread_key.as_str())
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn set_slack_search_epoch(
        &self,
        thread_key: &ThreadKey,
        epoch: &str,
    ) -> Result<(), SessionStoreError> {
        sqlx::query(
            "update sessions set slack_search_epoch = $2, updated_at = now() where thread_key = $1",
        )
        .bind(thread_key.as_str())
        .bind(epoch)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn has_active_execution(
        &self,
        thread_key: &ThreadKey,
    ) -> Result<bool, SessionStoreError> {
        Ok(sqlx::query_scalar("select exists(select 1 from session_executions where thread_key = $1 and status in ('queued', 'running'))")
            .bind(thread_key.as_str()).fetch_one(&self.pool).await?)
    }
}
