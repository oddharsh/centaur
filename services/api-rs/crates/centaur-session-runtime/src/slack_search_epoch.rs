use centaur_iron_control::{Principal, SLACK_SEARCH_EPOCH_LABEL};
use centaur_session_core::{Session, SessionExecution, ThreadKey};
use centaur_session_sqlx::SlackSearchSessionLock;

use crate::{ExecuteSessionInput, SessionRuntime, SessionRuntimeError};

impl SessionRuntime {
    pub(crate) fn slack_epoch_for_thread(&self, thread: &ThreadKey) -> Option<&str> {
        thread
            .as_str()
            .starts_with("slack:")
            .then_some(self.slack_search_epoch.as_deref())
            .flatten()
    }

    pub(crate) async fn lock_enrolled_slack_session(
        &self,
        thread: &ThreadKey,
        principal: &Principal,
    ) -> Result<Option<SlackSearchSessionLock>, SessionRuntimeError> {
        let Some(epoch) = self.slack_epoch_for_thread(thread) else {
            return Ok(None);
        };
        require_enrollment(principal, epoch)?;
        Ok(Some(self.store.lock_slack_search_session(thread).await?))
    }

    /// Called only while holding the session's rollout lock, before a new
    /// execution can be admitted. Restart uses the canonical harness reset.
    pub(crate) async fn prepare_slack_search_epoch(
        &self,
        thread: &ThreadKey,
        mut session: Session,
    ) -> Result<Session, SessionRuntimeError> {
        let Some(epoch) = self.slack_epoch_for_thread(thread) else {
            return Ok(session);
        };
        if self.store.slack_search_epoch(thread).await?.as_deref() == Some(epoch) {
            return Ok(session);
        }
        if self.store.has_active_execution(thread).await? {
            return Err(SessionRuntimeError::BadRequest(
                "slack_search_epoch_requires_idle_session".to_owned(),
            ));
        }
        if session.sandbox_id.is_some() || session.harness_thread_id.is_some() {
            session = self
                .restart_session_on_harness(
                    thread,
                    &session.harness_type,
                    session.harness_type.as_ref(),
                )
                .await?;
        }
        self.store.set_slack_search_epoch(thread, epoch).await?;
        Ok(session)
    }

    pub(crate) async fn lock_slack_search_execution(
        &self,
        thread: &ThreadKey,
    ) -> Result<Option<SlackSearchSessionLock>, SessionRuntimeError> {
        let Some(epoch) = self.slack_epoch_for_thread(thread) else {
            return Ok(None);
        };
        let lock = self.store.lock_slack_search_session(thread).await?;
        let session = self.store.get_session(thread).await?;
        let principal_id = session.iron_control_principal.as_deref().ok_or_else(|| {
            SessionRuntimeError::BadRequest("slack_search_enrollment_required".to_owned())
        })?;
        let principal = self.iron_control.get_principal(principal_id).await?;
        require_enrollment(&principal, epoch)?;
        if self.store.slack_search_epoch(thread).await?.as_deref() != Some(epoch) {
            return Err(SessionRuntimeError::BadRequest(
                "slack_search_fresh_session_required".to_owned(),
            ));
        }
        Ok(Some(lock))
    }

    /// Only call after the live enrollment/session epoch admission check.
    /// Stamp before persisting either a queued request or a direct execution.
    pub(crate) fn stamp_slack_execution_epoch(
        &self,
        thread: &ThreadKey,
        input: &mut ExecuteSessionInput,
    ) {
        if let Some(epoch) = self.slack_epoch_for_thread(thread) {
            let metadata = input.metadata.get_or_insert_with(|| serde_json::json!({}));
            if !metadata.is_object() {
                *metadata = serde_json::json!({});
            }
            metadata[SLACK_SEARCH_EPOCH_LABEL] = serde_json::json!(epoch);
        }
    }

    pub(crate) fn validate_slack_execution_epoch(
        &self,
        thread: &ThreadKey,
        execution: &SessionExecution,
    ) -> Result<(), SessionRuntimeError> {
        if let Some(epoch) = self.slack_epoch_for_thread(thread)
            && execution
                .metadata
                .get(SLACK_SEARCH_EPOCH_LABEL)
                .and_then(serde_json::Value::as_str)
                != Some(epoch)
        {
            return Err(SessionRuntimeError::BadRequest(
                "slack_search_pre_epoch_execution_denied".to_owned(),
            ));
        }
        Ok(())
    }
}

fn require_enrollment(principal: &Principal, epoch: &str) -> Result<(), SessionRuntimeError> {
    if principal
        .labels
        .get(SLACK_SEARCH_EPOCH_LABEL)
        .map(String::as_str)
        != Some(epoch)
    {
        return Err(SessionRuntimeError::BadRequest(
            "slack_search_enrollment_required".to_owned(),
        ));
    }
    Ok(())
}
