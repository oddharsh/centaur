-- Short-lived credentials only. Retrieved Slack content and generated answers
-- must never be written here or into the ordinary session/event tables.
CREATE TABLE slack_search_contexts (
    context_id text PRIMARY KEY,
    thread_key text NOT NULL REFERENCES sessions(thread_key) ON DELETE CASCADE,
    message_id text NOT NULL,
    team_id text NOT NULL,
    user_id text NOT NULL,
    channel_id text NOT NULL,
    thread_ts text,
    encrypted_action_token bytea,
    state text NOT NULL DEFAULT 'ready' CHECK (state IN ('ready', 'claimed', 'accepted', 'failed', 'expired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '10 minutes'),
    UNIQUE (thread_key, message_id)
);
CREATE INDEX slack_search_contexts_expiry ON slack_search_contexts (expires_at);

-- The control-plane migration owner is the only role that may handle these
-- credentials. No reader policy exists, so even a broad future SELECT grant
-- cannot expose rows through one of the sandbox's database reader roles.
ALTER TABLE slack_search_contexts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON slack_search_contexts FROM PUBLIC;
DO $$
DECLARE reader_role text;
BEGIN
    FOREACH reader_role IN ARRAY ARRAY[
        'centaur_readonly', 'centaur_slack_reader', 'centaur_slack_admin',
        'centaur_company_context_reader'
    ] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = reader_role) THEN
            EXECUTE format('REVOKE ALL ON slack_search_contexts FROM %I', reader_role);
        END IF;
    END LOOP;
END
$$;
