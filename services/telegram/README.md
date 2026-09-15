# Personal Telegram

This service owns encrypted Telegram provider sessions. Console remains the
source of truth for users, Slack identities, and sandbox authorization. The
browser signs into Console with Slack, opens **Integrations → Personal
Telegram**, and scans a Telegram QR code. A Telegram two-step password is entered
only on that private page. Login QR codes, passwords, and sessions never reach
the sandbox or Slack transcript.

The initial MCP surface is read-only: `search_dialogs`, `get_messages`, and
`search_messages`. Dialog discovery examines at most 1,000 conversations; message
reads/searches return at most 50 messages, truncated to 16,000 characters each.
It does not download media, send messages, or index Telegram into company context.

## Request boundary

1. `POST /api/v1/sandbox/telegram/mcp` uses the existing sandbox entitlement JWT.
   Console verifies the current proxy assignment on every request.
2. `TelegramAccess` accepts only a primary `slack_dm` principal with matching
   workspace-qualified Slack IDs and an active Console user with that exact
   Slack SSO identity. Shared channels, group DMs, ambiguous identities, disabled
   users, stale assignments, and requester credential overrides fail closed.
3. Console supplies the authenticated owner's opaque user ID and an internal
   service credential. Caller arguments cannot choose an owner. The service is
   inaccessible from sandbox pods under its Kubernetes NetworkPolicy.
4. Every MCP call opens only that owner's encrypted session. Each owner has a
   separate lock; disconnect removes local access and asks Telegram to revoke
   that session. If Telegram is unreachable, the UI asks the user to also revoke
   it under Telegram Settings → Devices.

The SQLite volume contains encrypted provider state, not another user or grant
database. Ciphertext also binds the owner ID, so moving a stored row between
owners cannot select another Telegram session. The encryption key belongs only
in the service Secret and must be backed up separately. Destroying it without a
backup disconnects all accounts. The single replica and `Recreate` rollout keep
one process responsible for login waits and the database. Pending logins expire
within five minutes and do not survive a restart; connected sessions do survive.

## Deployment

Build `services/telegram/Dockerfile` and the changed Console image together. The
image publication workflow includes `centaur-telegram`; the Helm chart takes
`telegram.enabled`, a pinned `telegram.image`, and `telegram.existingSecretName`.
Create the referenced Secret outside Git with:

- `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` from your Telegram developer app.
- `TELEGRAM_SESSION_KEY`, generated with `cryptography.fernet.Fernet.generate_key()`.
- `TELEGRAM_SERVICE_TOKEN`, at least 32 random characters.

Only the worker receives the Telegram app credentials and encryption key.
Console receives the service token and internal endpoint. Do not add any of
these credentials to a sandbox environment, Infra role, repository cache, or
OAuth app marked `always_available`.

Before enabling it for people, configure Console HTTPS and Slack OIDC with an
exact callback URL (`<console public URL>/auth/slack/callback`). Scope Console
admission to the intended workspace/team. Audit session-reading, observability,
workflow, and storage access separately: protecting MCP credentials does not
prove that another principal cannot retrieve an already-persisted DM transcript.
Run live cross-user canaries through both the tools and those retrieval paths.

Use the overlay's `telegram_personal` CLI from an authenticated DM. The CLI uses
the MCP SDK through Console; iron-proxy supplies the existing sandbox JWT. There
is no personal-token environment variable or shared-account fallback.

## Local verification

```sh
uv sync --frozen
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Console tests are in `test/controllers/api/v1/sandbox_telegram_controller_test.rb`
and `test/controllers/console/telegram_controller_test.rb`. Run them against the
repository's local ParadeDB as described in the Console contributor guide.
Synthetic service tests exercise actual MCP HTTP initialization, discovery,
cross-owner canaries, two-step login, encryption, and disconnect; they do not
claim to verify a real Telegram account or the deployed network boundary.
