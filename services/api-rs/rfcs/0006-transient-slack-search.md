# RFC 0006: Transient Slack search answers

Status: Implemented locally; activation pending
Target: slackbotv2, api-rs, Slack productivity CLI

## Outcome

Answer Slack questions using public Real-time Search, including channels the
bot has not joined, plus bounded recent private history shared by the bot and
requester. Exclude IM and MPIM sources. Deliver private information only to a
currently verified member. Retrieved content must not enter ordinary durable
agent transcripts, tool output, telemetry, or activity summaries.

## One execution path

Slackbot verifies the original webhook signature before capturing its action
token in request-local AsyncLocalStorage. It removes action tokens before the
Chat SDK receives the event and from serialized historical messages. Once the
session exists, the Slack ingress registers a short-lived credential with
`POST /api/slack/search-context`. The token travels in the
`x-slack-action-token` header. The body identifies the signed event's workspace,
requester, channel, thread, and message.

Only the authenticated `slackbot` ingress may register. The returned UUID
enters execution metadata and the agent's instructions; the credential does
not. Other callers cannot assert `slack_search_context_id` in execute metadata.

The agent invokes `slack search-answer QUESTION --context UUID` using its
existing principal API JWT. It does not need a Slack credential. The API
checks the stored session principal and the currently running execution's
event tuple before atomically claiming the credential. The normal agent is
not a consumer of retrieved messages or the resulting answer.

The principal is the authentication boundary, and the single-use UUID selects
an active signed event. Slack channel threads share a channel principal, so a
holder of the same principal credential and another active context's UUID can
consume that context or trigger its answer. This does not prove the calling
sandbox's individual session identity. Delivery still targets the context's
original requester, whose source memberships are checked live; the caller
receives no retrieved content or answer.

The API then performs live Slack authorization, retrieval, one stateless synthesis
call, and `chat.postEphemeral` to the original requester in the
original channel. It returns only a fixed acceptance receipt. It never falls
back to a persistent Slack message, direct sandbox read, indexed corpus, or
different credential.

The synthesis provider is explicit: OpenAI Responses uses `store: false`;
Anthropic Messages uses one request with no history, tools, or prompt caching.
Both enforce the same answer schema and source citation validation.

## Credential lifetime and recovery

The dedicated `slack_search_contexts` table stores operational bindings and an
AES-256-GCM encrypted action token. The encryption key is domain-separated
from the existing API JWT signing secret using HMAC-SHA256. A fresh random
nonce and context UUID as authenticated associated data prevent ciphertext
reuse across contexts.

Credentials expire after ten minutes. Registering the same event is idempotent
and does not replace its credential or extend its lifetime. Claiming checks
the active execution and clears the ciphertext in one database transaction.
Expiry is enforced synchronously and a periodic task clears unused expired
ciphertexts and trims old operational rows. No source content, provider
response, answer, or error body is written to this table.

Unclaimed credentials survive API replica changes and restarts. A crash,
cancellation, or uncertain delivery after claim requires a fresh Slack
request. The operation deliberately cannot retry a possible send. API signing
secret rotation invalidates outstanding encrypted credentials.

## Audience and source checks

Public RTS is restricted server-side to public channels and message results.
Every result's workspace and actual conversation type are validated. Context
messages may inherit their verified parent's identity but conflicting fields
are rejected. No channel-prefix heuristic authorizes a source.

Private history is read using the bot credential, from channels currently
shared by the bot and requester. The bounded first version examines at most
ten channels, one hundred recent roots, and five threads of fifty messages.
Answers disclose this incomplete coverage. It does not implement exhaustive
private search or attachment retrieval.

Requester, bot membership, channel type, and relevant source membership are
checked before retrieval and again before delivery. Guests and external
requesters cannot obtain workspace-wide retrieval. A Slack Connect origin is
restricted to that origin channel. Unknown or inconsistent metadata and failed
membership checks deny the operation.

Ephemeral delivery is visible only to the verified requester and is temporary.
The receipt means Slack accepted the request, not that the user saw it. The
ordinary agent cannot continue reasoning from the temporary answer. This is
an intentional product limitation of keeping results out of saved sessions.

## Deployment contract

The opt-in Helm setting is `slackbotv2.slackSearchEnabled`; it requires the
bot's `search:read.public` scope and reinstall. Private history uses existing
bot conversation scopes, not shared user search credentials. Model synthesis
uses existing API provider configuration, `SLACK_SEARCH_PROVIDER`, and
`SLACK_SEARCH_MODEL`.

`SLACK_SEARCH_EPOCH` requires a matching trusted principal label before Slack
registration or execution. The session's initialized epoch lives in a dedicated
database column, outside caller metadata. A changed epoch retires the previous
sandbox and harness state while preserving message rows; an active execution
must drain first. Execution admission, steering, event attachment, and orphan
recovery enforce this boundary. Enrolled DM registration preserves read denial.
Slackbot suppresses historical backfill while search is enabled.

This implementation constrains the new search operation. A deployment-wide
no-DM policy additionally requires removal of legacy direct Slack reads,
Slack-bearing database grants, cross-session transcript access, and unsafe
observability from enrolled sandboxes. Disabling ETL or hiding commands does
not revoke those paths. Permission migration is a separate, explicit rollout
step and must preserve unrelated principals and necessary write capabilities.

## Verification boundaries

Tests cover verified-event capture, credential hygiene, API caller separation,
execution identity, concurrent claims, expiry, encryption, public nonmember
channels, IM/MPIM denial, private membership, revalidation, bounded responses,
provider error redaction, ephemeral-only delivery, and strict CLI receipts.
Live RTS scope availability, real Slack action tokens, provider behavior, and
effective production grant isolation require rollout verification. Mock tests
do not substitute for that evidence.
