import { AsyncLocalStorage } from 'node:async_hooks'

type SlackSearchCredential = {
  actionToken: string
  channelId: string
  messageId: string
  teamId: string
  threadId: string
  threadTs: string
  userId: string
}

/**
 * Why this request carries no search credential, when the event was a human
 * turn the bot would otherwise search for. Surfaced to the agent so its
 * unavailable notice can say whether retrying could ever help.
 */
export type SlackSearchCaptureFailure = 'group_dm' | 'missing_action_token'

export type SlackbotV2RequestContext = {
  waitUntil(promise: Promise<unknown>): void
  actionError?: unknown
  /** Verified request-local credential. Never copy this into message or recovery state. */
  slackSearchCredential?: SlackSearchCredential
  slackSearchCaptureFailure?: SlackSearchCaptureFailure
}

export const requestContext = new AsyncLocalStorage<SlackbotV2RequestContext>()

/** Called only after the original webhook bytes pass Slack signature verification. */
export function captureSlackSearchCredential(payload: unknown, agentViewEnabled = false): void {
  const context = requestContext.getStore()
  if (!context || !record(payload) || payload.type !== 'event_callback') return
  const event = payload.event
  if (!record(event) || !['app_mention', 'message'].includes(String(event.type))) return
  if (event.bot_id || (event.subtype && event.subtype !== 'file_share')) return
  // Group DMs are excluded as search origins by design (RFC 0006). Record
  // that so the turn's notice can say so instead of asking for a retry.
  if (event.channel_type === 'mpim') {
    context.slackSearchCaptureFailure = 'group_dm'
    return
  }
  const actionToken = text(event.action_token) ?? text(payload.action_token)
  // Slack attaches the token only when the app install carries the search
  // scope. Its absence on an otherwise ordinary human turn is a workspace
  // configuration signal, not something a retry fixes.
  if (!actionToken) {
    context.slackSearchCaptureFailure = 'missing_action_token'
    return
  }
  const channelId = text(event.channel)
  const messageId = text(event.ts)
  const isDirectMessage = event.channel_type === 'im' && channelId?.startsWith('D') === true
  // Match Chat SDK's canonical DM routing: legacy DM roots use an empty
  // suffix; agent-view roots and all explicit replies use a message timestamp.
  const threadTs = text(event.thread_ts) ?? (isDirectMessage && !agentViewEnabled ? '' : messageId)
  const teamId = text(payload.team_id)
  const userId = text(event.user)
  if (!channelId || !/^[CGD][A-Z0-9]+$/.test(channelId)
    || (channelId.startsWith('D') && !isDirectMessage)
    || (event.channel_type === 'im' && !isDirectMessage)
    || !messageId || !/^\d+\.\d+$/.test(messageId)
    || threadTs === undefined || (threadTs !== '' && !/^\d+\.\d+$/.test(threadTs))
    || !teamId || !userId) return
  context.slackSearchCredential = {
    actionToken, channelId, messageId, teamId, threadTs, userId,
    threadId: `slack:${channelId}:${threadTs}`
  }
}

/** A capability can be handed off once, only for the event currently being handled. */
export function takeSlackSearchCredential(
  threadId: string,
  messageId: string,
  userId: string
): SlackSearchCredential | undefined {
  const context = requestContext.getStore()
  const credential = context?.slackSearchCredential
  if (!credential || credential.threadId !== threadId
    || credential.messageId !== messageId || credential.userId !== userId) return undefined
  delete context!.slackSearchCredential
  return credential
}

/** Why the current event yielded no credential, when capture recorded a reason. */
export function slackSearchCaptureFailure(): SlackSearchCaptureFailure | undefined {
  return requestContext.getStore()?.slackSearchCaptureFailure
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}
