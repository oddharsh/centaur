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

export type SlackbotV2RequestContext = {
  waitUntil(promise: Promise<unknown>): void
  actionError?: unknown
  /** Verified request-local credential. Never copy this into message or recovery state. */
  slackSearchCredential?: SlackSearchCredential
}

export const requestContext = new AsyncLocalStorage<SlackbotV2RequestContext>()

/** Called only after the original webhook bytes pass Slack signature verification. */
export function captureSlackSearchCredential(payload: unknown, agentViewEnabled = false): void {
  const context = requestContext.getStore()
  if (!context || !record(payload) || payload.type !== 'event_callback') return
  const event = payload.event
  if (!record(event) || !['app_mention', 'message'].includes(String(event.type))) return
  if (event.bot_id || (event.subtype && event.subtype !== 'file_share')) return
  if (event.channel_type === 'mpim') return
  const actionToken = text(event.action_token) ?? text(payload.action_token)
  const channelId = text(event.channel)
  const messageId = text(event.ts)
  const isDirectMessage = event.channel_type === 'im' && channelId?.startsWith('D') === true
  // Match Chat SDK's canonical DM routing: legacy DM roots use an empty
  // suffix; agent-view roots and all explicit replies use a message timestamp.
  const threadTs = text(event.thread_ts) ?? (isDirectMessage && !agentViewEnabled ? '' : messageId)
  const teamId = text(payload.team_id)
  const userId = text(event.user)
  if (!actionToken || !channelId || !/^[CGD][A-Z0-9]+$/.test(channelId)
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

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}
