import { createHmac } from 'node:crypto'
import { describe, expect, test } from 'bun:test'
import { Message, parseMarkdown } from 'chat'
import { slackCredentialSafeVerifier, withoutSlackActionTokens } from '../src/slack-credentials'
import { serializeMessage } from '../src/session-api'
import { captureSlackSearchCredential, requestContext, takeSlackSearchCredential } from '../src/request-context'

const SIGNING_SECRET = 'synthetic-signing-secret'
const ACTION_TOKEN = 'synthetic-action-token-canary'

function signedRequest(body: string, contentType = 'application/json', ageSeconds = 0): Request {
  const timestamp = Math.floor(Date.now() / 1000) - ageSeconds
  const signature = createHmac('sha256', SIGNING_SECRET)
    .update(`v0:${timestamp}:${body}`)
    .digest('hex')
  return new Request('https://example.test/api/webhooks/slack', {
    method: 'POST',
    body,
    headers: {
      'content-type': contentType,
      'x-slack-request-timestamp': String(timestamp),
      'x-slack-signature': `v0=${signature}`
    }
  })
}

describe('Slack action token hygiene', () => {
  test('captures only verified, matching channel turns in request-local memory', async () => {
    const payload = {
      type: 'event_callback', team_id: 'T1', action_token: ACTION_TOKEN,
      event: { type: 'app_mention', channel: 'C1', user: 'U1', ts: '123.456' }
    }
    const body = JSON.stringify(payload)
    const verifier = slackCredentialSafeVerifier(SIGNING_SECRET, captureSlackSearchCredential)
    await requestContext.run({ waitUntil: () => undefined }, async () => {
      await expect(verifier(signedRequest(body), body.replace('U1', 'U2'))).rejects.toThrow()
      expect(takeSlackSearchCredential('slack:C1:123.456', '123.456', 'U1')).toBeUndefined()
      expect(String(await verifier(signedRequest(body), body))).not.toContain(ACTION_TOKEN)
      expect(takeSlackSearchCredential('slack:C1:123.456', '123.456', 'U2')).toBeUndefined()
      expect(takeSlackSearchCredential('slack:C1:123.456', '123.457', 'U1')).toBeUndefined()
      expect(takeSlackSearchCredential('slack:C1:123.456', '123.456', 'U1')?.actionToken).toBe(ACTION_TOKEN)
      expect(takeSlackSearchCredential('slack:C1:123.456', '123.456', 'U1')).toBeUndefined()
    })
    expect(takeSlackSearchCredential('slack:C1:123.456', '123.456', 'U1')).toBeUndefined()
    for (const event of [
      { ...payload.event, channel: 'G1', channel_type: 'mpim' },
      { ...payload.event, channel: 'D1', channel_type: 'channel' },
      { ...payload.event, channel: 'G1', channel_type: 'im' },
      { ...payload.event, bot_id: 'B1' },
      { ...payload.event, subtype: 'message_changed' }
    ]) {
      await requestContext.run({ waitUntil: () => undefined }, async () => {
        const body = JSON.stringify({ ...payload, event })
        await verifier(signedRequest(body), body)
        expect(requestContext.getStore()?.slackSearchCredential).toBeUndefined()
      })
    }
  })

  test('captures verified DM requests with canonical root and reply bindings', async () => {
    for (const agentViewEnabled of [false, true]) {
      for (const isReply of [false, true]) {
        const threadTs = isReply ? '123.400' : agentViewEnabled ? '123.456' : ''
        const body = JSON.stringify({
          type: 'event_callback', team_id: 'T1', action_token: ACTION_TOKEN,
          event: { type: 'message', channel: 'D1', channel_type: 'im', user: 'U1', ts: '123.456',
            ...(isReply ? { thread_ts: '123.400' } : {}) }
        })
        const verifier = slackCredentialSafeVerifier(SIGNING_SECRET,
          payload => captureSlackSearchCredential(payload, agentViewEnabled))
        await requestContext.run({ waitUntil: () => undefined }, async () => {
          expect(String(await verifier(signedRequest(body), body))).not.toContain(ACTION_TOKEN)
          expect(takeSlackSearchCredential(`slack:D1:${threadTs}`, '123.456', 'UOTHER')).toBeUndefined()
          expect(takeSlackSearchCredential('slack:D1:999.000', '123.456', 'U1')).toBeUndefined()
          const credential = takeSlackSearchCredential(`slack:D1:${threadTs}`, '123.456', 'U1')
          expect(credential?.channelId).toBe('D1')
          expect(credential?.threadTs).toBe(threadTs)
          expect(credential?.actionToken).toBe(ACTION_TOKEN)
          expect(takeSlackSearchCredential(`slack:D1:${threadTs}`, '123.456', 'U1')).toBeUndefined()
        })
      }
    }
  })

  test('strips credentials recursively without mutating harmless raw metadata', () => {
    const raw = {
      action_token: ACTION_TOKEN,
      event: {
        message: { action_token: ACTION_TOKEN, text: 'keep this message' },
        previous_message: { action_token: ACTION_TOKEN, ts: '123.456' },
        reactions: [{ name: 'eyes', users: ['U1'], count: 1 }],
        raw: [{ action_token: ACTION_TOKEN, nested: [{ action_token: ACTION_TOKEN, id: 'C1' }] }]
      }
    }
    const sanitized = withoutSlackActionTokens(raw)
    expect(sanitized).toEqual({
      event: {
        message: { text: 'keep this message' },
        previous_message: { ts: '123.456' },
        reactions: [{ name: 'eyes', users: ['U1'], count: 1 }],
        raw: [{ nested: [{ id: 'C1' }] }]
      }
    })
    expect(JSON.stringify(sanitized)).not.toContain(ACTION_TOKEN)
    expect(raw.event.message.action_token).toBe(ACTION_TOKEN)
    expect(withoutSlackActionTokens(raw.event.reactions)).toBe(raw.event.reactions)
  })

  test('removes raw credentials when serializing a message for recovery', async () => {
    const serialized = await serializeMessage(new Message({
      id: '123.456',
      threadId: 'slack:C1:123.456',
      text: 'keep this message',
      formatted: parseMarkdown('keep this message'),
      attachments: [],
      raw: { event: { action_token: ACTION_TOKEN }, team: 'T1', reactions: [{ name: 'eyes' }] },
      author: { fullName: 'Test', userName: 'test', userId: 'U1', isMe: false, isBot: false },
      metadata: { dateSent: new Date(), edited: false }
    }))
    expect(serialized.raw).toEqual({ event: {}, team: 'T1', reactions: [{ name: 'eyes' }] })
    expect(JSON.stringify(serialized)).not.toContain(ACTION_TOKEN)
  })

  test('verifies signed original bytes before returning sanitized JSON to the SDK', async () => {
    const body = JSON.stringify({ event: { action_token: ACTION_TOKEN, text: 'hello' } })
    const verifier = slackCredentialSafeVerifier(SIGNING_SECRET)
    const request = signedRequest(body)
    const result = await verifier(request, body)
    expect(result).toBe('{"event":{"text":"hello"}}')
    await expect(verifier(request, String(result))).rejects.toThrow('signature is invalid')
  })

  test('keeps timestamp replay protection', async () => {
    const body = JSON.stringify({ event: { action_token: ACTION_TOKEN } })
    await expect(slackCredentialSafeVerifier(SIGNING_SECRET)(signedRequest(body, undefined, 600), body))
      .rejects.toThrow('timestamp is too old')
  })

  test('removes credentials from form payloads while preserving interaction actions', async () => {
    const payload = {
      type: 'block_actions',
      action_token: ACTION_TOKEN,
      message: { action_token: ACTION_TOKEN, text: 'hello' },
      actions: [{ action_id: 'workflow.approve', value: 'keep-this-value' }]
    }
    const body = new URLSearchParams({ payload: JSON.stringify(payload), action_token: ACTION_TOKEN }).toString()
    const result = await slackCredentialSafeVerifier(SIGNING_SECRET)(
      signedRequest(body, 'application/x-www-form-urlencoded'), body
    )
    const params = new URLSearchParams(String(result))
    expect(params.has('action_token')).toBe(false)
    expect(JSON.parse(params.get('payload')!)).toEqual({
      type: 'block_actions',
      message: { text: 'hello' },
      actions: payload.actions
    })
    expect(String(result)).not.toContain(ACTION_TOKEN)
  })

  test('decodes escaped JSON property names and preserves malformed-payload handling', async () => {
    const body = '{"event":{"action_\\u0074oken":"synthetic-action-token-canary","text":"hello"}}'
    const verifier = slackCredentialSafeVerifier(SIGNING_SECRET)
    expect(await verifier(signedRequest(body), body)).toBe('{"event":{"text":"hello"}}')
    const malformed = `{"action_token":"${ACTION_TOKEN}","event":`
    expect(await verifier(signedRequest(malformed), malformed)).toBe('{')
    const form = new URLSearchParams({ payload: malformed }).toString()
    const sanitizedForm = await verifier(signedRequest(form, 'application/x-www-form-urlencoded'), form)
    expect(new URLSearchParams(String(sanitizedForm)).get('payload')).toBe('{')
    expect(String(sanitizedForm)).not.toContain(ACTION_TOKEN)
  })

  test('never returns the original body for a token-only form', async () => {
    const body = new URLSearchParams({ action_token: ACTION_TOKEN }).toString()
    const result = await slackCredentialSafeVerifier(SIGNING_SECRET)(
      signedRequest(body, 'application/x-www-form-urlencoded'), body
    )
    expect(typeof result).toBe('string')
    expect(result).toBeTruthy()
    expect(String(result)).not.toContain(ACTION_TOKEN)
    expect(new URLSearchParams(String(result)).has('action_token')).toBe(false)
  })
})
