import { verifySlackSignature, type SlackWebhookVerifier } from '@chat-adapter/slack/webhook'

/** Action tokens are request credentials, not durable Slack message metadata. */
export function withoutSlackActionTokens(value: unknown): unknown {
  if (Array.isArray(value)) {
    const items = value.map(withoutSlackActionTokens)
    return items.some((item, index) => item !== value[index]) ? items : value
  }
  if (!value || typeof value !== 'object') return value

  let changed = false
  const entries: Array<[string, unknown]> = []
  for (const [key, item] of Object.entries(value)) {
    if (key === 'action_token') {
      changed = true
      continue
    }
    const sanitized = withoutSlackActionTokens(item)
    if (sanitized !== item) changed = true
    entries.push([key, sanitized])
  }
  return changed ? Object.fromEntries(entries) : value
}

function sanitizeJson(body: string): string {
  try {
    const value: unknown = JSON.parse(body)
    const sanitized = withoutSlackActionTokens(value)
    return sanitized === value ? body : JSON.stringify(sanitized)
  } catch {
    // Keep the SDK's malformed-payload response without handing it credential
    // bytes that a parser diagnostic or future debug log could retain.
    return '{'
  }
}

/** Verify original bytes, then remove credentials before SDK logging/caching. */
export function slackCredentialSafeVerifier(
  signingSecret: string,
  onVerifiedEvent?: (payload: unknown) => void
): SlackWebhookVerifier {
  return async (request, body) => {
    await verifySlackSignature(body, request.headers, { signingSecret })
    if (request.headers.get('content-type')?.includes('application/x-www-form-urlencoded')) {
      const params = new URLSearchParams(body)
      const payload = params.get('payload')
      const sanitizedPayload = payload === null ? null : sanitizeJson(payload)
      if (!params.has('action_token') && payload === sanitizedPayload) return body || true
      params.delete('action_token')
      if (sanitizedPayload !== null) params.set('payload', sanitizedPayload)
      // A boolean true tells the SDK to reuse the original credential-bearing
      // body. Keep an empty sanitized form truthy without restoring that body.
      return params.toString() || ' '
    }
    if (onVerifiedEvent) {
      // Capture only the verified request, before removing credentials from the
      // bytes seen by the SDK. Malformed bodies retain the generic SDK error.
      let payload: unknown
      try { payload = JSON.parse(body) } catch { return '{' }
      onVerifiedEvent(payload)
    }
    return sanitizeJson(body) || true
  }
}
