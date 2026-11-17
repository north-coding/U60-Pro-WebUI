import type { ProxyGroups } from '../../types'

export const PROXY_READY_ATTEMPTS = 12
export const PROXY_READY_INTERVAL_MS = 500

export interface SubscriptionUpdateResult {
  ok: boolean
  error?: string
}

export interface SubscriptionUpdateSummary {
  results: Record<string, SubscriptionUpdateResult>
  successCount: number
  failureCount: number
  malformed: boolean
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Count only explicit, complete per-subscription results as successes. */
export function summarizeSubscriptionUpdate(reply: unknown, expectedIds: readonly string[]): SubscriptionUpdateSummary {
  const ids = [...new Set(expectedIds)]
  const failAll = (): SubscriptionUpdateSummary => ({
    results: Object.fromEntries(ids.map((id) => [id, { ok: false }])),
    successCount: 0,
    failureCount: ids.length,
    malformed: true,
  })

  if (!ids.length || !isRecord(reply) || !isRecord(reply.results)) return failAll()
  const returnedIds = Object.keys(reply.results)
  if (returnedIds.length !== ids.length || ids.some((id) => !Object.hasOwn(reply.results as object, id))) return failAll()

  const results: Record<string, SubscriptionUpdateResult> = {}
  let malformed = false
  for (const id of ids) {
    const result = reply.results[id]
    if (!isRecord(result) || typeof result.ok !== 'boolean') {
      results[id] = { ok: false }
      malformed = true
      continue
    }
    if (result.ok) {
      results[id] = { ok: true }
    } else {
      results[id] = { ok: false }
      if (typeof result.error === 'string' && result.error.trim()) results[id].error = result.error
    }
  }

  const successCount = Object.values(results).filter((result) => result.ok).length
  return { results, successCount, failureCount: ids.length - successCount, malformed }
}

/** Poll the groups endpoint; it succeeds only after the manager and controller both respond. */
export async function waitForProxyReady(
  getGroups: () => Promise<ProxyGroups>,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  attempts = PROXY_READY_ATTEMPTS,
  intervalMs = PROXY_READY_INTERVAL_MS,
): Promise<boolean> {
  const maxAttempts = Math.max(1, Math.floor(attempts))
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      if ((await getGroups()).running === true) return true
    } catch {
      // Startup can briefly return 503 while the controller is becoming ready.
    }
    if (attempt + 1 < maxAttempts) await sleep(intervalMs)
  }
  return false
}

export type SubscriptionFlowOutcome =
  | { status: 'cancelled' }
  | { status: 'start-failed'; error: unknown }
  | { status: 'not-ready' }
  | { status: 'readiness-failed'; error: unknown }
  | { status: 'update-failed'; error: unknown }
  | { status: 'updated'; summary: SubscriptionUpdateSummary }

/** Start only after an explicit confirmation, then wait for readiness before refreshing. */
export async function runSubscriptionUpdateFlow(options: {
  running: boolean
  expectedIds: readonly string[]
  confirmStart: () => Promise<boolean>
  start: () => Promise<unknown>
  waitUntilReady: () => Promise<boolean>
  refresh: () => Promise<unknown>
}): Promise<SubscriptionFlowOutcome> {
  if (!options.running) {
    let confirmed: boolean
    try {
      confirmed = await options.confirmStart()
    } catch (error) {
      return { status: 'start-failed', error }
    }
    if (!confirmed) return { status: 'cancelled' }
    try {
      await options.start()
    } catch (error) {
      return { status: 'start-failed', error }
    }
  }

  let ready: boolean
  try {
    ready = await options.waitUntilReady()
  } catch (error) {
    return { status: 'readiness-failed', error }
  }
  if (!ready) return { status: 'not-ready' }

  try {
    const reply = await options.refresh()
    return { status: 'updated', summary: summarizeSubscriptionUpdate(reply, options.expectedIds) }
  } catch (error) {
    return { status: 'update-failed', error }
  }
}
