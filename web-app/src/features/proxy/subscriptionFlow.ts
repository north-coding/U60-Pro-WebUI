import type { ProxyGroups } from '../../types'

export const PROXY_READY_ATTEMPTS = 12
export const PROXY_READY_INTERVAL_MS = 500
export const PROXY_READY_TIMEOUT_MS = 8_000
export const PROXY_READY_REQUEST_TIMEOUT_MS = 1_000

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

export interface ProxyReadyRequest {
  signal: AbortSignal
  timeoutMs: number
}

export interface ProxyReadyOptions {
  attempts?: number
  intervalMs?: number
  timeoutMs?: number
  requestTimeoutMs?: number
}

function sleepUntil(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted || ms <= 0) {
      resolve()
      return
    }
    const finish = () => {
      clearTimeout(timer)
      signal.removeEventListener('abort', finish)
      resolve()
    }
    const timer = setTimeout(finish, ms)
    signal.addEventListener('abort', finish, { once: true })
  })
}

/** Poll the groups endpoint under one deadline, including and canceling in-flight HTTP requests. */
export async function waitForProxyReady(
  getGroups: (request: ProxyReadyRequest) => Promise<ProxyGroups>,
  options: ProxyReadyOptions = {},
  sleep: (ms: number, signal: AbortSignal) => Promise<void> = sleepUntil,
): Promise<boolean> {
  const maxAttempts = Math.max(1, Math.floor(options.attempts ?? PROXY_READY_ATTEMPTS))
  const intervalMs = Math.max(0, options.intervalMs ?? PROXY_READY_INTERVAL_MS)
  const timeoutMs = Math.max(1, options.timeoutMs ?? PROXY_READY_TIMEOUT_MS)
  const requestTimeoutMs = Math.max(1, options.requestTimeoutMs ?? PROXY_READY_REQUEST_TIMEOUT_MS)
  const controller = new AbortController()
  const deadline = Date.now() + timeoutMs
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const remainingMs = deadline - Date.now()
      if (remainingMs <= 0 || controller.signal.aborted) return false
      try {
        const groups = await getGroups({
          signal: controller.signal,
          timeoutMs: Math.max(1, Math.min(requestTimeoutMs, remainingMs)),
        })
        if (controller.signal.aborted || Date.now() >= deadline) return false
        if (groups.running === true) return true
      } catch {
        // Startup can briefly return 503 while the controller is becoming ready.
        if (controller.signal.aborted) return false
      }
      const afterRequestMs = deadline - Date.now()
      if (afterRequestMs <= 0 || controller.signal.aborted) return false
      if (attempt + 1 < maxAttempts) {
        await sleep(Math.min(intervalMs, afterRequestMs), controller.signal)
      }
    }
    return false
  } finally {
    clearTimeout(timeout)
    controller.abort()
  }
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
