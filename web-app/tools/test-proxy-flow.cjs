const { test } = require('node:test')
const assert = require('node:assert/strict')
const { loadTs } = require('./ts-loader.cjs')
const flow = loadTs('features/proxy/subscriptionFlow.ts')

test('stopped update requires confirmation and does nothing when declined', async () => {
  const calls = []
  const result = await flow.runSubscriptionUpdateFlow({
    running: false,
    expectedIds: ['sub-a'],
    confirmStart: async () => { calls.push('confirm'); return false },
    start: async () => calls.push('start'),
    waitUntilReady: async () => { calls.push('ready'); return true },
    refresh: async () => { calls.push('refresh'); return { results: { 'sub-a': { ok: true } } } },
  })
  assert.equal(result.status, 'cancelled')
  assert.deepEqual(calls, ['confirm'])
})

test('failed start never checks readiness or reports a refresh', async () => {
  const calls = []
  const result = await flow.runSubscriptionUpdateFlow({
    running: false,
    expectedIds: ['sub-a'],
    confirmStart: async () => { calls.push('confirm'); return true },
    start: async () => { calls.push('start'); throw new Error('synthetic start failure') },
    waitUntilReady: async () => { calls.push('ready'); return true },
    refresh: async () => { calls.push('refresh'); return { results: { 'sub-a': { ok: true } } } },
  })
  assert.equal(result.status, 'start-failed')
  assert.deepEqual(calls, ['confirm', 'start'])
})

test('a started proxy that never becomes ready is not refreshed', async () => {
  const calls = []
  const result = await flow.runSubscriptionUpdateFlow({
    running: false,
    expectedIds: ['sub-a'],
    confirmStart: async () => { calls.push('confirm'); return true },
    start: async () => { calls.push('start') },
    waitUntilReady: async () => { calls.push('ready'); return false },
    refresh: async () => { calls.push('refresh'); return { results: { 'sub-a': { ok: true } } } },
  })
  assert.equal(result.status, 'not-ready')
  assert.deepEqual(calls, ['confirm', 'start', 'ready'])
})

test('successful start waits for readiness before refreshing', async () => {
  const calls = []
  const result = await flow.runSubscriptionUpdateFlow({
    running: false,
    expectedIds: ['sub-a', 'sub-b'],
    confirmStart: async () => { calls.push('confirm'); return true },
    start: async () => { calls.push('start') },
    waitUntilReady: async () => { calls.push('ready'); return true },
    refresh: async () => { calls.push('refresh'); return { results: { 'sub-a': { ok: true }, 'sub-b': { ok: true } } } },
  })
  assert.deepEqual(calls, ['confirm', 'start', 'ready', 'refresh'])
  assert.equal(result.status, 'updated')
  assert.equal(result.summary.successCount, 2)
  assert.equal(result.summary.failureCount, 0)
})

test('a running proxy is checked for readiness without prompting or starting again', async () => {
  const calls = []
  const result = await flow.runSubscriptionUpdateFlow({
    running: true,
    expectedIds: ['sub-a'],
    confirmStart: async () => { calls.push('confirm'); return true },
    start: async () => { calls.push('start') },
    waitUntilReady: async () => { calls.push('ready'); return true },
    refresh: async () => { calls.push('refresh'); return { results: { 'sub-a': { ok: true } } } },
  })
  assert.deepEqual(calls, ['ready', 'refresh'])
  assert.equal(result.status, 'updated')
})

test('readiness polling retries transient errors and stops at its bound', async () => {
  let checks = 0
  let sleeps = 0
  const ready = await flow.waitForProxyReady(async () => {
    checks += 1
    if (checks === 1) throw new Error('synthetic controller startup delay')
    return { running: false, groups: [], nodes: [] }
  }, { attempts: 3, intervalMs: 25, timeoutMs: 500 }, async (ms) => { assert.equal(ms, 25); sleeps += 1 })
  assert.equal(ready, false)
  assert.equal(checks, 3)
  assert.equal(sleeps, 2)
})

test('readiness polling succeeds only on an explicit running response', async () => {
  let checks = 0
  const ready = await flow.waitForProxyReady(async () => {
    checks += 1
    return { running: checks === 2, groups: [], nodes: [] }
  }, { attempts: 4, intervalMs: 0, timeoutMs: 500 }, async () => {})
  assert.equal(ready, true)
  assert.equal(checks, 2)
})

test('a nonresponsive readiness request is aborted by the total deadline', async () => {
  let checks = 0
  let cancellations = 0
  const startedAt = Date.now()
  const ready = await flow.waitForProxyReady(({ signal }) => {
    checks += 1
    return new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => {
        cancellations += 1
        reject(new Error('synthetic request aborted'))
      }, { once: true })
    })
  }, { attempts: 12, intervalMs: 5, timeoutMs: 40, requestTimeoutMs: 100 })
  assert.equal(ready, false)
  assert.equal(checks, 1)
  assert.equal(cancellations, 1)
  assert.ok(Date.now() - startedAt < 500)
})

test('partial provider failures remain failures while successful providers are counted', () => {
  const summary = flow.summarizeSubscriptionUpdate({
    results: { 'sub-a': { ok: true }, 'sub-b': { ok: false, error: 'synthetic provider failure' } },
  }, ['sub-a', 'sub-b'])
  assert.equal(summary.successCount, 1)
  assert.equal(summary.failureCount, 1)
  assert.equal(summary.results['sub-a'].ok, true)
  assert.equal(summary.results['sub-b'].ok, false)
  assert.equal(summary.results['sub-b'].error, 'synthetic provider failure')
})

test('empty, missing and extra result maps fail closed', () => {
  for (const reply of [
    {},
    { results: {} },
    { results: [] },
    { results: { 'sub-a': { ok: true } } },
    { results: { 'sub-a': { ok: true }, 'sub-b': { ok: true }, unexpected: { ok: true } } },
  ]) {
    const summary = flow.summarizeSubscriptionUpdate(reply, ['sub-a', 'sub-b'])
    assert.equal(summary.failureCount, 2, JSON.stringify(reply))
    assert.equal(summary.successCount, 0, JSON.stringify(reply))
    assert.equal(summary.malformed, true, JSON.stringify(reply))
  }
})

test('a malformed per-subscription entry fails that provider while preserving explicit results', () => {
  const summary = flow.summarizeSubscriptionUpdate({
    results: { 'sub-a': { ok: true }, 'sub-b': { ok: 'true' } },
  }, ['sub-a', 'sub-b'])
  assert.equal(summary.successCount, 1)
  assert.equal(summary.failureCount, 1)
  assert.equal(summary.malformed, true)
  assert.equal(summary.results['sub-a'].ok, true)
  assert.equal(summary.results['sub-b'].ok, false)
})
