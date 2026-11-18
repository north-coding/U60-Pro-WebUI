const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const ts = require('typescript')
// These fixtures evaluate one module in isolation; i18n resolves to English.
const i18nStub = {
  t: (text, vars) => (vars ? text.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m)) : text),
}
function fixture(fetchImpl, location = { protocol: 'http:', hostname: '192.168.0.1', origin: 'http://192.168.0.1:8080' }) {
  const requests = []
  const context = { exports: {}, require: () => i18nStub, AbortController, setTimeout, clearTimeout,
    window: { location, dispatchEvent: () => {} },
    sessionStorage: { getItem: () => 'general-session-secret', setItem: () => {}, removeItem: () => {} },
    fetch: async (url, options) => {
      requests.push({ url, options })
      if (fetchImpl) return fetchImpl(url, options)
      return { ok: true, status: 200, json: async () => ({ ok: true, data: url.endsWith('/api/auth/login') ? { token: 'synthetic-login-token' } : {} }) }
    },
  }
  const source = fs.readFileSync(path.join(__dirname, '../src/data/client.ts'), 'utf8')
  vm.runInNewContext(ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
  } }).outputText, context)
  return { client: context.exports, requests }
}
test('HTTPS WebUI uses its same origin for Agent APIs and never targets plaintext port 9090', async () => {
  const origin = 'https://u60.home.arpa:8443'
  const { client, requests } = fixture(undefined, { protocol: 'https:', hostname: 'u60.home.arpa', origin })
  const login = await client.login('synthetic-password')
  client.setToken(login.token)
  await client.get('/api/proxy/groups')
  assert.equal(client.API_BASE, origin)
  assert.deepEqual(requests.map(request => request.url), [
    `${origin}/api/auth/login`,
    `${origin}/api/proxy/groups`,
  ])
  assert.ok(requests.every(request => request.url.startsWith('https://')))
  assert.equal(requests[0].options.headers.Authorization, undefined)
  assert.equal(requests[1].options.headers.Authorization, 'Bearer synthetic-login-token')
})

test('HTTPS failures are explicit and never fall back to HTTP; LAN confirmation sends no token', async () => {
  const origin = 'https://u60.home.arpa:8443'
  const { client, requests } = fixture(() => Promise.reject(new Error('certificate rejected')), {
    protocol: 'https:', hostname: 'u60.home.arpa', origin,
  })
  await assert.rejects(client.get('/api/proxy/groups'), /HTTPS gateway and trusted certificate/)
  await assert.rejects(client.readCsv('/api/system/log.csv'), /HTTPS gateway and trusted certificate/)
  await assert.rejects(client.confirmLan('192.168.2.1', 'one-time-secret'), /cannot send a token over HTTP/)
  assert.equal(requests.length, 2)
  assert.equal(requests[0].url, `${origin}/api/proxy/groups`)
  assert.equal(requests[1].url, `${origin}/api/system/log.csv`)
  assert.ok(requests.every(request => !request.url.startsWith('http://')))
})

test('LAN confirmation carries only the scoped nonce to the new address', async () => {
  const { client, requests } = fixture()
  assert.equal(client.API_BASE, 'http://192.168.0.1:9090')
  await client.confirmLan('192.168.2.1', 'single-use-nonce')
  assert.equal(requests[0].url, 'http://192.168.2.1:9090/api/router/lan/confirm')
  assert.equal(requests[0].options.headers.Authorization, undefined)
  assert.equal(JSON.parse(requests[0].options.body).token, 'single-use-nonce')
  await client.get('/api/device')
  assert.equal(requests[1].options.headers.Authorization, 'Bearer general-session-secret')
})
test('LAN confirmation rejects URLs and addresses outside private IPv4 space', async () => {
  const { client, requests } = fixture()
  for (const ip of ['8.8.8.8', '192.168.1.999', 'http://192.168.1.1', '192.168.1.1@example.org', '172.32.0.1']) {
    await assert.rejects(client.confirmLan(ip, 'nonce'), /Invalid LAN/)
  }
  assert.equal(requests.length, 0)
})

test('GET request timeout aborts a nonresponsive fetch', async () => {
  const { client, requests } = fixture((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true })
  }))
  await assert.rejects(client.get('/api/proxy/groups', 20), /Timed out reaching the agent/)
  assert.equal(requests.length, 1)
  assert.equal(requests[0].options.signal.aborted, true)
})

test('caller cancellation aborts the underlying GET', async () => {
  const { client, requests } = fixture((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true })
  }))
  const caller = new AbortController()
  const request = client.get('/api/proxy/groups', 1000, caller.signal)
  await new Promise((resolve) => setTimeout(resolve, 0))
  caller.abort()
  await assert.rejects(request, /Timed out reaching the agent/)
  assert.equal(requests.length, 1)
  assert.equal(requests[0].options.signal.aborted, true)
})
