const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { execFileSync } = require('node:child_process')
const http = require('node:http')
const https = require('node:https')
const vm = require('node:vm')
const ts = require('typescript')
const { loadTs } = require('./ts-loader.cjs')

const i18nStub = {
  t: (text, vars) => (vars ? text.replace(/\{(\w+)\}/g, (match, key) => (key in vars ? String(vars[key]) : match)) : text),
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject)
      resolve(server.address())
    })
  })
}

function close(server) {
  return new Promise(resolve => server.close(() => resolve()))
}

function httpsRequest(url, { method = 'GET', headers = {}, body, ca, signal } = {}) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method, headers, ca, signal }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => resolve({
        status: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'),
        json: async () => JSON.parse(Buffer.concat(chunks).toString('utf8')),
      }))
    })
    request.once('error', reject)
    if (body !== undefined) request.write(body)
    request.end()
  })
}

function loadManagementApi(location, fetchImpl) {
  const previous = {
    window: globalThis.window,
    sessionStorage: globalThis.sessionStorage,
    fetch: globalThis.fetch,
  }
  globalThis.window = { location, dispatchEvent: () => {} }
  globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} }
  globalThis.fetch = fetchImpl
  const client = loadTs('data/client.ts', { stubs: { i18n: i18nStub } })
  const api = loadTs('data/api.ts', { stubs: { client, i18n: i18nStub } }).api
  const flow = loadTs('features/proxy/subscriptionFlow.ts')
  return {
    client,
    api,
    flow,
    restore() {
      if (previous.window === undefined) delete globalThis.window
      else globalThis.window = previous.window
      if (previous.sessionStorage === undefined) delete globalThis.sessionStorage
      else globalThis.sessionStorage = previous.sessionStorage
      globalThis.fetch = previous.fetch
    },
  }
}

function loadClient(location, fetchImpl) {
  const sourcePath = path.join(__dirname, '../src/data/client.ts')
  const source = fs.readFileSync(sourcePath, 'utf8')
  const context = {
    exports: {},
    require: () => i18nStub,
    AbortController,
    setTimeout,
    clearTimeout,
    window: { location, dispatchEvent: () => {} },
    sessionStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: fetchImpl,
  }
  vm.runInNewContext(ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText, context)
  return context.exports
}

test('synthetic same-origin HTTPS gateway keeps credentials on TLS and forwards allowed proxy APIs', async t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'u60-secure-origin-'))
  fs.chmodSync(temp, 0o700)
  const keyFile = path.join(temp, 'ephemeral-test-key.pem')
  const certFile = path.join(temp, 'ephemeral-test-cert.pem')
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1',
    '-keyout', keyFile, '-out', certFile, '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:TRUE',
  ], { stdio: 'ignore' })
  const key = fs.readFileSync(keyFile)
  const cert = fs.readFileSync(certFile)
  const observedAgentRequests = []
  const expectedPassword = 'synthetic-password-only'
  const expectedToken = 'synthetic-bearer-only'
  const trustedOrigin = { value: '' }
  let refreshData = { results: {
    'synthetic-id': { ok: true },
    'synthetic-second': { ok: true },
  } }

  const agent = http.createServer((request, response) => {
    const chunks = []
    request.on('data', chunk => chunks.push(chunk))
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8')
      observedAgentRequests.push({
        url: request.url,
        method: request.method,
        origin: request.headers.origin,
        authorization: request.headers.authorization,
        body,
        remoteAddress: request.socket.remoteAddress,
      })
      response.setHeader('Content-Type', 'application/json')
      response.setHeader('Cache-Control', 'no-store')
      if (request.headers.origin && request.headers.origin !== trustedOrigin.value) {
        response.writeHead(403).end(JSON.stringify({ ok: false, error: 'origin is not allowed' }))
      } else if (request.url === '/api/proxy/capabilities' && request.method === 'GET') {
        response.end(JSON.stringify({ ok: true, data: { mode: 'proxy_only', auth_required: true, features: ['proxy_management'] } }))
      } else if (request.url === '/api/auth/login' && request.method === 'POST') {
        if (JSON.parse(body).password !== expectedPassword) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: { token: expectedToken } }))
        }
      } else if (request.url === '/api/proxy/subscriptions' && request.method === 'GET') {
        if (request.headers.authorization !== `Bearer ${expectedToken}`) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: { running: true, subscriptions: [
            { id: 'synthetic-id', name: 'synthetic-provider', enabled: true, use_config: false, interval_hours: 24 },
            { id: 'synthetic-second', name: 'synthetic-second-provider', enabled: true, use_config: false, interval_hours: 24 },
          ] } }))
        }
      } else if (request.url === '/api/proxy/subscriptions' && request.method === 'POST') {
        if (request.headers.authorization !== `Bearer ${expectedToken}`) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: { id: 'synthetic-id', name: 'synthetic-provider' } }))
        }
      } else if (request.url === '/api/proxy/subscriptions/update' && request.method === 'POST') {
        if (request.headers.authorization !== `Bearer ${expectedToken}`) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: refreshData }))
        }
      } else if (request.url === '/api/proxy/groups' && request.method === 'GET') {
        if (request.headers.authorization !== `Bearer ${expectedToken}`) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: {
            running: true,
            groups: [{ name: 'PROXY', type: 'Selector', now: 'synthetic-node', all: ['synthetic-node'], hidden: false }],
            nodes: [{ name: 'synthetic-node', type: 'Shadowsocks', udp: true, alive: true, delay: 20,
              subscription_id: 'synthetic-id', subscription: 'synthetic-provider' }],
          } }))
        }
      } else if (request.url === '/api/proxy/groups' && request.method === 'PUT') {
        if (request.headers.authorization !== `Bearer ${expectedToken}`) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: { group: 'PROXY', now: 'synthetic-node' } }))
        }
      } else if (request.url === '/api/proxy/settings' && request.method === 'PUT') {
        if (request.headers.authorization !== `Bearer ${expectedToken}`) {
          response.writeHead(401).end(JSON.stringify({ ok: false, error: 'unauthorized' }))
        } else {
          response.end(JSON.stringify({ ok: true, data: { mode: 'rule', preset: 'bypass_cn' } }))
        }
      } else {
        const knownPath = ['/api/proxy/subscriptions', '/api/proxy/subscriptions/update', '/api/proxy/groups', '/api/proxy/settings'].includes(request.url)
        response.writeHead(knownPath ? 405 : 404).end(JSON.stringify({ ok: false, error: knownPath ? 'method not allowed' : 'not found' }))
      }
    })
  })
  const agentAddress = await listen(agent)
  assert.equal(agentAddress.address, '127.0.0.1')
  t.after(() => close(agent))

  const gateway = https.createServer({ key, cert }, (request, response) => {
    if (request.url === '/' && request.method === 'GET') {
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      response.end('<!doctype html><title>U60 Proxy WebUI</title><main>Proxy management</main>')
      return
    }
    if (!request.url.startsWith('/api/')) {
      response.writeHead(404).end('not found')
      return
    }
    const upstream = http.request({
      hostname: '127.0.0.1',
      port: agentAddress.port,
      method: request.method,
      path: request.url,
      headers: request.headers,
    }, upstreamResponse => {
      response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers)
      upstreamResponse.pipe(response)
    })
    upstream.once('error', () => {
      if (!response.headersSent) response.writeHead(502)
      response.end(JSON.stringify({ ok: false, error: 'loopback Agent unavailable' }))
    })
    request.pipe(upstream)
  })
  const gatewayAddress = await listen(gateway)
  t.after(() => close(gateway))
  const origin = `https://127.0.0.1:${gatewayAddress.port}`
  trustedOrigin.value = origin
  const ca = cert

  try {
    const page = await httpsRequest(`${origin}/`, { ca })
    assert.equal(page.status, 200)
    assert.match(page.body, /U60 Proxy WebUI/)

    const webRequests = []
    const fetchImpl = async (url, options) => {
      webRequests.push({ url, options })
      const headers = { ...options.headers, Origin: origin }
      const result = await httpsRequest(url, { method: options.method, headers, body: options.body, ca, signal: options.signal })
      return {
        ok: result.status >= 200 && result.status < 300,
        status: result.status,
        json: result.json,
      }
    }
    const client = loadClient({ protocol: 'https:', hostname: '127.0.0.1', origin }, fetchImpl)
    assert.equal(client.API_BASE, origin)

    const capabilities = await client.req('GET', '/api/proxy/capabilities', undefined, undefined, 15000, client.API_BASE, false)
    assert.equal(capabilities.mode, 'proxy_only')
    const management = loadManagementApi(
      { protocol: 'https:', hostname: '127.0.0.1', origin },
      fetchImpl,
    )
    t.after(() => management.restore())
    const login = await management.client.login(expectedPassword)
    assert.equal(login.token, expectedToken)
    management.client.setToken(login.token)

    // Exercise the actual API facade and its response mappers against Rust
    // Agent-shaped synthetic envelopes through the HTTPS gateway.
    const subscriptions = await management.api.proxySubscriptions()
    const added = await management.api.proxySubscriptionAdd({
      name: 'synthetic-provider', url: 'https://provider.invalid/synthetic', interval_hours: 24, use_config: false,
    })
    const groups = await management.api.proxyGroups()
    const selected = await management.api.proxySelect('PROXY', 'synthetic-node')
    const settings = await management.api.proxySettings({ mode: 'rule', preset: 'bypass_cn' })
    assert.equal(subscriptions.running, true)
    assert.equal(subscriptions.subscriptions[0].name, 'synthetic-provider')
    assert.equal(subscriptions.subscriptions[0].use_config, false)
    assert.equal(added.id, 'synthetic-id')
    assert.equal(groups.running, true)
    assert.equal(groups.groups[0].name, 'PROXY')
    assert.equal(groups.nodes[0].name, 'synthetic-node')
    assert.equal(selected.now, 'synthetic-node')
    assert.equal(settings.preset, 'bypass_cn')

    const expectedIds = subscriptions.subscriptions.map(subscription => subscription.id)
    const runUpdate = () => management.flow.runSubscriptionUpdateFlow({
      running: true,
      expectedIds,
      confirmStart: async () => { throw new Error('already running; confirmation is not expected') },
      start: async () => { throw new Error('already running; start is not expected') },
      waitUntilReady: async () => (await management.api.proxyGroups()).running,
      refresh: () => management.api.proxySubscriptionUpdate(),
    })

    const successful = await runUpdate()
    assert.equal(successful.status, 'updated')
    assert.equal(successful.summary.successCount, 2)
    assert.equal(successful.summary.failureCount, 0)

    refreshData = { results: {
      'synthetic-id': { ok: true },
      'synthetic-second': { ok: false, error: 'synthetic provider unavailable' },
    } }
    const partial = await runUpdate()
    assert.equal(partial.status, 'updated')
    assert.equal(partial.summary.successCount, 1)
    assert.equal(partial.summary.failureCount, 1)
    assert.equal(partial.summary.results['synthetic-second'].error, 'synthetic provider unavailable')

    refreshData = { results: {
      'synthetic-id': { ok: 'true' },
      'synthetic-second': { ok: true },
    } }
    const malformed = await runUpdate()
    assert.equal(malformed.status, 'updated')
    assert.equal(malformed.summary.malformed, true)
    assert.equal(malformed.summary.successCount, 1)
    assert.equal(malformed.summary.failureCount, 1)
    assert.equal(malformed.summary.results['synthetic-id'].ok, false)

    refreshData = { results: ['not-a-provider-result-map'] }
    const malformedResponse = await runUpdate()
    assert.equal(malformedResponse.status, 'updated')
    assert.equal(malformedResponse.summary.malformed, true)
    assert.equal(malformedResponse.summary.successCount, 0)
    assert.equal(malformedResponse.summary.failureCount, 2)

    refreshData = { results: { 'synthetic-id': { ok: true } } }
    const missingProvider = await runUpdate()
    assert.equal(missingProvider.status, 'updated')
    assert.equal(missingProvider.summary.malformed, true)
    assert.equal(missingProvider.summary.successCount, 0)
    assert.equal(missingProvider.summary.failureCount, 2)
    assert.ok(webRequests.some(item => item.url.endsWith('/api/proxy/subscriptions/update')))
    assert.ok(webRequests.length >= 12)
    assert.ok(webRequests.every(item => new URL(item.url).origin === origin))
    assert.ok(webRequests.every(item => !item.url.startsWith('http://')))
    const loginRequest = webRequests.find(item => item.url.endsWith('/api/auth/login'))
    assert.equal(loginRequest.options.headers.Authorization, undefined)
    assert.equal(JSON.parse(loginRequest.options.body).password, expectedPassword)

    const unauthorized = await httpsRequest(`${origin}/api/proxy/groups`, { ca, headers: { Origin: origin } })
    assert.equal(unauthorized.status, 401)
    const crossOrigin = await httpsRequest(`${origin}/api/proxy/groups`, {
      ca,
      headers: { Origin: 'https://attacker.invalid', Authorization: `Bearer ${expectedToken}` },
    })
    assert.equal(crossOrigin.status, 403)
    const unrelated = await httpsRequest(`${origin}/api/router/wifi`, {
      ca,
      headers: { Origin: origin, Authorization: `Bearer ${expectedToken}` },
    })
    assert.equal(unrelated.status, 404)
    const wrongMethod = await httpsRequest(`${origin}/api/proxy/groups`, {
      ca,
      method: 'DELETE',
      headers: { Origin: origin, Authorization: `Bearer ${expectedToken}` },
    })
    assert.equal(wrongMethod.status, 405)

    await assert.rejects(httpsRequest(`${origin}/api/proxy/capabilities`), error =>
      ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'DEPTH_ZERO_SELF_SIGNED_CERT'].includes(error.code))

    const noTrustUrls = []
    const noTrustClient = loadClient({ protocol: 'https:', hostname: '127.0.0.1', origin },
      (url, options) => {
        noTrustUrls.push(url)
        return httpsRequest(url, {
          method: options.method,
          headers: { ...options.headers, Origin: origin },
          body: options.body,
        }).then(result => ({ ok: result.status >= 200 && result.status < 300, status: result.status, json: result.json }))
      })
    await assert.rejects(noTrustClient.get('/api/proxy/capabilities'), /HTTPS gateway and trusted certificate/)
    assert.deepEqual(noTrustUrls, [`${origin}/api/proxy/capabilities`])

    assert.ok(observedAgentRequests.every(item => item.remoteAddress === '127.0.0.1' || item.remoteAddress === '::ffff:127.0.0.1'))
    assert.ok(observedAgentRequests.some(item => item.body.includes(expectedPassword)))
    assert.ok(observedAgentRequests.some(item => item.authorization === `Bearer ${expectedToken}`))
    assert.ok(observedAgentRequests.some(item => item.origin === 'https://attacker.invalid'))
    assert.ok(observedAgentRequests.every(item =>
      item.url.startsWith('/api/proxy/') || item.url === '/api/auth/login' || item.url === '/api/router/wifi'))
  } finally {
    await Promise.all([close(gateway), close(agent)])
    fs.rmSync(temp, { recursive: true, force: true })
  }
})
