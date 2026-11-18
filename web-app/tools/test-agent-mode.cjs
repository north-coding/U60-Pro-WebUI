const { test } = require('node:test')
const assert = require('node:assert/strict')
const { loadTs } = require('./ts-loader.cjs')
const mode = loadTs('app/agentMode.ts')

test('credential gate only permits HTTPS or local loopback development contexts', () => {
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: 'localhost' }), true)
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: '127.0.0.1' }), true)
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: '127.0.0.2' }), true)
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: 'router.localhost' }), true)
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: '192.168.0.1' }), false)
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: 'u60.local' }), false)
  assert.equal(mode.secureManagementContext({ protocol: 'http:', hostname: '127.attacker.example' }), false)
  assert.equal(mode.secureManagementContext({ protocol: 'https:', hostname: '192.168.0.1' }), true)
})

test('capability probe accepts only authenticated proxy-management modes', () => {
  assert.equal(mode.agentModeFromCapabilities({ mode: 'proxy_only', auth_required: true, features: ['proxy_management'] }), 'proxy_only')
  assert.equal(mode.agentModeFromCapabilities({ mode: 'full', auth_required: true, features: ['router_management', 'proxy_management'] }), 'full')
  assert.equal(mode.agentModeFromCapabilities({ mode: 'proxy_only', auth_required: false, features: ['proxy_management'] }), undefined)
  assert.equal(mode.agentModeFromCapabilities({ mode: 'proxy_only', auth_required: true, features: ['router_management'] }), undefined)
  assert.equal(mode.agentModeFromCapabilities({ mode: 'unknown', auth_required: true, features: ['proxy_management'] }), undefined)
})
