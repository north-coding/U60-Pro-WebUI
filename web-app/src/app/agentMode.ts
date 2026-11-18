export type AgentMode = 'proxy_only' | 'full'

function isLoopbackIpv4(hostname: string): boolean {
  const octets = hostname.split('.')
  return octets.length === 4 && octets.every((part) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return false
    const value = Number(part)
    return value <= 255
  }) && Number(octets[0]) === 127
}

export function secureManagementContext(location: Pick<Location, 'protocol' | 'hostname'>): boolean {
  if (location.protocol === 'https:') return true
  if (location.protocol !== 'http:') return false
  const hostname = location.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '::1' ||
    isLoopbackIpv4(hostname)
}

export function agentModeFromCapabilities(value: Record<string, unknown>): AgentMode | undefined {
  if (value.auth_required !== true || !Array.isArray(value.features) || !value.features.includes('proxy_management')) {
    return undefined
  }
  return value.mode === 'proxy_only' || value.mode === 'full' ? value.mode : undefined
}
