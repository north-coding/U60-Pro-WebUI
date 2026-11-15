import { useState } from 'react'
import { api } from '../../data/api'
import type { PollResult } from '../../data/poll'
import { useResource } from '../../data/poll'
import { t } from '../../i18n'
import type { Client, ProxyStatus } from '../../types'
import { Button, Field, Input, Select } from '../../ui/controls'
import { confirm, toastError } from '../../ui/feedback'
import { Card, Chip, InlineStatus } from '../../ui/primitives'
import { displayName } from '../network/clientsView'

const MAC_RE = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/

/** `aa-bb-…` / `aa:bb:…` → `AA:BB:…`, the form the agent stores. */
function normalizeMac(raw: string): string {
  return raw.trim().replace(/-/g, ':').toUpperCase()
}

/** LAN devices (by MAC) whose traffic skips the TUN entirely (`bypass_macs`). */
export default function DirectDevicesCard({ status }: { status: PollResult<ProxyStatus> }) {
  const clients = useResource<Client[]>('network:clients', api.clients)
  const [busy, setBusy] = useState<string | null>(null)
  const [draft, setDraft] = useState<string | null>(null)
  const [error, setError] = useState<string | undefined>()
  const s = status.data
  if (!s) return null

  const listed = s.bypass_macs
  const byMac = new Map((clients.data ?? []).map((c) => [c.mac.toUpperCase(), c]))
  const candidates = (clients.data ?? []).filter((c) => !listed.includes(c.mac.toUpperCase()))
  const nameOf = (mac: string) => {
    const c = byMac.get(mac)
    return (c && displayName(c)) ?? mac
  }

  async function save(key: string, next: string[]) {
    setBusy(key)
    try {
      status.mutate(await api.proxySettings({ bypass_macs: next }))
      return true
    } catch (e) {
      toastError(e, t('Failed to save the setting'))
      status.refresh()
      return false
    } finally {
      setBusy(null)
    }
  }

  async function add() {
    if (draft === null) return
    if (!MAC_RE.test(draft.trim())) {
      setError(t('Enter a MAC address such as AA:BB:CC:DD:EE:FF'))
      return
    }
    const mac = normalizeMac(draft)
    if (listed.includes(mac)) {
      setError(t('This device is already on the list'))
      return
    }
    setError(undefined)
    const name = nameOf(mac)
    const ok = await confirm({
      title: t('Send {name} past the proxy?', { name }),
      body: t('Everything this device sends skips mihomo and goes out the router’s normal route.'),
      kind: 'connection',
      details: [{ label: 'MAC', value: mac }],
      consequence: t('Its open connections through mihomo close; its apps reconnect directly.'),
      recovery: t('Remove it from this list to send it through the proxy again.'),
    })
    if (ok && (await save('add', [...listed, mac]))) setDraft(null)
  }

  async function remove(mac: string) {
    const name = nameOf(mac)
    const ok = await confirm({
      title: t('Send {name} through the proxy again?', { name }),
      kind: 'connection',
      details: [{ label: 'MAC', value: mac }],
      consequence: t('Its open direct connections drop; its apps reconnect through mihomo.'),
    })
    if (ok) await save(`del:${mac}`, listed.filter((m) => m !== mac))
  }

  return (
    <Card
      title={t('Devices without proxy')}
      action={
        s.tun_active && listed.length > 0 ? (
          <Chip tone={s.bypass_macs_active ? 'ok' : 'warn'}>{s.bypass_macs_active ? t('Active') : t('Not applied')}</Chip>
        ) : undefined
      }
    >
      <div className="space-y-3">
        <p className="text-meta text-ink2">
          {t('These devices skip mihomo entirely, IPv4 and IPv6, as if no proxy ran: for devices with their own proxy client (Surge, Shadowrocket, …). They are recognised by MAC address, so set their private Wi-Fi address to Fixed. DNS sent to the router is still answered through mihomo’s resolver.')}
        </p>
        {!s.tun_active && (
          <InlineStatus kind="info" live={false}>
            {t('Takes effect while the transparent proxy (TUN) is running; without it every device already goes direct.')}
          </InlineStatus>
        )}
        {listed.length > 0 && (
          <ul className="divide-y divide-line/6">
            {listed.map((mac) => {
              const c = byMac.get(mac)
              return (
                <li key={mac} className="flex items-center justify-between gap-2 py-2">
                  <div className="min-w-0">
                    <p className="truncate text-body font-medium text-ink">{(c && displayName(c)) ?? t('Not connected')}</p>
                    <p className="tnum font-mono text-meta text-ink2">
                      {c?.ip ? `${c.ip} · ${mac}` : mac}
                    </p>
                  </div>
                  <Button size="sm" variant="ghost" onClick={() => void remove(mac)} loading={busy === `del:${mac}`} disabled={busy !== null}>
                    {t('Remove')}
                  </Button>
                </li>
              )
            })}
          </ul>
        )}
        {draft !== null ? (
          <div className="space-y-2.5 rounded-ctl border border-line/8 p-3">
            {candidates.length > 0 && (
              <Field label={t('Pick a connected device')}>
                <Select
                  value=""
                  onChange={(e) => {
                    setDraft(e.target.value)
                    setError(undefined)
                  }}
                >
                  <option value="">—</option>
                  {candidates.map((c) => (
                    <option key={c.mac} value={c.mac}>
                      {displayName(c) ?? c.mac} {c.ip ? `(${c.ip})` : ''}
                    </option>
                  ))}
                </Select>
              </Field>
            )}
            <Field label="MAC" error={error}>
              <Input
                value={draft}
                placeholder="AA:BB:CC:DD:EE:FF"
                onChange={(e) => {
                  setDraft(e.target.value)
                  setError(undefined)
                }}
              />
            </Field>
            <div className="flex gap-2">
              <Button variant="primary" onClick={() => void add()} loading={busy === 'add'} disabled={busy !== null}>
                {t('Add')}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setDraft(null)
                  setError(undefined)
                }}
                disabled={busy !== null}
              >
                {t('Cancel')}
              </Button>
            </div>
          </div>
        ) : (
          <Button variant="outline" onClick={() => setDraft('')} disabled={busy !== null || listed.length >= 32}>
            {t('Add device')}
          </Button>
        )}
      </div>
    </Card>
  )
}
