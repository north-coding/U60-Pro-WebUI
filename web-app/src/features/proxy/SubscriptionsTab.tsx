import { useState } from 'react'
import { api } from '../../data/api'
import { usePoll } from '../../data/poll'
import { formatBytes } from '../../format'
import { ITrash } from '../../icons'
import type { ProxySubscription, ProxySubscriptions } from '../../types'
import { Button, Field, Input, Select, Toggle } from '../../ui/controls'
import { confirm, toast, toastError } from '../../ui/feedback'
import { Card, Chip, Empty, InlineStatus, Meter, Skeleton } from '../../ui/primitives'
import {
  ago,
  DEFAULT_SUBSCRIPTION_INTERVAL_HOURS,
  DEFAULT_SUBSCRIPTION_USE_CONFIG,
  expiry,
  INTERVAL_OPTIONS,
  intervalLabel,
  usagePct,
  usageTone,
  usedBytes,
  validateSubscription,
} from './proxyView'
import { runSubscriptionUpdateFlow, waitForProxyReady, type SubscriptionFlowOutcome } from './subscriptionFlow'
import { t } from '../../i18n'

type UpdateTarget = { id: string; name: string }

function confirmProxyStartAndUpdate(targets: UpdateTarget[]) {
  const targetLabel = targets.length === 1
    ? targets[0].name
    : t('{n} enabled subscriptions', { n: targets.length })
  return confirm({
    title: t('Start Mihomo and update?'),
    body: t('This starts Mihomo now and leaves it running after the update. It also enables Mihomo to start with the router.'),
    kind: 'connection',
    details: [{ label: t('Subscriptions'), value: targetLabel }],
    consequence: t('If transparent proxy is enabled, LAN traffic may route through Mihomo.'),
    recovery: t('Stop Mihomo in Overview or turn off transparent proxy in Settings.'),
    confirmLabel: targets.length === 1 ? t('Start & update') : t('Start & update all'),
  })
}

async function refreshSubscriptions(running: boolean, targets: UpdateTarget[], id?: string) {
  return runSubscriptionUpdateFlow({
    running,
    expectedIds: targets.map((target) => target.id),
    confirmStart: () => confirmProxyStartAndUpdate(targets),
    start: async () => {
      await api.proxyService('start')
    },
    waitUntilReady: () => waitForProxyReady(api.proxyGroups),
    refresh: () => api.proxySubscriptionUpdate(id),
  })
}

function reportSubscriptionRefresh(outcome: SubscriptionFlowOutcome, targets: UpdateTarget[], all: boolean) {
  switch (outcome.status) {
    case 'cancelled':
      return
    case 'start-failed':
      toastError(outcome.error, t('Failed to start the proxy'))
      return
    case 'not-ready':
      toast(t('Mihomo did not become ready. Subscriptions were not updated.'), 'err')
      return
    case 'readiness-failed':
      toastError(outcome.error, t('Could not confirm Mihomo readiness. Subscriptions were not updated.'))
      return
    case 'update-failed':
      toastError(outcome.error, all ? t('Failed to update subscriptions') : t('Failed to update the subscription'))
      return
    case 'updated': {
      const { summary } = outcome
      if (summary.failureCount === 0 && summary.successCount === targets.length && !summary.malformed) {
        toast(all ? t('Subscriptions updated') : t('{name} updated', { name: targets[0].name }))
        return
      }
      if (!all) {
        const result = summary.results[targets[0].id]
        toast(t('{name}: {error}', { name: targets[0].name, error: result?.error || t('update failed') }), 'err')
        return
      }
      toast(t('{updated} of {total} subscriptions updated; {failed} failed', {
        updated: summary.successCount,
        total: targets.length,
        failed: summary.failureCount,
      }), 'err')
    }
  }
}

export default function SubscriptionsTab() {
  const subs = usePoll<ProxySubscriptions>('proxy-subscriptions', api.proxySubscriptions, 15_000)
  const [updatingAll, setUpdatingAll] = useState(false)
  const [updatingSubscriptionId, setUpdatingSubscriptionId] = useState<string | null>(null)

  async function updateAll() {
    const targets = (subs.data?.subscriptions ?? []).filter((sub) => sub.enabled).map(({ id, name }) => ({ id, name }))
    if (!targets.length) return
    setUpdatingAll(true)
    try {
      const outcome = await refreshSubscriptions(!!subs.data?.running, targets)
      reportSubscriptionRefresh(outcome, targets, true)
    } finally {
      setUpdatingAll(false)
      subs.refresh()
    }
  }

  let list
  if (subs.status === 'loading') {
    list = <Skeleton className="h-24" />
  } else if (!subs.data) {
    list = (
      <InlineStatus kind="error" action={{ label: 'Retry', onClick: subs.refresh, loading: subs.refreshing }}>
        {subs.error ? t('Subscriptions could not be read: {error}', { error: subs.error }) : t('Subscriptions could not be read.')}
      </InlineStatus>
    )
  } else if (subs.data.subscriptions.length === 0) {
    list = <Empty title={t('No subscriptions yet')} body={t('Add your provider’s subscription link below to get nodes.')} />
  } else {
    list = (
      <div className="space-y-3">
        {!subs.data.running && (
          <InlineStatus kind="info" live={false}>
            {t('The proxy is stopped. Start Mihomo with an explicit update action to fetch enabled subscriptions.')}
          </InlineStatus>
        )}
        <ul className="divide-y divide-line/6">
          {subs.data.subscriptions.map((s) => (
            <SubscriptionRow
              key={s.id}
              sub={s}
              running={subs.data!.running}
              profileActive={subs.data!.subscriptions.some((x) => x.use_config)}
              updatesLocked={updatingAll || updatingSubscriptionId !== null}
              onUpdateBusyChange={(busy) => setUpdatingSubscriptionId(busy ? s.id : null)}
              onChanged={subs.refresh}
            />
          ))}
        </ul>
      </div>
    )
  }

  const canUpdateAll = subs.data?.subscriptions.some((s) => s.enabled) ?? false

  return (
    <>
      <Card
        title={t('Subscriptions')}
        action={
          <Button size="sm" variant="outline" onClick={() => void updateAll()} loading={updatingAll} disabled={!canUpdateAll || updatingAll || updatingSubscriptionId !== null}>
            {subs.data && !subs.data.running ? t('Start & update all') : t('Update all')}
          </Button>
        }
      >
        {list}
      </Card>
      <AddSubscription onAdded={subs.refresh} />
    </>
  )
}

function SubscriptionRow({
  sub,
  running,
  profileActive,
  updatesLocked,
  onUpdateBusyChange,
  onChanged,
}: {
  sub: ProxySubscription
  running: boolean
  profileActive: boolean
  updatesLocked: boolean
  onUpdateBusyChange: (busy: boolean) => void
  onChanged: () => void
}) {
  const [busy, setBusy] = useState<'update' | 'toggle' | 'delete' | 'config' | null>(null)
  const [editing, setEditing] = useState(false)
  const pct = usagePct(sub.usage)
  const used = usedBytes(sub.usage)
  const exp = expiry(sub.usage)
  const updated = ago(sub.updated_at)

  async function update() {
    setBusy('update')
    onUpdateBusyChange(true)
    try {
      const targets = [{ id: sub.id, name: sub.name }]
      const outcome = await refreshSubscriptions(running, targets, sub.id)
      reportSubscriptionRefresh(outcome, targets, false)
    } finally {
      setBusy(null)
      onUpdateBusyChange(false)
      onChanged()
    }
  }

  async function toggle(enabled: boolean) {
    setBusy('toggle')
    try {
      await api.proxySubscriptionEdit({ id: sub.id, enabled })
    } catch (e) {
      toastError(e, t('Failed to change the subscription'))
    } finally {
      setBusy(null)
      onChanged()
    }
  }

  async function setUseConfig(on: boolean) {
    setBusy('config')
    try {
      await api.proxySubscriptionEdit({ id: sub.id, use_config: on })
      toast(on ? t('Now using the rules and groups of {name}', { name: sub.name }) : t('Switched to the managed rules'))
    } catch (e) {
      toastError(e, t('Failed to change the subscription'))
    } finally {
      setBusy(null)
      onChanged()
    }
  }

  async function remove() {
    const ok = await confirm({
      title: t('Delete {name}?', { name: sub.name }),
      body: t('Its nodes are removed from the proxy. The link is deleted from the router.'),
      kind: 'danger',
      confirmLabel: t('Delete'),
      details: [{ label: t('Subscription link'), value: sub.url_masked }],
    })
    if (!ok) return
    setBusy('delete')
    try {
      await api.proxySubscriptionDelete(sub.id)
      toast(t('{name} deleted', { name: sub.name }))
    } catch (e) {
      toastError(e, t('Failed to delete the subscription'))
    } finally {
      setBusy(null)
      onChanged()
    }
  }

  return (
    <li className="space-y-2 py-3 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-semibold text-ink">{sub.name}</span>
            {!sub.enabled && <Chip>{t('Off')}</Chip>}
            {sub.use_config && <Chip tone="ok">{t('Rules in use')}</Chip>}
            {!sub.use_config && profileActive && sub.enabled && <Chip>{t('Not in use')}</Chip>}
            {sub.node_count !== undefined && <Chip tone="accent">{t('{n} nodes', { n: sub.node_count })}</Chip>}
            {sub.groups !== undefined && <Chip>{t('{n} groups', { n: sub.groups })}</Chip>}
            <Chip>{intervalLabel(sub.interval_hours)}</Chip>
          </div>
          <p className="mt-0.5 break-all font-mono text-caption text-ink3">{sub.url_masked}</p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-1">
          {sub.use_config ? (
              <Button size="sm" variant="ghost" onClick={() => void setUseConfig(false)} loading={busy === 'config'} disabled={!!busy || updatesLocked}>
              {t('Use managed rules')}
            </Button>
          ) : (
            sub.enabled && (
              <Button size="sm" variant="ghost" onClick={() => void setUseConfig(true)} loading={busy === 'config'} disabled={!!busy || updatesLocked}>
                {t('Use its rules')}
              </Button>
            )
          )}
          <Toggle
            checked={sub.enabled}
            onChange={(v) => void toggle(v)}
            disabled={!!busy || updatesLocked}
            label={t('Use {name}', { name: sub.name })}
          />
          <Button size="sm" variant="ghost" onClick={() => setEditing((v) => !v)} disabled={!!busy || updatesLocked}>
            {editing ? t('Close') : t('Edit')}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void update()}
            loading={busy === 'update'}
            disabled={!!busy || updatesLocked || !sub.enabled || (!sub.use_config && profileActive)}
          >
            {!running ? t('Start & update') : t('Update')}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => void remove()} loading={busy === 'delete'} disabled={!!busy || updatesLocked} aria-label={t('Delete {name}', { name: sub.name })}>
            <ITrash size={15} />
          </Button>
        </div>
      </div>

      {(pct !== undefined || used !== undefined || exp) && (
        <div className="space-y-1">
          {pct !== undefined && <Meter pct={pct} tone={usageTone(pct)} />}
          <div className="flex flex-wrap items-center justify-between gap-2 text-meta text-ink2">
            <span className="tnum font-mono">
              {sub.usage?.total
                ? t('{used} of {total}', { used: formatBytes(used), total: formatBytes(sub.usage.total) })
                : formatBytes(used)}
              {pct !== undefined ? ` (${pct}%)` : ''}
            </span>
            {exp && (
              <Chip tone={exp.tone}>
                {exp.daysLeft < 0
                  ? t('Expired {date}', { date: exp.date })
                  : t('Expires {date} · {days} d left', { date: exp.date, days: exp.daysLeft })}
              </Chip>
            )}
          </div>
        </div>
      )}

      <p className="text-caption text-ink3">{updated ? t('Updated {when}', { when: updated }) : running && sub.enabled ? t('Not fetched yet') : ''}</p>
      {sub.error && <InlineStatus kind="error">{sub.error}</InlineStatus>}
      {editing && (
        <EditSubscription
          sub={sub}
          onDone={() => {
            setEditing(false)
            onChanged()
          }}
        />
      )}
    </li>
  )
}

function EditSubscription({ sub, onDone }: { sub: ProxySubscription; onDone: () => void }) {
  const [name, setName] = useState(sub.name)
  const [url, setUrl] = useState('')
  const [intervalHours, setIntervalHours] = useState(sub.interval_hours)
  const [errors, setErrors] = useState<{ name?: string; url?: string }>({})
  const [busy, setBusy] = useState(false)

  async function save() {
    const v = validateSubscription(name, url || 'https://unchanged')
    if (v.name || (url && v.url)) {
      setErrors({ name: v.name, url: url ? v.url : undefined })
      return
    }
    setBusy(true)
    try {
      await api.proxySubscriptionEdit({
        id: sub.id,
        name: name.trim(),
        interval_hours: intervalHours,
        ...(url.trim() ? { url: url.trim() } : {}),
      })
      toast(t('{name} saved', { name: name.trim() }))
      onDone()
    } catch (e) {
      toastError(e, t('Failed to save the subscription'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-3 rounded-ctl border border-line/10 p-3 sm:grid-cols-2">
      <Field label={t('Name')} error={errors.name}>
        <Input value={name} maxLength={32} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label={t('Update interval')}>
        <Select value={intervalHours} onChange={(e) => setIntervalHours(Number(e.target.value))}>
          {INTERVAL_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </Select>
      </Field>
      <div className="sm:col-span-2">
        <Field label={t('New link')} hint={t('Leave empty to keep the current link.')} error={errors.url}>
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://…"
            autoComplete="off"
            spellCheck={false}
            inputMode="url"
          />
        </Field>
      </div>
      <div className="flex gap-2 sm:col-span-2">
        <Button variant="primary" onClick={() => void save()} loading={busy}>
          {t('Save')}
        </Button>
        <Button variant="ghost" onClick={onDone} disabled={busy}>
          {t('Cancel')}
        </Button>
      </div>
    </div>
  )
}

function AddSubscription({ onAdded }: { onAdded: () => void }) {
  const [useConfig, setUseConfig] = useState(DEFAULT_SUBSCRIPTION_USE_CONFIG)
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [intervalHours, setIntervalHours] = useState(DEFAULT_SUBSCRIPTION_INTERVAL_HOURS)
  const [errors, setErrors] = useState<{ name?: string; url?: string }>({})
  const [busy, setBusy] = useState(false)

  async function add() {
    const v = validateSubscription(name, url)
    setErrors(v)
    if (v.name || v.url) return
    setBusy(true)
    try {
      const r = await api.proxySubscriptionAdd({
        name: name.trim(),
        url: url.trim(),
        interval_hours: intervalHours,
        use_config: useConfig,
      })
      if (r.warning) toast(t('{name} added as a node source: it has no groups or rules', { name: name.trim() }), 'err')
      else toast(t('{name} added', { name: name.trim() }))
      setName('')
      setUrl('')
      onAdded()
    } catch (e) {
      toastError(e, t('Failed to add the subscription'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title={t('Add subscription')}>
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault()
          void add()
        }}
      >
        <Field label={t('Name')} error={errors.name}>
          <Input value={name} maxLength={32} placeholder={t('My provider')} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={t('Update interval')}>
          <Select value={intervalHours} onChange={(e) => setIntervalHours(Number(e.target.value))}>
            {INTERVAL_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </Field>
        <div className="sm:col-span-2">
          <Field
            label={t('Subscription link')}
            hint={t('Clash/mihomo or base64 (v2ray) format. Stored on the router readable by root only, and shown masked.')}
            error={errors.url}
          >
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://…"
              autoComplete="off"
              spellCheck={false}
              inputMode="url"
            />
          </Field>
        </div>
        <div className="flex items-start justify-between gap-4 sm:col-span-2">
          <div>
            <p className="text-body font-medium text-ink">{t('Advanced: use the provider’s complete configuration')}</p>
            <p className="mt-0.5 text-meta text-ink2">
              {t('Recommended: import only the provider’s nodes. Managed Rule mode uses the bypass_cn preset: mainland China traffic is DIRECT, foreign traffic is PROXY.')}
            </p>
          </div>
          <Toggle checked={useConfig} onChange={setUseConfig} label={t('Import the complete provider configuration')} />
        </div>
        <div className="sm:col-span-2">
          <Button type="submit" variant="primary" loading={busy}>
            {t('Add subscription')}
          </Button>
        </div>
      </form>
    </Card>
  )
}
