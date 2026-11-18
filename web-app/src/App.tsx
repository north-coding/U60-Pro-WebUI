import { lazy, useEffect, useState } from 'react'
import { AUTH_EXPIRED_EVENT, ApiError, clearToken, hasToken } from './data/client'
import { api } from './data/api'
import { clearPollCache } from './data/poll'
import { HomeProvider } from './app/HomeContext'
import Login from './app/Login'
import Shell, { type Group } from './app/Shell'
import {
  agentModeFromCapabilities,
  isLegacyFullAgentProbe,
  maySubmitCredentials,
  secureManagementContext,
  type AgentMode,
} from './app/agentMode'
import { useTheme } from './app/theme'
import { ConfirmHost, Toaster } from './ui/feedback'
import { Mark } from './ui/Mark'
import { InlineStatus, Spinner } from './ui/primitives'
import { t } from './i18n'

const HomePage = lazy(() => import('./features/home/HomePage'))
const SignalGroup = lazy(() => import('./features/signal/SignalGroup'))
const NetworkGroup = lazy(() => import('./features/network/NetworkGroup'))
const ModemGroup = lazy(() => import('./features/modem/ModemGroup'))
const ProxyGroup = lazy(() => import('./features/proxy/ProxyGroup'))
const SystemGroup = lazy(() => import('./features/system/SystemGroup'))

export default function App() {
  const secureContext = secureManagementContext(window.location)
  const [authed, setAuthed] = useState(false)
  const [group, setGroup] = useState<Group>('home')
  const [mode, setMode] = useState<AgentMode | 'checking' | 'insecure' | 'unavailable'>('checking')
  const [connectionError, setConnectionError] = useState('')
  const { theme, toggle } = useTheme()

  useEffect(() => {
    let active = true
    api.proxyCapabilities().then((capabilities) => {
      if (!active) return
      const agentMode = agentModeFromCapabilities(capabilities)
      if (!agentMode) {
        setConnectionError(t('The connected Agent did not report a supported management mode.'))
        setMode('unavailable')
        return
      }
      if (agentMode === 'proxy_only') setGroup('proxy')
      if (!maySubmitCredentials(agentMode, secureContext)) {
        clearToken()
        setAuthed(false)
        setMode('insecure')
        return
      }
      setAuthed(hasToken())
      setMode(agentMode)
    }).catch((error: unknown) => {
      if (!active) return
      if (isLegacyFullAgentProbe(error instanceof ApiError ? error.status : undefined)) {
        setAuthed(hasToken())
        setMode('full')
        return
      }
      setConnectionError(error instanceof Error ? error.message : t('Could not reach the Agent.'))
      setMode('unavailable')
    })
    return () => { active = false }
  }, [secureContext])

  useEffect(() => {
    const onAuthExpired = () => {
      clearPollCache()
      setAuthed(false)
    }
    window.addEventListener(AUTH_EXPIRED_EVENT, onAuthExpired)
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, onAuthExpired)
  }, [])

  if (mode === 'insecure') {
    return <AccessGate title={t('Secure management is unavailable')} message={t('This dashboard is using plain HTTP from a remote device. Passwords and session tokens could be exposed, so sign-in is disabled until HTTPS is configured for the management API.')} />
  }
  if (mode === 'unavailable') {
    return <AccessGate title={t('Agent connection unavailable')} message={connectionError || t('Could not reach the proxy-management Agent.')} />
  }
  if (mode === 'checking') {
    return <AccessGate title={t('Checking Agent')} message={t('Checking the management connection before requesting credentials.')} loading />
  }

  const proxyOnly = mode === 'proxy_only'
  const activeGroup = proxyOnly ? 'proxy' : group
  const logout = () => {
    clearToken()
    clearPollCache()
    setAuthed(false)
  }

  if (!authed) {
    return (
      <>
        <Login proxyOnly={proxyOnly} onAuthed={() => setAuthed(true)} />
        <Toaster />
      </>
    )
  }

  return (
    <>
      {proxyOnly ? (
        <Shell group="proxy" proxyOnly onLogout={logout} onNavigate={setGroup} theme={theme} onToggleTheme={toggle}>
          <ProxyGroup />
        </Shell>
      ) : (
        <HomeProvider fast={activeGroup === 'home' || activeGroup === 'signal'}>
          <Shell group={activeGroup} onNavigate={setGroup} theme={theme} onToggleTheme={toggle}>
            {activeGroup === 'home' && <HomePage />}
            {activeGroup === 'signal' && <SignalGroup />}
            {activeGroup === 'network' && <NetworkGroup />}
            {activeGroup === 'modem' && <ModemGroup />}
            {activeGroup === 'proxy' && <ProxyGroup />}
            {activeGroup === 'system' && <SystemGroup onLogout={logout} />}
          </Shell>
        </HomeProvider>
      )}
      <Toaster />
      <ConfirmHost />
    </>
  )
}

function AccessGate({ title, message, loading = false }: { title: string; message: string; loading?: boolean }) {
  return (
    <main className="flex min-h-full items-center justify-center bg-bg p-6">
      <section className="w-full max-w-md rounded-panel border border-line/8 bg-surface p-5">
        <div className="mb-4 flex items-center gap-3">
          {loading ? <Spinner size={22} /> : <Mark size={24} className="text-ink" />}
          <h1 className="font-display text-lg font-semibold text-ink">{title}</h1>
        </div>
        <InlineStatus kind={loading ? 'info' : 'error'}>{message}</InlineStatus>
      </section>
    </main>
  )
}
