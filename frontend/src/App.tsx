import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import Ring from './Ring'
import Dropdown from './Dropdown'
import { config, main } from '../wailsjs/go/models'
import {
  GetConfig, SaveConfig, TokenStatus, CertDetails, ListRoles, RenewToken,
  Authenticate, CancelAuth, ExportActiveProfile, ImportProfile, Version,
} from '../wailsjs/go/main/App'
import { EventsOn, BrowserOpenURL } from '../wailsjs/runtime'

type LogLine = { text: string; tone: 'info' | 'ok' | 'fail' }

function applyTheme(theme: string) {
  const root = document.documentElement
  const resolved =
    theme === 'light' ? 'light'
    : theme === 'dark' ? 'dark'
    : window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  root.dataset.theme = resolved
}

function ringState(remaining: number, valid: boolean): 'ok' | 'warn' | 'danger' | 'idle' {
  if (!valid) return 'idle'
  if (remaining < 30 * 60) return 'danger'
  if (remaining < 2 * 60 * 60) return 'warn'
  return 'ok'
}

function fmt(secs: number): string {
  if (secs <= 0) return 'expired'
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

export default function App() {
  const [cfg, setCfg] = useState<config.Config | null>(null)
  const [status, setStatus] = useState<main.Status | null>(null)
  const [cert, setCert] = useState<main.CertDetails | null>(null)
  const [ttl, setTtl] = useState(0)
  const [roles, setRoles] = useState<string[]>([])
  const [log, setLog] = useState<LogLine[]>([])
  const [busy, setBusy] = useState(false)
  const [authing, setAuthing] = useState(false)
  const [authUrl, setAuthUrl] = useState('')
  const [force, setForce] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [version, setVersion] = useState('')
  const logEnd = useRef<HTMLDivElement>(null)

  const profile = cfg ? cfg.profiles[cfg.active_profile] : null

  function refreshStatus() {
    TokenStatus().then((s) => { setStatus(s); setTtl(s.ttlSeconds) })
    CertDetails().then(setCert)
  }

  useEffect(() => {
    GetConfig().then((c) => { setCfg(c); applyTheme(c.theme) })
    Version().then(setVersion)
    refreshStatus()
    const offStep = EventsOn('auth:step', (e: { step: string; ok: boolean; detail: string }) => {
      setLog((l) => {
        const next = [...l, { text: `${e.ok ? '✓' : '✗'} ${e.step}`, tone: e.ok ? 'ok' : 'fail' } as LogLine]
        if (e.detail) next.push({ text: '   ' + e.detail, tone: 'info' })
        return next
      })
    })
    const offUrl = EventsOn('auth:url', (url: string) => {
      setAuthUrl(url)
      setLog((l) => [...l, { text: 'Waiting for browser login…', tone: 'info' }])
      BrowserOpenURL(url)
    })
    const offDone = EventsOn('auth:done', (e: { ok: boolean; message: string }) => {
      setLog((l) => [...l, { text: e.ok ? '✓ Done — key signed and loaded into ssh-agent.' : '✗ ' + e.message, tone: e.ok ? 'ok' : 'fail' }])
      setBusy(false); setAuthing(false); setAuthUrl('')
      refreshStatus()
    })
    return () => { offStep(); offUrl(); offDone() }
  }, [])

  useEffect(() => {
    if (!status?.valid) return
    const id = setInterval(() => setTtl((t) => Math.max(0, t - 1)), 1000)
    return () => clearInterval(id)
  }, [status])

  useEffect(() => { logEnd.current?.scrollIntoView({ behavior: 'smooth' }) }, [log])

  function updateCfg(next: config.Config) { setCfg(next) }

  function patchProfile(patch: Partial<config.Profile>) {
    if (!cfg || !profile) return
    const next = config.Config.createFrom(cfg)
    next.profiles[cfg.active_profile] = config.Profile.createFrom({ ...profile, ...patch })
    updateCfg(next)
  }

  async function persist() { if (cfg) await SaveConfig(cfg) }

  async function authenticate() {
    if (!cfg) return
    setLog([]); setBusy(true); setAuthing(true); setAuthUrl('')
    await persist()
    await Authenticate(force)
  }

  async function cancelAuth() {
    await CancelAuth()
    setAuthing(false); setBusy(false); setAuthUrl('')
  }

  async function refreshRoles() {
    await persist()
    setRoles(await ListRoles())
  }

  async function renew() {
    const r = await RenewToken()
    setLog((l) => [...l, { text: (r.ok ? '✓ ' : '✗ ') + r.message, tone: r.ok ? 'ok' : 'fail' }])
    refreshStatus()
  }

  function cycleTheme() {
    if (!cfg) return
    const order = ['system', 'dark', 'light']
    const nextTheme = order[(order.indexOf(cfg.theme) + 1) % order.length]
    const next = config.Config.createFrom({ ...cfg, theme: nextTheme })
    updateCfg(next); applyTheme(nextTheme); SaveConfig(next)
  }

  const valid = !!status?.valid
  const total = status?.creationTtlSeconds || 1
  const frac = valid ? ttl / total : 0
  const rstate = ringState(ttl, valid)

  return (
    <div className="h-full flex flex-col text-sm t-fg">
      <header className="flex items-center justify-between px-5 pt-5 pb-2">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-accent to-accent-2 flex items-center justify-center text-white font-bold">V</div>
          <div>
            <div className="font-semibold leading-none">VaultSign</div>
            <div className="text-[10px] t-faint">v{version}</div>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={cycleTheme} title={`Theme: ${cfg?.theme ?? 'system'}`} className="t-muted hover:t-fg transition-colors text-base px-2 py-1 rounded-md hover:bg-white/5">
            {cfg?.theme === 'light' ? '☀' : cfg?.theme === 'dark' ? '☾' : '◐'}
          </button>
          <button onClick={() => setSettingsOpen((o) => !o)} className="t-muted hover:t-fg transition-colors text-xs px-2 py-1 rounded-md hover:bg-white/5">
            {settingsOpen ? 'Done' : 'Settings'}
          </button>
        </div>
      </header>

      <main className="flex-1 overflow-y-auto px-5 pb-4 space-y-4">
        {authing ? (
          <AuthScreen url={authUrl} log={log} logEnd={logEnd} onReopen={() => authUrl && BrowserOpenURL(authUrl)} onCancel={cancelAuth} />
        ) : !settingsOpen ? (
          <>
            <section className="flex flex-col items-center pt-2">
              <Ring fraction={frac} label={valid ? fmt(ttl) : '—'} caption={valid ? 'remaining' : 'no session'} state={rstate} />
              <div className="mt-3 text-center">
                <div className="t-fg">{valid ? status?.displayName : 'Not authenticated'}</div>
                {valid && (
                  <div className="flex flex-wrap gap-1.5 justify-center mt-2">
                    {status?.policies?.map((p) => (
                      <span key={p} className="text-[11px] px-2 py-0.5 rounded-full bg-card-hi border border-border t-muted">{p}</span>
                    ))}
                  </div>
                )}
              </div>
            </section>

            {cert?.valid && (
              <CertCard cert={cert} />
            )}

            <section className="space-y-2">
              <button
                onClick={authenticate}
                disabled={busy}
                className="w-full py-3 rounded-xl font-medium text-white bg-gradient-to-r from-accent to-accent-2 shadow-lg shadow-accent/20 hover:brightness-110 active:scale-[.99] transition disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {busy && <span className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin-slow" />}
                {busy ? 'Authenticating…' : valid ? 'Re-sign SSH key' : 'Authenticate'}
              </button>
              <div className="flex items-center justify-between text-xs t-muted px-1">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} className="accent-accent" />
                  Force re-login
                </label>
                {valid && status?.renewable && (
                  <button onClick={renew} className="hover:t-fg transition-colors">Renew token</button>
                )}
              </div>
            </section>

            {log.length > 0 && (
              <section className="rounded-xl bg-bg-soft border border-border p-3 font-mono text-[11.5px] leading-relaxed max-h-52 overflow-y-auto">
                {log.map((l, i) => (
                  <div key={i} className={'fade-up ' + (l.tone === 'ok' ? 'text-ok' : l.tone === 'fail' ? 'text-danger' : 't-muted')}>
                    {l.text}
                  </div>
                ))}
                <div ref={logEnd} />
              </section>
            )}
          </>
        ) : (
          <Settings
            cfg={cfg}
            profile={profile}
            roles={roles}
            onCfg={updateCfg}
            onPatch={patchProfile}
            onRefreshRoles={refreshRoles}
            onSave={persist}
            onExport={async () => { const r = await ExportActiveProfile(); if (!r.ok && r.message !== 'cancelled') alert(r.message) }}
            onImport={async () => { const r = await ImportProfile(); if (r.ok) { const c = await GetConfig(); setCfg(c) } }}
          />
        )}
      </main>
    </div>
  )
}

function CertCard({ cert }: { cert: main.CertDetails }) {
  const until = cert.validBefore ? new Date(cert.validBefore).toLocaleString() : '—'
  return (
    <section className="rounded-xl bg-card border border-border p-4 space-y-2 fade-up">
      <div className="text-[11px] uppercase tracking-widest t-faint font-semibold">Certificate</div>
      <Row k="Principals" v={cert.principals?.join(', ') || '—'} />
      <Row k="Valid until" v={until} />
      <Row k="Serial" v={cert.serial} />
    </section>
  )
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3 text-xs">
      <span className="t-faint shrink-0">{k}</span>
      <span className="t-muted text-right font-mono break-all">{v}</span>
    </div>
  )
}

function AuthScreen({ url, log, logEnd, onReopen, onCancel }: {
  url: string
  log: LogLine[]
  logEnd: RefObject<HTMLDivElement>
  onReopen: () => void
  onCancel: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center pt-6 space-y-5 fade-up">
      <div className="relative w-24 h-24">
        <div className="absolute inset-0 rounded-full bg-gradient-to-br from-accent to-accent-2 opacity-20 blur-xl pulse-ring" />
        <div className="absolute inset-0 rounded-full border-4 border-white/10" />
        <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-accent border-r-accent-2 animate-spin-slow" />
        <div className="absolute inset-0 flex items-center justify-center text-2xl">🔐</div>
      </div>
      <div className="text-center">
        <div className="text-lg font-semibold">Authenticating…</div>
        <div className="t-faint text-xs mt-1 max-w-[18rem]">
          {url ? 'Complete the login in your browser. This window updates automatically when you’re done.' : 'Preparing secure login…'}
        </div>
      </div>
      {url && (
        <div className="w-full rounded-xl bg-bg-soft border border-border p-3 space-y-2">
          <div className="text-[11px] t-faint uppercase tracking-widest">OIDC login URL</div>
          <div className="font-mono text-[11px] t-muted truncate">{url}</div>
          <button onClick={onReopen} className="w-full py-2 rounded-lg bg-card-hi border border-border hover:brightness-110 transition text-xs">Reopen in browser</button>
        </div>
      )}
      {log.length > 0 && (
        <div className="w-full rounded-xl bg-bg-soft border border-border p-3 font-mono text-[11.5px] leading-relaxed max-h-40 overflow-y-auto">
          {log.map((l, i) => (
            <div key={i} className={'fade-up ' + (l.tone === 'ok' ? 'text-ok' : l.tone === 'fail' ? 'text-danger' : 't-muted')}>{l.text}</div>
          ))}
          <div ref={logEnd} />
        </div>
      )}
      <button onClick={onCancel} className="t-faint hover:text-danger transition-colors text-xs px-3 py-1.5">Cancel</button>
    </div>
  )
}

function Settings({ cfg, profile, roles, onCfg, onPatch, onRefreshRoles, onSave, onExport, onImport }: {
  cfg: config.Config | null
  profile: config.Profile | null
  roles: string[]
  onCfg: (c: config.Config) => void
  onPatch: (p: Partial<config.Profile>) => void
  onRefreshRoles: () => void
  onSave: () => Promise<void>
  onExport: () => void
  onImport: () => void
}) {
  const [saved, setSaved] = useState(false)
  const [adding, setAdding] = useState(false)
  const [newName, setNewName] = useState('')
  if (!cfg || !profile) return null
  const names = Object.keys(cfg.profiles)

  function selectProfile(name: string) {
    if (!cfg) return
    onCfg(config.Config.createFrom({ ...cfg, active_profile: name }))
  }
  function addProfile() {
    const name = newName.trim()
    if (!cfg || !name || cfg.profiles[name]) return
    const next = config.Config.createFrom(cfg)
    next.profiles[name] = config.Profile.createFrom({
      vault_addr: 'https://vault.example.com:8200/', ssh_key_path: '~/.ssh/id_ed25519',
      role: '', ssh_signer_path: 'ssh-client-signer', oidc_mount: 'oidc',
      show_tray: true, autostart: true, expiry_warn_minutes: 15,
    })
    next.active_profile = name
    onCfg(next); SaveConfig(next); setAdding(false); setNewName('')
  }
  function deleteProfile() {
    if (!cfg || names.length <= 1) return
    const next = config.Config.createFrom(cfg)
    delete next.profiles[cfg.active_profile]
    next.active_profile = Object.keys(next.profiles)[0]
    onCfg(next); SaveConfig(next)
  }

  return (
    <div className="space-y-4 pt-1">
      <Card title="Profile">
        {!adding ? (
          <div className="flex gap-2">
            <Dropdown value={cfg.active_profile} options={names} onChange={selectProfile} />
            <IconBtn label="+" title="Add profile" onClick={() => setAdding(true)} />
            <IconBtn label="🗑" title="Delete profile" onClick={deleteProfile} disabled={names.length <= 1} />
          </div>
        ) : (
          <div className="flex gap-2">
            <input autoFocus value={newName} onChange={(e) => setNewName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addProfile()}
              placeholder="new profile name"
              className="flex-1 bg-card-hi border border-border rounded-lg px-3 py-2 outline-none focus:border-accent transition" />
            <IconBtn label="✓" title="Create" onClick={addProfile} />
            <IconBtn label="✕" title="Cancel" onClick={() => { setAdding(false); setNewName('') }} />
          </div>
        )}
        <div className="flex gap-2">
          <button onClick={onExport} className="flex-1 py-1.5 rounded-lg bg-card-hi border border-border hover:brightness-110 transition text-xs">Export</button>
          <button onClick={onImport} className="flex-1 py-1.5 rounded-lg bg-card-hi border border-border hover:brightness-110 transition text-xs">Import</button>
        </div>
      </Card>

      <Card title="Connection">
        <Field label="Server address" value={profile.vault_addr} onChange={(v) => onPatch({ vault_addr: v })} />
        <Field label="SSH key path" value={profile.ssh_key_path} onChange={(v) => onPatch({ ssh_key_path: v })} />
        <Field label="OIDC mount" value={profile.oidc_mount} onChange={(v) => onPatch({ oidc_mount: v })} />
        <Field label="Signer mount" value={profile.ssh_signer_path} onChange={(v) => onPatch({ ssh_signer_path: v })} />
      </Card>

      <Card title="Role">
        <div className="flex gap-2">
          <input list="roles" value={profile.role} onChange={(e) => onPatch({ role: e.target.value })} placeholder="type or pick a role"
            className="flex-1 bg-card-hi border border-border rounded-lg px-3 py-2 outline-none focus:border-accent transition" />
          <datalist id="roles">{roles.map((r) => <option key={r} value={r} />)}</datalist>
          <IconBtn label="↻" title="Refresh roles from Vault" onClick={onRefreshRoles} />
        </div>
        {roles.length > 0 && <div className="text-[11px] t-faint mt-1.5">{roles.length} role(s) loaded</div>}
      </Card>

      <Card title="Behavior">
        <Toggle label="Show tray icon" checked={profile.show_tray} onChange={(v) => onPatch({ show_tray: v })} />
        <Toggle label="Start on login" checked={profile.autostart} onChange={(v) => onPatch({ autostart: v })} />
      </Card>

      <button onClick={() => { onSave(); setSaved(true); setTimeout(() => setSaved(false), 1500) }}
        className="w-full py-2.5 rounded-xl bg-card-hi border border-border hover:brightness-110 transition font-medium">
        {saved ? 'Saved ✓' : 'Save settings'}
      </button>
    </div>
  )
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl bg-card border border-border p-4 space-y-3">
      <div className="text-[11px] uppercase tracking-widest t-faint font-semibold">{title}</div>
      {children}
    </div>
  )
}

function Field({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="block">
      <span className="text-xs t-faint">{label}</span>
      <input value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full mt-1 bg-card-hi border border-border rounded-lg px-3 py-2 outline-none focus:border-accent transition font-mono text-[12.5px]" />
    </label>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center justify-between cursor-pointer text-sm">
      <span className="t-muted">{label}</span>
      <span onClick={() => onChange(!checked)}
        className={'relative w-10 h-5 rounded-full transition ' + (checked ? 'bg-accent' : 'bg-card-hi border border-border')}>
        <span className={'absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ' + (checked ? 'left-5' : 'left-0.5')} />
      </span>
    </label>
  )
}

function IconBtn({ label, title, onClick, disabled }: { label: string; title: string; onClick: () => void; disabled?: boolean }) {
  return (
    <button title={title} onClick={onClick} disabled={disabled}
      className="px-3 rounded-lg bg-card-hi border border-border hover:brightness-110 transition text-xs disabled:opacity-40 disabled:cursor-not-allowed">
      {label}
    </button>
  )
}
