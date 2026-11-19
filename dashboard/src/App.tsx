/* The AI asset register: catalogue, registration and audit trail.
 *
 * WHAT THIS SCREEN IS FOR, in one line: answering "what AI assets do we have,
 * who owns them, and did a human sign them off?" — a question most platform
 * teams running agents today cannot answer, and the reason the catalogue
 * exists at all.
 *
 * WHAT IT MUST NOT IMPLY. A table of APPROVED rows looks like a list of what is
 * allowed to run. It is not. The Gateway does not consult the Registry, so
 * approval here gates nothing — Cedar decides reachability. The caveat banner is
 * not decoration: it is the one place a viewer could reasonably draw the wrong
 * conclusion, so the correction sits on screen rather than depending on the
 * reader already knowing it.
 *
 * THREE PANELS, AND WHY EACH IS A DIFFERENT KIND OF THING
 *
 *   the catalogue     what we have, and who signed it off      (reads the Registry)
 *   register          propose an asset, scanned before publish  (writes, gated by
 *                                                                a real guardrail)
 *   the audit trail   what actually happened at call time       (reads CloudWatch)
 *
 * They are separated on screen because they answer separate questions and only
 * ONE of them describes enforcement. The audit trail is the only panel showing a
 * control that stopped something, and it is labelled that way — a viewer should
 * come away able to say which of the three gates anything.
 *
 * Still deliberately one page and no router. Panels collapse rather than
 * navigate: a URL that can be wrong is one more thing to break live, and the
 * previous build's deep-link bug (see vite.config.ts) is the reason for the
 * caution.
 */

import { useEffect, useState } from 'react'
import type { AppConfig } from './config'
import { loadConfig } from './config'
import { signIn, type Session } from './auth'
import {
  ApiError,
  fetchDecisions,
  fetchSummary,
  registerAsset,
  setStatus,
  type AssetRecord,
  type Decisions,
  type Registered,
  type Summary,
} from './api'

/* Status -> how it reads. A reviewer should see what needs them at a glance,
 * which is why PENDING_APPROVAL is the only one that draws the eye. */
const STATUS_STYLE: Record<string, { bg: string; fg: string; label: string }> = {
  APPROVED: { bg: '#E6FFFA', fg: '#234E52', label: 'Approved' },
  PENDING_APPROVAL: { bg: '#FEF3D7', fg: '#744210', label: 'Awaiting review' },
  DRAFT: { bg: '#EDF2F7', fg: '#4A5568', label: 'Draft' },
  REJECTED: { bg: '#FFF5F5', fg: '#742A2A', label: 'Rejected' },
  DEPRECATED: { bg: '#EDF2F7', fg: '#4A5568', label: 'Deprecated' },
  CREATING: { bg: '#EDF2F7', fg: '#4A5568', label: 'Creating…' },
  UPDATING: { bg: '#EDF2F7', fg: '#4A5568', label: 'Updating…' },
  CREATE_FAILED: { bg: '#FFF5F5', fg: '#742A2A', label: 'Failed' },
}

/* Minutes -> something readable. Needed once the window went past a day: the
 * old `${m / 60} h` rendered 15 days as "360 h". */
function windowLabel(minutes: number): string {
  if (minutes < 60) return `${minutes} min`
  if (minutes < 1440) return `${minutes / 60} h`
  const days = minutes / 1440
  return days === 1 ? '1 day' : `${days} days`
}

export default function App() {
  const [cfg, setCfg] = useState<AppConfig | null>(null)
  const [fatal, setFatal] = useState('')
  const [session, setSession] = useState<Session | null>(null)

  useEffect(() => {
    loadConfig().then(setCfg).catch((e) => setFatal(String(e.message ?? e)))
  }, [])

  if (fatal) return <Fatal message={fatal} />
  if (!cfg) return <Centred>Loading…</Centred>
  if (!session) return <Login cfg={cfg} onSignIn={setSession} />
  return <Register cfg={cfg} session={session} onSignOut={() => setSession(null)} />
}

/* -------------------------------------------------------------------- login */

function Login({
  cfg,
  onSignIn,
}: {
  cfg: AppConfig
  onSignIn: (s: Session) => void
}) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      onSignIn(await signIn(cfg, email, password))
    } catch (err) {
      setError(String((err as Error).message ?? err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Centred>
      <form onSubmit={submit} style={{ width: 340 }}>
        <h1 style={{ ...S.h1, fontSize: 22, marginBottom: 4 }}>AI Asset Register</h1>
        <p style={{ ...S.dim, marginTop: 0, marginBottom: 22 }}>
          {cfg.platformName} · sign in with your platform account
        </p>
        <input
          style={S.input}
          type="email"
          placeholder="you@company.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoFocus
          required
        />
        <input
          style={S.input}
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button style={S.primary} disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        {error && <p style={S.error}>{error}</p>}
      </form>
    </Centred>
  )
}

/* ----------------------------------------------------------------- register */

function Register({
  cfg,
  session,
  onSignOut,
}: {
  cfg: AppConfig
  session: Session
  onSignOut: () => void
}) {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [error, setError] = useState('')
  const [busyId, setBusyId] = useState('')

  async function refresh() {
    try {
      setSummary(await fetchSummary(cfg, session.idToken))
      setError('')
    } catch (err) {
      setError(String((err as Error).message ?? err))
    }
  }

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function act(rec: AssetRecord, status: string) {
    const verb = status === 'APPROVED' ? 'Approve' : status === 'REJECTED' ? 'Reject' : 'Deprecate'
    // The API requires a reason and so does the service. Prompting for it makes
    // the audit trail a deliberate act rather than an autogenerated string.
    const reason = window.prompt(`${verb} ${rec.name}: enter a reason`)
    if (!reason) return
    setBusyId(rec.id)
    try {
      await setStatus(cfg, session.idToken, rec.id, status, reason)
      // The status machine is not instant. Re-read rather than optimistically
      // patching the row: showing a state the service has not reached yet is
      // the one lie a governance dashboard cannot afford.
      await new Promise((r) => setTimeout(r, 1500))
      await refresh()
    } catch (err) {
      setError(String((err as Error).message ?? err))
    } finally {
      setBusyId('')
    }
  }

  const records = summary?.records ?? []
  const waiting = records.filter((r) => r.status === 'PENDING_APPROVAL').length
  const drafts = records.filter((r) => r.status === 'DRAFT').length

  return (
    <div style={S.page}>
      <header style={S.header}>
        <div>
          <h1 style={S.h1}>AI Asset Register</h1>
          <p style={{ ...S.dim, margin: 0 }}>
            {cfg.platformName} · {records.length} asset{records.length === 1 ? '' : 's'}
            {summary?.viewer.isReviewer
              ? ' · platform reviewer'
              : session.tenant && ` · scoped to ${session.tenant}`}
          </p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={S.modes}>
            <Mode label="Cedar" value={summary?.platform.enforcementMode ?? cfg.enforcementMode} />
            <Mode label="Scan" value={summary?.platform.scanMode ?? cfg.scanMode} />
          </div>
          <p style={{ ...S.dim, margin: '6px 0 0' }}>
            {session.email} · <button style={S.link} onClick={onSignOut}>sign out</button>
          </p>
        </div>
      </header>

      {error && <p style={{ ...S.error, marginBottom: 16 }}>{error}</p>}

      {!summary ? (
        <p style={S.dim}>Loading the catalogue…</p>
      ) : records.length === 0 ? (
        <p style={S.dim}>
          No assets visible. {summary.viewer.isReviewer
            ? 'The catalogue is empty.'
            : `Nothing is registered to tenant ${session.tenant || '(none)'}.`}
        </p>
      ) : (
        <table style={S.table}>
          <thead>
            <tr>
              {['Asset', 'Type', 'Owner', 'Tenant', 'Status', 'Reviewed because'].map((h) => (
                <th key={h} style={S.th}>{h}</th>
              ))}
              {summary.viewer.isReviewer && <th style={S.th} />}
            </tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <Row
                key={r.id}
                record={r}
                isReviewer={summary.viewer.isReviewer}
                busy={busyId === r.id}
                onAct={act}
              />
            ))}
          </tbody>
        </table>
      )}

      {summary && (
        <p style={{ ...S.dim, marginTop: 18 }}>
          {waiting > 0 && <strong>{waiting} asset{waiting === 1 ? '' : 's'} waiting for review. </strong>}
          {drafts > 0 && <>{drafts} in draft. </>}
          {waiting === 0 && drafts === 0 && 'Nothing waiting for review.'}
        </p>
      )}

      {summary && (
        <RegisterPanel
          cfg={cfg}
          session={session}
          capabilities={summary.capabilities}
          onRegistered={refresh}
        />
      )}

      {summary && (
        <AuditPanel cfg={cfg} session={session} capabilities={summary.capabilities} />
      )}

    </div>
  )
}

/* ----------------------------------------------------------------- register */

/* Propose an asset.
 *
 * The description field is the whole point of this panel, and the placeholder
 * says so. A tool description is a prompt: the model reads it to decide whether
 * to call the tool, so an instruction hidden in one reaches every future call by
 * every user. That is why it is scanned BEFORE the record is created — a refused
 * submission leaves nothing behind, with no poisoned draft for someone to find
 * later and wonder about.
 *
 * There are no tenant or owner fields, deliberately. Both come from the caller's
 * token server-side, so a tenant cannot register into another tenant's namespace
 * and ownership cannot be assigned to someone else to dodge a review
 * conversation. Showing them as read-only text makes that visible rather than
 * merely true.
 */
function RegisterPanel({
  cfg,
  session,
  capabilities,
  onRegistered,
}: {
  cfg: AppConfig
  session: Session
  capabilities: Summary['capabilities']
  onRegistered: () => Promise<void>
}) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<Registered | null>(null)
  const [refusal, setRefusal] = useState<ApiError | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setResult(null)
    setRefusal(null)
    try {
      const registered = await registerAsset(cfg, session.idToken, name.trim(), description.trim())
      setResult(registered)
      setName('')
      setDescription('')
      // Re-read rather than appending the new row optimistically: the record has
      // to travel DRAFT -> PENDING_APPROVAL through the service, and showing a
      // status it has not reached yet is the one lie this screen cannot afford.
      await new Promise((r) => setTimeout(r, 1500))
      await onRegistered()
    } catch (err) {
      setRefusal(err instanceof ApiError ? err : new ApiError(0, String(err), null))
    } finally {
      setBusy(false)
    }
  }

  if (!capabilities.register) {
    /* Shown, not hidden. A missing feature with a stated reason is honest; a
     * missing feature with no explanation looks broken. */
    return (
      <section style={S.panel}>
        <h2 style={S.h2}>Register an asset — unavailable</h2>
        <p style={{ ...S.dim, margin: 0 }}>{capabilities.registerDisabledBecause}</p>
      </section>
    )
  }

  return (
    <section style={S.panel}>
      <div style={S.panelHead}>
        <h2 style={S.h2}>Register an asset</h2>
        <button style={S.link} onClick={() => setOpen(!open)}>
          {open ? 'close' : 'add a tool to the catalogue'}
        </button>
      </div>

      {!open ? (
        <p style={{ ...S.dim, margin: 0 }}>
          Propose a new tool for review.
        </p>
      ) : (
        <form onSubmit={submit} style={{ marginTop: 6 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <label style={{ flex: '1 1 220px' }}>
              <span style={S.label}>Name</span>
              <input
                style={S.input}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="expense-lookup"
                required
              />
            </label>
            <div style={{ flex: '1 1 220px' }}>
              <span style={S.label}>Tenant and owner</span>
              <p style={{ ...S.dim, fontSize: 13, margin: '6px 0 0', lineHeight: 1.5 }}>
                {session.tenant || '(no tenant claim)'} · {session.email}
              </p>
            </div>
          </div>

          <label>
            <span style={S.label}>Description</span>
            <textarea
              style={{ ...S.input, minHeight: 78, resize: 'vertical', fontFamily: 'inherit' }}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Returns approved expense claims for a cost centre by month."
              required
            />
          </label>

          <button style={{ ...S.primary, width: 'auto', padding: '10px 20px' }} disabled={busy}>
            {busy ? 'Scanning…' : 'Scan and register'}
          </button>
        </form>
      )}

      {refusal && <Refusal error={refusal} />}
      {result && <Registration result={result} />}
    </section>
  )
}

/* A refused registration. The guardrail's reasons are the evidence, so they are
 * rendered rather than summarised — "PROMPT_ATTACK (HIGH confidence)" on screen
 * is what explains the refusal. */
function Refusal({ error }: { error: ApiError }) {
  const scan = error.scan
  // 503 means the scan could not run. Different fact from "refused", and worth
  // saying: an outage reported as a detection is a control claiming credit it
  // has not earned.
  const outage = error.status === 503 || scan?.failed

  return (
    <div style={{ ...S.error, marginTop: 16 }}>
      <strong style={{ display: 'block', marginBottom: 6 }}>
        {outage ? 'Not registered — the scan could not run' : 'Registration refused'}
      </strong>
      {error.message}
      {scan?.reasons?.length ? (
        <ul style={{ margin: '8px 0 0', paddingLeft: 20 }}>
          {scan.reasons.map((r) => (
            <li key={r}>
              <code>{r}</code>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

function Registration({ result }: { result: Registered }) {
  return (
    <div style={{ ...S.ok, marginTop: 16 }}>
      <strong style={{ display: 'block', marginBottom: 6 }}>
        {result.name} registered — status {result.status}
      </strong>
      {result.warning ?? result.note}
    </div>
  )
}

/* -------------------------------------------------------------- audit trail */

/* What actually happened.
 *
 * This is the ONLY panel on this page describing enforcement. The catalogue says
 * what was signed off; this says what Cedar decided when someone made a call.
 * The distinction is the single most important thing on the screen, so the panel
 * heading carries it rather than leaving it to the reader to infer.
 *
 * Loaded on demand rather than with the page. It reads a CloudWatch log group,
 * which is slower than the catalogue and can be legitimately empty, and a slow
 * empty panel above the fold reads as a broken page.
 */
function AuditPanel({
  cfg,
  session,
  capabilities,
}: {
  cfg: AppConfig
  session: Session
  capabilities: Summary['capabilities']
}) {
  const [open, setOpen] = useState(false)
  const [data, setData] = useState<Decisions | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // 15 days by default. An hour is the right default for an operator watching
  // live traffic, and the wrong one for an occasional review: the panel opens
  // empty and reads as "nothing is being recorded" when it means "nothing in
  // the last hour". Retention is 30 days, so this is inside it.
  const [minutes, setMinutes] = useState(21600)

  async function load(mins: number) {
    setBusy(true)
    setError('')
    try {
      setData(await fetchDecisions(cfg, session.idToken, mins))
    } catch (err) {
      setError(String((err as Error).message ?? err))
    } finally {
      setBusy(false)
    }
  }

  function toggle() {
    const next = !open
    setOpen(next)
    if (next && !data) load(minutes)
  }

  if (!capabilities.auditTrail) {
    return (
      <section style={S.panel}>
        <h2 style={S.h2}>Audit trail — unavailable</h2>
        <p style={{ ...S.dim, margin: 0 }}>{capabilities.auditDisabledBecause}</p>
      </section>
    )
  }

  return (
    <section style={S.panel}>
      <div style={S.panelHead}>
        <h2 style={S.h2}>Audit trail</h2>
        <button style={S.link} onClick={toggle}>
          {open ? 'close' : 'show recent decisions'}
        </button>
      </div>

      {!open ? (
        <p style={{ ...S.dim, margin: 0 }}>
          Recent policy decisions on tool calls.
        </p>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 14 }}>
            {[15, 60, 240, 1440, 10080, 21600].map((m) => (
              <button
                key={m}
                style={m === minutes ? S.chipOn : S.chip}
                onClick={() => {
                  setMinutes(m)
                  load(m)
                }}
              >
                last {windowLabel(m)}
              </button>
            ))}
            <button style={S.chip} disabled={busy} onClick={() => load(minutes)}>
              {busy ? 'reading…' : 'refresh'}
            </button>
            {data?.scopedTo && (
              <span style={{ ...S.dim, fontSize: 12 }}>
                scoped to your own calls ({data.scopedTo})
              </span>
            )}
          </div>

          {error && <p style={S.error}>{error}</p>}
          {data?.unavailable && <p style={S.error}>{data.unavailable}</p>}

          {data && !data.unavailable && data.decisions.length === 0 && (
            <p style={S.dim}>
              No policy decisions in the last {windowLabel(data.minutes)}. New calls can
              take up to a minute to appear.
            </p>
          )}

          {data && data.decisions.length > 0 && (
            <table style={S.table}>
              <thead>
                <tr>
                  {['When', 'Tool', 'Decision', 'Who', 'Outcome', 'Because'].map((h) => (
                    <th key={h} style={S.th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.decisions.map((d) => (
                  <tr key={d.requestId}>
                    <td style={{ ...S.td, whiteSpace: 'nowrap' }}>
                      {new Date(d.at).toLocaleTimeString()}
                    </td>
                    <td style={S.td}>{d.tool || <span style={S.dim}>—</span>}</td>
                    <td style={S.td}>
                      <span
                        style={{
                          ...S.pill,
                          background: d.decision === 'DENY' ? '#FFF5F5' : '#E6FFFA',
                          color: d.decision === 'DENY' ? '#742A2A' : '#234E52',
                        }}
                      >
                        {d.decision}
                      </span>
                    </td>
                    <td style={S.td}>{d.principal}</td>
                    <td style={S.td}>
                      {/* The contradiction only LOG_ONLY can produce, and the
                          whole argument for the mode: the policy said no and the
                          caller got their data anyway. */}
                      {d.succeededDespiteDeny ? (
                        <strong style={{ color: '#975A16' }}>
                          allowed anyway — LOG_ONLY
                        </strong>
                      ) : d.decision === 'DENY' ? (
                        'blocked'
                      ) : (
                        'allowed'
                      )}
                    </td>
                    <td style={{ ...S.td, ...S.dim, fontSize: 12, maxWidth: 280 }}>
                      {d.determiningPolicies.length
                        ? `permitted by ${d.determiningPolicies.join(', ')}`
                        : d.reason || <span style={{ opacity: 0.6 }}>—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

        </>
      )}
    </section>
  )
}

function Row({
  record,
  isReviewer,
  busy,
  onAct,
}: {
  record: AssetRecord
  isReviewer: boolean
  busy: boolean
  onAct: (r: AssetRecord, status: string) => void
}) {
  const style = STATUS_STYLE[record.status] ?? { bg: '#EDF2F7', fg: '#4A5568', label: record.status }
  const actionable = record.status === 'PENDING_APPROVAL'

  return (
    <tr>
      <td style={S.td}>
        <div style={{ fontWeight: 600 }}>{record.name}</div>
        <div style={{ ...S.dim, fontSize: 12, maxWidth: 420 }}>{record.description}</div>
      </td>
      <td style={S.td}>{record.type}</td>
      <td style={S.td}>{record.owner || <span style={S.dim}>—</span>}</td>
      <td style={S.td}>{record.tenant || <span style={S.dim}>—</span>}</td>
      <td style={S.td}>
        <span style={{ ...S.pill, background: style.bg, color: style.fg }}>{style.label}</span>
      </td>
      <td style={{ ...S.td, ...S.dim, fontSize: 12, maxWidth: 300 }}>
        {record.statusReason || <span style={{ opacity: 0.6 }}>no reason recorded</span>}
      </td>
      {isReviewer && (
        <td style={{ ...S.td, whiteSpace: 'nowrap' }}>
          {actionable ? (
            <>
              <button style={S.approve} disabled={busy} onClick={() => onAct(record, 'APPROVED')}>
                {busy ? '…' : 'Approve'}
              </button>
              <button style={S.reject} disabled={busy} onClick={() => onAct(record, 'REJECTED')}>
                Reject
              </button>
            </>
          ) : record.status === 'REJECTED' ? (
            /* Worth showing rather than hiding: REJECTED is terminal, enforced
               server-side. A greyed-out row teaches the lifecycle better than an
               absent one. */
            <span style={{ ...S.dim, fontSize: 12 }}>terminal</span>
          ) : null}
        </td>
      )}
    </tr>
  )
}

/* ------------------------------------------------------------------- bits */

function Mode({ label, value }: { label: string; value: string }) {
  const hot = value === 'ENFORCE'
  return (
    <span
      style={{
        ...S.pill,
        marginLeft: 6,
        background: hot ? '#D5F5F0' : '#FEF3D7',
        color: hot ? '#234E52' : '#744210',
      }}
    >
      {label}: {value}
    </span>
  )
}

function Centred({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ ...S.page, display: 'grid', placeItems: 'center', minHeight: '80vh' }}>
      {children}
    </div>
  )
}

function Fatal({ message }: { message: string }) {
  return (
    <Centred>
      <div style={{ maxWidth: 520 }}>
        <h1 style={{ ...S.h1, fontSize: 20 }}>The dashboard could not start</h1>
        <p style={S.error}>{message}</p>
        <p style={{ ...S.dim, fontSize: 13 }}>Please contact your platform administrator.</p>
      </div>
    </Centred>
  )
}

const S: Record<string, React.CSSProperties> = {
  page: {
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
    color: '#1A202C',
    padding: '32px 40px',
    maxWidth: 1200,
    margin: '0 auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    borderBottom: '2px solid #E2E8F0',
    paddingBottom: 16,
    marginBottom: 24,
    gap: 24,
  },
  h1: { fontSize: 26, margin: '0 0 4px', color: '#1A365D', letterSpacing: '-0.01em' },
  dim: { color: '#718096', fontSize: 14 },
  modes: { display: 'flex', justifyContent: 'flex-end' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 14 },
  th: {
    textAlign: 'left',
    padding: '10px 12px',
    borderBottom: '1px solid #CBD5E0',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: '#718096',
    fontWeight: 600,
  },
  td: { padding: '14px 12px', borderBottom: '1px solid #EDF2F7', verticalAlign: 'top' },
  pill: {
    display: 'inline-block',
    padding: '3px 10px',
    borderRadius: 12,
    fontSize: 12,
    fontWeight: 600,
    whiteSpace: 'nowrap',
  },
  input: {
    display: 'block',
    width: '100%',
    padding: '10px 12px',
    marginBottom: 10,
    border: '1px solid #CBD5E0',
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box',
  },
  primary: {
    width: '100%',
    padding: '11px 12px',
    background: '#2B6CB0',
    color: 'white',
    border: 'none',
    borderRadius: 6,
    fontSize: 14,
    fontWeight: 600,
    cursor: 'pointer',
  },
  approve: {
    padding: '6px 12px',
    marginRight: 6,
    background: '#2C7A7B',
    color: 'white',
    border: 'none',
    borderRadius: 5,
    fontSize: 13,
    cursor: 'pointer',
  },
  reject: {
    padding: '6px 12px',
    background: 'white',
    color: '#742A2A',
    border: '1px solid #C53030',
    borderRadius: 5,
    fontSize: 13,
    cursor: 'pointer',
  },
  link: {
    background: 'none',
    border: 'none',
    padding: 0,
    color: '#2B6CB0',
    cursor: 'pointer',
    fontSize: 14,
    textDecoration: 'underline',
  },
  error: {
    color: '#742A2A',
    background: '#FFF5F5',
    border: '1px solid #FEB2B2',
    borderRadius: 6,
    padding: '10px 12px',
    fontSize: 13,
  },
  panel: {
    marginTop: 28,
    padding: '18px 20px',
    border: '1px solid #E2E8F0',
    borderRadius: 8,
    background: '#FDFDFE',
  },
  panelHead: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'baseline',
    gap: 16,
    marginBottom: 10,
  },
  h2: { fontSize: 16, margin: 0, color: '#1A365D' },
  label: {
    display: 'block',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    color: '#718096',
    fontWeight: 600,
    marginBottom: 6,
  },
  chip: {
    padding: '4px 10px',
    background: 'white',
    border: '1px solid #CBD5E0',
    borderRadius: 12,
    fontSize: 12,
    cursor: 'pointer',
    color: '#4A5568',
  },
  chipOn: {
    padding: '4px 10px',
    background: '#2B6CB0',
    border: '1px solid #2B6CB0',
    borderRadius: 12,
    fontSize: 12,
    cursor: 'pointer',
    color: 'white',
    fontWeight: 600,
  },
  ok: {
    color: '#234E52',
    background: '#E6FFFA',
    border: '1px solid #81E6D9',
    borderRadius: 6,
    padding: '10px 12px',
    fontSize: 13,
    lineHeight: 1.5,
  },
  caveat: {
    marginTop: 28,
    padding: '14px 16px',
    background: '#FAF5FF',
    border: '1px solid #D6BCFA',
    borderRadius: 8,
    fontSize: 13,
    color: '#44337A',
    lineHeight: 1.6,
    maxWidth: 760,
  },
}
