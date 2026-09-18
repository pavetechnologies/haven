import { useEffect, useState } from "react"
import {
  ACCESS_SECTIONS,
  APPROVAL_INBOX_ACTIONS,
  APPROVAL_INBOX_COLUMNS,
  ASSIGNMENT_FORM_CONTROLS,
  ORG_SWITCHER,
  orgScopedScreenKey,
  projectKeysForPicker,
} from "./access-contract"
import { sanitizeLedgerEvent } from "./safe"

type Screen = "projects" | "clearance" | "policy" | "buoys" | "agents" | "logbook" | "admin"
type OrgMem = { slug: string; role: string; name?: string; org_id?: string }
type ProjectRow = { id?: string; slug: string; name?: string; keyCount?: number }
type KeyRow = { id: string; name: string; version: number; ref: string }
type PermissionRow = { permission: string; scopes: Array<"org" | "project" | "key"> }
type AccessAssignmentRow = {
  id: string
  project_id: string | null
  key_id: string | null
  permission: string
  effect: "allow" | "deny"
  reason: string
  expires_at: string | null
  revoked_at: string | null
}
type AccessRequestRow = {
  id: string
  org_id: string
  project_id: string | null
  key_id: string | null
  action: string
  actor_type: "human" | "agent"
  actor_id: string
  requester_human_id: string | null
  agent_owner_human_id: string | null
  tiers: ApprovalTier[]
  stage_index: number
  status: "pending" | "approved" | "denied" | "auto_approved" | "auto_denied" | "cancelled" | "expired"
  policy_reason: string
  reason_required: boolean
  reason: string | null
  expires_at: string | null
}
type BuoyRow = {
  id: string
  kind: "harbor" | "custom"
  name: string
  status: "active" | "revoked"
  last_seen_at: string | null
  created_at: string
}
type CanaryRow = {
  id: string
  key_ref: string | null
  mode: "decoy_key" | "sibling"
  digest: string
  status: "active" | "revoked"
  planted_at: string
}
type RemediationRow = {
  id: string
  canary_id: string
  key_ref: string | null
  status: "open" | "rotated" | "dismissed"
  on_exposure_applied: "block" | "queue" | "observe"
  opened_at: string
}
type PolicyActorType = "human" | "agent"
type ApprovalTier = "normal" | "elevated" | "breakglass"
type PolicyDefaultRow = {
  action: string
  actor_type: PolicyActorType
  outcome: "deny" | "auto_approve" | "approval_required"
  mode?: "threshold" | "sequential"
  tiers?: ApprovalTier[]
}
type PolicyMinimumRow = {
  action: string
  actor_type: PolicyActorType
  min: "auto" | ApprovalTier | "deny"
  mode?: "threshold" | "sequential"
  tiers?: ApprovalTier[]
}
type PolicyDocument = { defaults: PolicyDefaultRow[]; minimums: PolicyMinimumRow[] }
type PolicyRecord = {
  scope_type: "org" | "project" | "key"
  scope_id: string
  version: number
  document: PolicyDocument
  created_at: string
  created_by: string
}

async function api(path: string, init: RequestInit = {}) {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "content-type": "application/json", ...(init.headers || {}) },
    ...init,
  })
  const text = await res.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = { raw: text }
  }
  if (res.status === 401) {
    const err = new Error("unauthorized")
    ;(err as any).status = 401
    throw err
  }
  if (!res.ok) {
    throw new Error(data?.message || data?.error || `http ${res.status}`)
  }
  return data
}

export function App() {
  const [me, setMe] = useState<{ username: string; orgs: OrgMem[] } | null>(null)
  const [checking, setChecking] = useState(true)

  useEffect(() => {
    api("/v1/me")
      .then((d) => setMe(d))
      .catch(() => setMe(null))
      .finally(() => setChecking(false))
  }, [])

  if (checking) return <div className="auth"><p className="muted">Loading…</p></div>
  if (!me) return <Login onOk={(d) => setMe(d)} />
  return <Shell me={me} onLogout={() => setMe(null)} />
}

function Login({ onOk }: { onOk: (d: { username: string; orgs: OrgMem[] }) => void }) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    try {
      await api("/v1/session", { method: "POST", body: JSON.stringify({ username, password }) })
      onOk(await api("/v1/me"))
    } catch (err: any) {
      setError(err.message || "login failed")
    }
  }
  return (
    <div className="auth">
      <form className="auth-card" onSubmit={submit}>
        <img src="/logo-mark.png" alt="Haven" />
        <h1>HAVEN</h1>
        <p className="tag">Secrets stay in port. Agents request clearance.</p>
        <label htmlFor="user">Username</label>
        <input id="user" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <label htmlFor="pass">Password</label>
        <input id="pass" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button className="primary" type="submit">Sign in</button>
        {error ? <p className="error">{error}</p> : null}
      </form>
    </div>
  )
}

function Shell({ me, onLogout }: { me: { username: string; orgs: OrgMem[] }; onLogout: () => void }) {
  const [screen, setScreen] = useState<Screen>("projects")
  const [activeOrg, setActiveOrg] = useState(me.orgs[0]?.slug || "")
  const membership = me.orgs.find((item) => item.slug === activeOrg) || me.orgs[0]
  const org = membership?.slug || ""
  const role = membership?.role || "user"
  async function logout() {
    await api("/v1/session/logout", { method: "POST", body: "{}" }).catch(() => {})
    onLogout()
  }
  const nav: Array<[Screen, string]> = [
    ["projects", "Projects"],
    ["clearance", "Approvals"],
    ["policy", "Policy"],
    ["buoys", "Buoys"],
    ["agents", "Agents"],
    ["logbook", "Logbook"],
    ["admin", "Administration"],
  ]
  return (
    <div className="shell">
      <nav className="nav">
        <div className="brand">
          <img src="/logo-mark.png" alt="" />
          <span className="wordmark">HAVEN</span>
        </div>
        <div className="short">Clearance · Berth · Logbook</div>
        <div className="muted" style={{ marginBottom: 16, fontSize: 12 }}>{me.username} · {role}</div>
        <label htmlFor={ORG_SWITCHER.id}>{ORG_SWITCHER.label}</label>
        <select
          id={ORG_SWITCHER.id}
          className="org-switcher"
          value={org}
          onChange={(event) => setActiveOrg(event.target.value)}
        >
          {me.orgs.map((item) => (
            <option key={item.slug} value={item.slug}>{item.name || item.slug}</option>
          ))}
        </select>
        {nav.map(([id, label]) => (
          <button key={id} className={screen === id ? "active" : ""} onClick={() => setScreen(id)}>{label}</button>
        ))}
        <button onClick={logout}>Sign out</button>
      </nav>
      <main className="main">
        <div key={orgScopedScreenKey(org, screen)}>
          {screen === "projects" ? <Projects org={org} canWrite={role !== "user"} isSuperadmin={role === "superadmin"} /> : null}
          {screen === "clearance" ? <Clearance org={org} /> : null}
          {screen === "policy" ? <PolicyWorkspace org={org} canOrg={role === "superadmin"} /> : null}
          {screen === "buoys" ? <Buoys org={org} /> : null}
          {screen === "agents" ? <Agents org={org} /> : null}
          {screen === "logbook" ? <Logbook org={org} /> : null}
          {screen === "admin" ? <Administration org={org} /> : null}
        </div>
      </main>
    </div>
  )
}

function Projects({ org, canWrite, isSuperadmin }: { org: string; canWrite: boolean; isSuperadmin: boolean }) {
  const [projects, setProjects] = useState<ProjectRow[]>([])
  const [view, setView] = useState<"grid" | "list">("grid")
  const [openSlug, setOpenSlug] = useState<string | null>(null)
  const [newProject, setNewProject] = useState("")
  const [msg, setMsg] = useState("")
  const [error, setError] = useState("")

  async function load() {
    setError("")
    try {
      const p = await api(`/v1/orgs/${org}/projects`)
      const list: ProjectRow[] = p.projects || []
      if (canWrite) {
        const withCounts = await Promise.all(
          list.map(async (proj) => {
            try {
              const [dev, prod] = await Promise.all([
                api(`/v1/secrets?org=${encodeURIComponent(org)}&project=${encodeURIComponent(proj.slug)}&env=dev`),
                api(`/v1/secrets?org=${encodeURIComponent(org)}&project=${encodeURIComponent(proj.slug)}&env=prod`),
              ])
              return {
                ...proj,
                keyCount: (dev.secrets?.length || 0) + (prod.secrets?.length || 0),
              }
            } catch {
              return { ...proj, keyCount: undefined }
            }
          }),
        )
        setProjects(withCounts)
      } else {
        setProjects(list)
      }
    } catch (e: any) {
      setError(e.message)
      setProjects([])
    }
  }
  useEffect(() => { load() }, [org, canWrite])

  async function createProject(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setMsg("")
    const slug = newProject.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "")
    if (!slug) {
      setError("project slug required")
      return
    }
    try {
      await api(`/v1/orgs/${org}/projects`, {
        method: "POST",
        body: JSON.stringify({ slug, name: slug }),
      })
      setNewProject("")
      setMsg(`created ${slug}`)
      setOpenSlug(slug)
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  if (openSlug) {
    return (
      <ProjectKeys
        org={org}
        project={openSlug}
        canWrite={canWrite}
        isSuperadmin={isSuperadmin}
        onBack={() => {
          setOpenSlug(null)
          load()
        }}
      />
    )
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <h2>Projects</h2>
          <p className="muted">Berths in org <span className="mono">{org}</span>. Open a project to manage keys.</p>
        </div>
        <div className="view-toggle" role="group" aria-label="View">
          <button type="button" className={view === "grid" ? "active" : ""} onClick={() => setView("grid")}>Grid</button>
          <button type="button" className={view === "list" ? "active" : ""} onClick={() => setView("list")}>List</button>
        </div>
      </div>
      {canWrite ? (
        <form onSubmit={createProject} className="row create-project">
          <div>
            <label>New project</label>
            <input className="mono" placeholder="slug" value={newProject} onChange={(e) => setNewProject(e.target.value)} />
          </div>
          <button className="secondary" type="submit">Create project</button>
        </form>
      ) : null}
      {msg ? <p className="ok">{msg}</p> : null}
      {error ? <p className="error">{error}</p> : null}
      {projects.length === 0 ? (
        <p className="muted">No projects yet.</p>
      ) : view === "grid" ? (
        <div className="project-grid">
          {projects.map((p) => (
            <button key={p.slug} type="button" className="project-card" onClick={() => setOpenSlug(p.slug)}>
              <div className="project-card-title mono">{p.slug}</div>
              <div className="muted">{p.name && p.name !== p.slug ? p.name : "Project"}</div>
              <div className="project-card-meta">
                {typeof p.keyCount === "number" ? `${p.keyCount} key${p.keyCount === 1 ? "" : "s"}` : "Open →"}
              </div>
            </button>
          ))}
        </div>
      ) : (
        <table className="project-list">
          <thead>
            <tr><th>Project</th><th>Keys</th><th></th></tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <tr key={p.slug} className="click-row" onClick={() => setOpenSlug(p.slug)}>
                <td className="mono">{p.slug}</td>
                <td>{typeof p.keyCount === "number" ? p.keyCount : "—"}</td>
                <td><span className="muted">Open →</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function ProjectKeys({
  org,
  project,
  canWrite,
  isSuperadmin,
  onBack,
}: {
  org: string
  project: string
  canWrite: boolean
  isSuperadmin: boolean
  onBack: () => void
}) {
  const [env, setEnv] = useState("dev")
  const [rows, setRows] = useState<KeyRow[]>([])
  const [name, setName] = useState("")
  const [value, setValue] = useState("")
  const [msg, setMsg] = useState("")
  const [error, setError] = useState("")
  const [revealed, setRevealed] = useState<{ ref: string; value: string } | null>(null)
  const [pendingDelete, setPendingDelete] = useState<{ name: string; ref: string } | null>(null)
  const [confirmName, setConfirmName] = useState("")
  const [deleting, setDeleting] = useState(false)

  async function load() {
    setError("")
    try {
      if (!canWrite) {
        setRows([])
        return
      }
      const data = await api(
        `/v1/secrets?org=${encodeURIComponent(org)}&project=${encodeURIComponent(project)}&env=${encodeURIComponent(env)}`,
      )
      setRows(data.secrets || [])
    } catch (e: any) {
      setError(e.message)
      setRows([])
    }
  }
  useEffect(() => { load() }, [org, project, env, canWrite])

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setMsg("")
    try {
      const data = await api("/v1/secrets", {
        method: "POST",
        body: JSON.stringify({ org, project, env, name, value }),
      })
      setValue("")
      setMsg(`${data.status} ${data.ref}`)
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  async function reveal(row: { name: string; ref: string }, forEdit = false) {
    if (!window.confirm(`Reveal ${row.name}? The value will be shown once and recorded in the logbook.`)) return
    setError("")
    try {
      const data = await api("/v1/secrets/reveal", {
        method: "POST",
        body: JSON.stringify({ ref: row.ref }),
      })
      setRevealed({ ref: data.ref, value: data.value })
      if (forEdit) {
        setName(row.name)
        setValue(data.value)
        setMsg(`Loaded ${row.name} for editing. Save to create a new version.`)
      }
    } catch (err: any) {
      setError(err.message)
    }
  }

  function askDelete(row: { name: string; ref: string }) {
    setError("")
    setMsg("")
    setConfirmName("")
    setPendingDelete(row)
  }

  function cancelDelete() {
    setPendingDelete(null)
    setConfirmName("")
    setDeleting(false)
  }

  async function confirmDelete(e: React.FormEvent) {
    e.preventDefault()
    if (!pendingDelete) return
    setError("")
    setMsg("")
    setDeleting(true)
    try {
      await api("/v1/secrets/delete", {
        method: "POST",
        body: JSON.stringify({ ref: pendingDelete.ref, confirm_name: confirmName.trim() }),
      })
      if (revealed?.ref === pendingDelete.ref) setRevealed(null)
      setMsg(`Deleted ${pendingDelete.name}`)
      cancelDelete()
      await load()
    } catch (err: any) {
      setError(err.message)
      setDeleting(false)
    }
  }

  return (
    <section>
      <button type="button" className="back-link" onClick={onBack}>← Projects</button>
      <div className="page-head">
        <div>
          <h2 className="mono">{project}</h2>
          <p className="muted">
            Keys for <span className="mono">haven://{org}/{project}/…</span>. Values stay in port.
          </p>
        </div>
        <div>
          <label>Berth</label>
          <select value={env} onChange={(e) => setEnv(e.target.value)}>
            <option value="dev">dev</option>
            <option value="prod">prod</option>
          </select>
        </div>
      </div>
      {canWrite ? (
        <form onSubmit={save}>
          <div className="row">
            <div>
              <label>Name</label>
              <input className="mono" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div>
              <label>Value</label>
              <input type="password" autoComplete="off" value={value} onChange={(e) => setValue(e.target.value)} required />
            </div>
          </div>
          <button className="primary" type="submit">Save key</button>
        </form>
      ) : (
        <p className="muted">Your role can clear knocks, not browse key values.</p>
      )}
      {revealed ? (
        <div className="flash">
          <div>Value for <span className="mono">{revealed.ref}</span> (shown once)</div>
          <div className="mono">{revealed.value}</div>
          <button className="secondary" type="button" onClick={() => setRevealed(null)}>Dismiss value</button>
        </div>
      ) : null}
      {pendingDelete ? (
        <form className="flash danger-panel" onSubmit={confirmDelete}>
          <div><strong>Delete key permanently?</strong></div>
          <p className="muted">
            This cannot be undone. Type <span className="mono">{pendingDelete.name}</span> to confirm.
          </p>
          <p className="mono muted">{pendingDelete.ref}</p>
          <label htmlFor="confirm-delete-name">Confirm name</label>
          <input
            id="confirm-delete-name"
            className="mono"
            autoComplete="off"
            autoFocus
            value={confirmName}
            onChange={(e) => setConfirmName(e.target.value)}
            placeholder={pendingDelete.name}
          />
          <div className="row" style={{ marginTop: 12 }}>
            <button
              className="danger"
              type="submit"
              disabled={deleting || confirmName.trim() !== pendingDelete.name}
            >
              {deleting ? "Deleting…" : "Delete permanently"}
            </button>
            <button className="secondary" type="button" onClick={cancelDelete} disabled={deleting}>
              Cancel
            </button>
          </div>
        </form>
      ) : null}
      {msg ? <p className="ok">{msg}</p> : null}
      {error ? <p className="error">{error}</p> : null}
      <table>
        <thead><tr><th>Name</th><th>Version</th><th>Ref</th>{isSuperadmin ? <th>Actions</th> : null}</tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name}>
              <td className="mono">{r.name}</td>
              <td>{r.version}</td>
              <td>
                <button className="secondary" type="button" onClick={() => navigator.clipboard.writeText(r.ref)}>{r.ref}</button>
              </td>
              {isSuperadmin ? (
                <td>
                  <button className="secondary" type="button" onClick={() => reveal(r)}>Reveal</button>
                  <button className="secondary" type="button" onClick={() => reveal(r, true)}>Edit</button>
                  <button className="secondary" type="button" onClick={() => askDelete(r)}>Delete</button>
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function Clearance({ org }: { org: string }) {
  const [rows, setRows] = useState<AccessRequestRow[]>([])
  const [error, setError] = useState("")

  async function load() {
    setError("")
    try {
      const data = await api(`/v1/access-requests?org=${encodeURIComponent(org)}&status=pending`)
      setRows(data.access_requests || [])
    } catch (e: any) {
      setError(e.message)
      setRows([])
    }
  }
  useEffect(() => { load() }, [org])

  async function decide(request: AccessRequestRow, decision: "approve" | "deny") {
    const tier = request.tiers[request.stage_index]
    const reason = window.prompt(
      `${decision === "approve" ? "Approval" : "Denial"} reason${request.reason_required || tier !== "normal" ? " (required)" : " (optional)"}`,
    )
    if (reason === null || ((request.reason_required || tier !== "normal") && !reason.trim())) return
    setError("")
    try {
      await api(`/v1/access-requests/${request.id}/${decision}`, {
        method: "POST",
        body: JSON.stringify({ ...(reason.trim() ? { reason: reason.trim() } : {}) }),
      })
      await load()
    } catch (e: any) {
      setError(e.message)
    }
  }

  async function escalate(request: AccessRequestRow) {
    const current = request.tiers[request.stage_index]
    const target: ApprovalTier | null =
      current === "normal" ? "elevated" : current === "elevated" ? "breakglass" : null
    if (!target) return
    const reason = window.prompt(`Reason to escalate to ${target} (required)`)
    if (!reason?.trim()) return
    setError("")
    try {
      await api(`/v1/access-requests/${request.id}/escalate`, {
        method: "POST",
        body: JSON.stringify({ tier: target, reason: reason.trim() }),
      })
      await load()
    } catch (e: any) {
      setError(e.message)
    }
  }

  return (
    <section>
      <h2>Approval inbox</h2>
      <p className="muted">Review policy-gated access requests for this organization. Decisions remain fail closed.</p>
      {error ? <p className="error">{error}</p> : null}
      <button className="secondary" type="button" onClick={load}>Refresh</button>
      <table>
        <thead>
          <tr>{APPROVAL_INBOX_COLUMNS.map((column) => <th key={column}>{column}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((request) => {
            const tier = request.tiers[request.stage_index]
            const owner = request.agent_owner_human_id || request.requester_human_id || "—"
            const resource = request.key_id || request.project_id || request.org_id
            return (
            <tr key={request.id}>
              <td>{request.actor_type}<div className="mono muted">{request.actor_id}</div></td>
              <td className="mono">{owner}</td>
              <td><div className="mono">{resource}</div><div className="muted">{request.action}</div></td>
              <td>{request.stage_index + 1}/{request.tiers.length}<div className="badge">{tier}</div></td>
              <td>{request.policy_reason || "Policy approval required"}{request.expires_at ? <div className="mono muted">Expires {request.expires_at}</div> : null}</td>
              <td>{request.reason && request.reason !== request.policy_reason ? request.reason : "—"}</td>
              <td>
                <button className="primary" type="button" onClick={() => decide(request, "approve")}>{APPROVAL_INBOX_ACTIONS[0]}</button>{" "}
                <button className="danger" type="button" onClick={() => decide(request, "deny")}>{APPROVAL_INBOX_ACTIONS[1]}</button>{" "}
                {tier !== "breakglass" ? (
                  <button className="secondary" type="button" onClick={() => escalate(request)}>{APPROVAL_INBOX_ACTIONS[2]}</button>
                ) : null}
              </td>
            </tr>
          )})}
        </tbody>
      </table>
      {rows.length === 0 && !error ? <p className="muted">No access requests await review.</p> : null}
    </section>
  )
}

function OneTimeValues({
  title,
  values,
  onDismiss,
}: {
  title: string
  values: Array<[string, string]>
  onDismiss: () => void
}) {
  return (
    <div className="flash">
      <div className="page-head">
        <div>
          <strong>{title}</strong>
          <div className="muted">Copy these now. Haven will not show them again.</div>
        </div>
        <button className="secondary" type="button" onClick={onDismiss}>Dismiss</button>
      </div>
      {values.map(([label, value]) => (
        <div key={label}>
          <label>{label}</label>
          <input className="mono" value={value} readOnly onFocus={(e) => e.currentTarget.select()} />
        </div>
      ))}
    </div>
  )
}

function Buoys({ org }: { org: string }) {
  const [tab, setTab] = useState<"buoys" | "canaries" | "remediations">("buoys")
  return (
    <section>
      <div className="page-head">
        <div>
          <h2>Buoys</h2>
          <p className="muted">Station watchers, plant tripwires, and clear exposure squalls.</p>
        </div>
        <div className="view-toggle" role="tablist" aria-label="Buoy operations">
          <button type="button" className={tab === "buoys" ? "active" : ""} onClick={() => setTab("buoys")}>Buoys</button>
          <button type="button" className={tab === "canaries" ? "active" : ""} onClick={() => setTab("canaries")}>Canaries</button>
          <button type="button" className={tab === "remediations" ? "active" : ""} onClick={() => setTab("remediations")}>Remediations</button>
        </div>
      </div>
      {tab === "buoys" ? <BuoyPanel org={org} /> : null}
      {tab === "canaries" ? <CanaryPanel org={org} /> : null}
      {tab === "remediations" ? <RemediationPanel org={org} /> : null}
    </section>
  )
}

function BuoyPanel({ org }: { org: string }) {
  const [rows, setRows] = useState<BuoyRow[]>([])
  const [form, setForm] = useState({ name: "", kind: "harbor" as BuoyRow["kind"] })
  const [credential, setCredential] = useState<{ token: string; pepper: string } | null>(null)
  const [error, setError] = useState("")

  async function load() {
    setError("")
    try {
      setRows((await api(`/v1/buoys?org=${encodeURIComponent(org)}`)).buoys || [])
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { load() }, [org])

  async function register(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    try {
      const data = await api("/v1/buoys", {
        method: "POST",
        body: JSON.stringify({ org, name: form.name, kind: form.kind }),
      })
      setCredential({ token: data.token, pepper: data.canary_pepper_hex })
      setForm({ ...form, name: "" })
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  async function act(id: string, action: "rotate-credential" | "revoke") {
    setError("")
    try {
      const data = await api(`/v1/buoys/${id}/${action}`, {
        method: "POST",
        body: JSON.stringify({ org }),
      })
      if (action === "rotate-credential") {
        setCredential({ token: data.token, pepper: data.canary_pepper_hex })
      }
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div>
      <p className="muted">Register watcher stations for Harbor or custom scanners.</p>
      {credential ? (
        <OneTimeValues
          title="Buoy kit (shown once)"
          values={[["Buoy token", credential.token], ["Canary pepper", credential.pepper]]}
          onDismiss={() => setCredential(null)}
        />
      ) : null}
      {error ? <p className="error">{error}</p> : null}
      <form className="row" onSubmit={register}>
        <div>
          <label>Station name</label>
          <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </div>
        <div>
          <label>Watch</label>
          <select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value as BuoyRow["kind"] })}>
                        <option value="custom">custom</option>
            <option value="harbor">harbor</option>
          </select>
        </div>
        <button className="primary" type="submit">Register buoy</button>
      </form>
      <table>
        <thead><tr><th>Station</th><th>Watch</th><th>Status</th><th>Last signal</th><th></th></tr></thead>
        <tbody>
          {rows.map((buoy) => (
            <tr key={buoy.id}>
              <td>{buoy.name}<div className="mono muted">{buoy.id}</div></td>
              <td>{buoy.kind}</td>
              <td>{buoy.status}</td>
              <td className="mono">{buoy.last_seen_at || "Never"}</td>
              <td>
                {buoy.status === "active" ? (
                  <>
                    <button className="secondary" type="button" onClick={() => act(buoy.id, "rotate-credential")}>Rotate token</button>{" "}
                    <button className="danger" type="button" onClick={() => act(buoy.id, "revoke")}>Recall</button>
                  </>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && !error ? <p className="muted">No buoys are on station.</p> : null}
    </div>
  )
}

function CanaryPanel({ org }: { org: string }) {
  const [rows, setRows] = useState<CanaryRow[]>([])
  const [form, setForm] = useState({ project: "default", mode: "decoy_key" as CanaryRow["mode"], key_ref: "", decoy: "" })
  const [plantedDecoy, setPlantedDecoy] = useState("")
  const [error, setError] = useState("")

  async function load() {
    setError("")
    try {
      setRows((await api(`/v1/canaries?org=${encodeURIComponent(org)}`)).canaries || [])
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { load() }, [org])

  async function plant(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    try {
      const data = await api("/v1/canaries", {
        method: "POST",
        body: JSON.stringify({
          org,
          project: form.project,
          mode: form.mode,
          ...(form.mode === "sibling" ? { key_ref: form.key_ref } : {}),
          ...(form.decoy ? { decoy: form.decoy } : {}),
        }),
      })
      setPlantedDecoy(data.decoy)
      setForm({ ...form, key_ref: "", decoy: "" })
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  async function revoke(id: string) {
    setError("")
    try {
      await api(`/v1/canaries/${id}/revoke`, { method: "POST", body: JSON.stringify({ org }) })
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div>
      <p className="muted">Plant decoys in a project berth. A sighting raises the configured exposure action.</p>
      {plantedDecoy ? (
        <OneTimeValues title="Canary decoy (shown once)" values={[["Decoy", plantedDecoy]]} onDismiss={() => setPlantedDecoy("")} />
      ) : null}
      {error ? <p className="error">{error}</p> : null}
      <form onSubmit={plant}>
        <div className="row">
          <div>
            <label>Project</label>
            <input className="mono" value={form.project} onChange={(e) => setForm({ ...form, project: e.target.value })} required />
          </div>
          <div>
            <label>Planting mode</label>
            <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value as CanaryRow["mode"], key_ref: "" })}>
              <option value="decoy_key">decoy key</option>
              <option value="sibling">sibling of key</option>
            </select>
          </div>
        </div>
        {form.mode === "sibling" ? (
          <>
            <label>Key ref</label>
            <input className="mono" placeholder={`haven://${org}/${form.project}/dev/NAME`} value={form.key_ref} onChange={(e) => setForm({ ...form, key_ref: e.target.value })} required />
          </>
        ) : null}
        <label>Decoy value (optional; generated if blank)</label>
        <input type="password" autoComplete="off" value={form.decoy} onChange={(e) => setForm({ ...form, decoy: e.target.value })} />
        <button className="primary" type="submit">Plant canary</button>
      </form>
      <table>
        <thead><tr><th>Canary</th><th>Mode</th><th>Key ref</th><th>Status</th><th></th></tr></thead>
        <tbody>
          {rows.map((canary) => (
            <tr key={canary.id}>
              <td className="mono">{canary.id}</td>
              <td>{canary.mode}</td>
              <td className="mono">{canary.key_ref || "—"}</td>
              <td>{canary.status}</td>
              <td>{canary.status === "active" ? <button className="danger" type="button" onClick={() => revoke(canary.id)}>Pull canary</button> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && !error ? <p className="muted">No canaries are planted.</p> : null}
    </div>
  )
}

function RemediationPanel({ org }: { org: string }) {
  const [rows, setRows] = useState<RemediationRow[]>([])
  const [status, setStatus] = useState<"" | RemediationRow["status"]>("open")
  const [error, setError] = useState("")

  async function load() {
    setError("")
    try {
      const query = new URLSearchParams({ org })
      if (status) query.set("status", status)
      setRows((await api(`/v1/remediations?${query}`)).remediations || [])
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { load() }, [org, status])

  async function act(id: string, action: "rotate" | "dismiss") {
    setError("")
    try {
      await api(`/v1/remediations/${id}/${action}`, {
        method: "POST",
        body: JSON.stringify({ org, ...(action === "rotate" ? { revoke_canary: true } : {}) }),
      })
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div>
      <div className="page-head">
        <p className="muted">Work exposure reports from first sighting to safe harbor.</p>
        <div>
          <label>Status</label>
          <select value={status} onChange={(e) => setStatus(e.target.value as "" | RemediationRow["status"])}>
            <option value="">all</option>
            <option value="open">open</option>
            <option value="rotated">rotated</option>
            <option value="dismissed">dismissed</option>
          </select>
        </div>
      </div>
      {error ? <p className="error">{error}</p> : null}
      <button className="secondary" type="button" onClick={load}>Refresh queue</button>
      <table>
        <thead><tr><th>Opened</th><th>Key ref</th><th>Action</th><th>Status</th><th></th></tr></thead>
        <tbody>
          {rows.map((item) => (
            <tr key={item.id}>
              <td className="mono">{item.opened_at}</td>
              <td className="mono">{item.key_ref || item.canary_id}</td>
              <td>{item.on_exposure_applied}</td>
              <td>{item.status}</td>
              <td>
                {item.status === "open" ? (
                  <>
                    <button className="primary" type="button" onClick={() => act(item.id, "rotate")}>Rotate &amp; secure</button>{" "}
                    <button className="secondary" type="button" onClick={() => act(item.id, "dismiss")}>Dismiss</button>
                  </>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 && !error ? <p className="muted">The remediation sea is calm.</p> : null}
    </div>
  )
}

function Administration({ org }: { org: string }) {
  const [tab, setTab] = useState<"members" | "access" | "apikeys" | "account">("members")
  return (
    <section>
      <div className="page-head">
        <div>
          <h2>Administration</h2>
          <p className="muted">Members, scoped access, activity keys, and your account.</p>
        </div>
        <div className="view-toggle" role="tablist" aria-label="Administration">
          <button type="button" className={tab === "members" ? "active" : ""} onClick={() => setTab("members")}>Members</button>
          <button type="button" className={tab === "access" ? "active" : ""} onClick={() => setTab("access")}>Access</button>
          <button type="button" className={tab === "apikeys" ? "active" : ""} onClick={() => setTab("apikeys")}>API keys</button>
          <button type="button" className={tab === "account" ? "active" : ""} onClick={() => setTab("account")}>Account</button>
        </div>
      </div>
      {tab === "members" ? <Members org={org} /> : null}
      {tab === "access" ? <AccessWorkspace org={org} /> : null}
      {tab === "apikeys" ? <ApiKeys org={org} /> : null}
      {tab === "account" ? <Account /> : null}
    </section>
  )
}

function AccessWorkspace({ org }: { org: string }) {
  const [members, setMembers] = useState<any[]>([])
  const [projects, setProjects] = useState<ProjectRow[]>([])
  const [keys, setKeys] = useState<KeyRow[]>([])
  const [catalog, setCatalog] = useState<PermissionRow[]>([])
  const [userId, setUserId] = useState("")
  const [access, setAccess] = useState<any>(null)
  const [view, setView] = useState<(typeof ACCESS_SECTIONS)[number]>("assigned")
  const [form, setForm] = useState({
    permission: "",
    effect: "allow" as "allow" | "deny",
    scope: "org" as "org" | "project" | "key",
    project_id: "",
    key_id: "",
    expires_at: "",
    reason: "",
  })
  const [explanation, setExplanation] = useState<any>(null)
  const [error, setError] = useState("")
  const [msg, setMsg] = useState("")

  async function loadWorkspace() {
    setError("")
    try {
      const [memberData, permissionData, projectData] = await Promise.all([
        api(`/v1/orgs/${encodeURIComponent(org)}/members`),
        api("/v1/permissions"),
        api(`/v1/orgs/${encodeURIComponent(org)}/projects`),
      ])
      const nextMembers = memberData.members || []
      const nextCatalog: PermissionRow[] = permissionData.permissions || []
      setMembers(nextMembers)
      setCatalog(nextCatalog)
      setProjects(projectData.projects || [])
      setUserId((current) => current && nextMembers.some((item: any) => item.id === current) ? current : nextMembers[0]?.id || "")
      setForm((current) => ({ ...current, permission: current.permission || nextCatalog[0]?.permission || "" }))
    } catch (e: any) {
      setError(e.message)
    }
  }

  async function loadAccess(selectedUser = userId) {
    if (!selectedUser) {
      setAccess(null)
      return
    }
    try {
      setAccess(await api(`/v1/orgs/${encodeURIComponent(org)}/users/${encodeURIComponent(selectedUser)}/access`))
    } catch (e: any) {
      setError(e.message)
      setAccess(null)
    }
  }

  useEffect(() => {
    setAccess(null)
    setExplanation(null)
    loadWorkspace()
  }, [org])
  useEffect(() => { loadAccess() }, [org, userId])

  useEffect(() => {
    setKeys([])
    setForm((current) => ({ ...current, key_id: "" }))
    if (form.scope !== "key" || !form.project_id) return
    const project = projects.find((item) => item.id === form.project_id)
    if (!project) return
    let cancelled = false
    Promise.all(
      ["dev", "prod"].map((env) =>
        api(
          `/v1/secrets?org=${encodeURIComponent(org)}&project=${encodeURIComponent(project.slug)}&env=${env}`,
        ),
      ),
    )
      .then((responses) => {
        if (!cancelled) setKeys(responses.flatMap((response) => response.secrets || []))
      })
      .catch((e: any) => {
        if (!cancelled) setError(e.message)
      })
    return () => {
      cancelled = true
    }
  }, [org, form.scope, form.project_id, projects])

  const scopePermissions = catalog.filter((item) => item.scopes.includes(form.scope))
  useEffect(() => {
    if (!scopePermissions.some((item) => item.permission === form.permission)) {
      setForm((current) => ({ ...current, permission: scopePermissions[0]?.permission || "" }))
    }
  }, [form.scope, catalog])

  async function assign(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setMsg("")
    try {
      await api(`/v1/orgs/${encodeURIComponent(org)}/access-assignments`, {
        method: "POST",
        body: JSON.stringify({
          user_id: userId,
          permission: form.permission,
          effect: form.effect,
          reason: form.reason,
          ...(form.scope !== "org" ? { project_id: form.project_id } : {}),
          ...(form.scope === "key" ? { key_id: form.key_id } : {}),
          ...(form.expires_at ? { expires_at: new Date(form.expires_at).toISOString() } : {}),
        }),
      })
      setMsg(`${form.effect === "deny" ? "Deny" : "Grant"} recorded`)
      setForm({ ...form, reason: "" })
      await loadAccess()
    } catch (err: any) {
      setError(err.message)
    }
  }

  async function revoke(assignment: AccessAssignmentRow) {
    const reason = window.prompt(`Reason for revoking ${assignment.permission}`)
    if (!reason?.trim()) return
    setError("")
    try {
      await api(
        `/v1/orgs/${encodeURIComponent(org)}/access-assignments/${encodeURIComponent(assignment.id)}/revoke`,
        { method: "POST", body: JSON.stringify({ reason }) },
      )
      setMsg("Assignment revoked")
      await loadAccess()
    } catch (err: any) {
      setError(err.message)
    }
  }

  async function explain() {
    setError("")
    try {
      setExplanation(await api("/v1/authorization/explain", {
        method: "POST",
        body: JSON.stringify({
          org,
          user_id: userId,
          permission: form.permission,
          ...(form.scope !== "org" && form.project_id ? { project_id: form.project_id } : {}),
          ...(form.scope === "key" && form.key_id ? { key_id: form.key_id } : {}),
        }),
      }))
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div className="access-workspace">
      <div className="access-member">
        <label>Member</label>
        <select value={userId} onChange={(event) => setUserId(event.target.value)}>
          {members.map((member) => <option key={member.id} value={member.id}>{member.username} · {member.role}</option>)}
        </select>
      </div>
      {error ? <p className="error">{error}</p> : null}
      {msg ? <p className="ok">{msg}</p> : null}
      <div className="view-toggle access-tabs" role="tablist" aria-label="Access detail">
        {ACCESS_SECTIONS.map((section) => (
          <button
            key={section}
            type="button"
            className={view === section ? "active" : ""}
            onClick={() => setView(section)}
          >
            {section[0].toUpperCase() + section.slice(1)}
          </button>
        ))}
      </div>
      {view === "assigned" ? (
        <table>
          <thead><tr><th>Effect</th><th>Permission</th><th>Scope</th><th>Reason</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {(access?.assigned || []).map((item: AccessAssignmentRow) => (
              <tr key={item.id}>
                <td><span className={`badge ${item.effect}`}>{item.effect}</span></td>
                <td className="mono">{item.permission}</td>
                <td className="mono">{item.key_id || item.project_id || "organization"}</td>
                <td>{item.reason}</td>
                <td>{item.revoked_at ? "revoked" : "active"}</td>
                <td>{!item.revoked_at ? <button className="danger" type="button" onClick={() => revoke(item)}>Revoke</button> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {view === "inherited" ? (
        <div className="permission-grid">
          {(access?.inherited || []).map((permission: string) => <span className="mono permission-chip" key={permission}>{permission}</span>)}
        </div>
      ) : null}
      {view === "effective" ? (
        <table>
          <thead><tr><th>Permission</th><th>Decision</th><th>Why</th></tr></thead>
          <tbody>
            {(access?.effective || []).map((item: any) => (
              <tr key={item.permission}>
                <td className="mono">{item.permission}</td>
                <td className={item.allow ? "ok" : "error"}>{item.allow ? "allow" : "deny"}</td>
                <td>{item.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      <h3 className="access-heading">Grant or deny scoped access</h3>
      <form onSubmit={assign} data-contract-controls={ASSIGNMENT_FORM_CONTROLS.join(" ")}>
        <div className="row">
          <div>
            <label>Effect</label>
            <select value={form.effect} onChange={(event) => setForm({ ...form, effect: event.target.value as "allow" | "deny" })}>
              <option value="allow">grant</option>
              <option value="deny">deny</option>
            </select>
          </div>
          <div>
            <label>Scope</label>
            <select value={form.scope} onChange={(event) => setForm({ ...form, scope: event.target.value as typeof form.scope })}>
              <option value="org">organization</option>
              <option value="project">project</option>
              <option value="key">key</option>
            </select>
          </div>
          <div>
            <label>Permission</label>
            <select className="mono" value={form.permission} onChange={(event) => setForm({ ...form, permission: event.target.value })}>
              {scopePermissions.map((item) => <option key={item.permission} value={item.permission}>{item.permission}</option>)}
            </select>
          </div>
        </div>
        {form.scope !== "org" ? (
          <div className="row">
            <div>
              <label>Project</label>
              <select value={form.project_id} onChange={(event) => setForm({ ...form, project_id: event.target.value })} required>
                <option value="">Select project</option>
                {projects.map((project) => <option key={project.id} value={project.id}>{project.slug}</option>)}
              </select>
            </div>
            {form.scope === "key" ? (
              <div>
                <label>Key</label>
                <select
                  className="mono"
                  value={form.key_id}
                  onChange={(event) => setForm({ ...form, key_id: event.target.value })}
                  required
                >
                  <option value="">Select key</option>
                  {projectKeysForPicker(keys).map((key) => (
                    <option key={key.value} value={key.value}>{key.label}</option>
                  ))}
                </select>
              </div>
            ) : null}
          </div>
        ) : null}
        <div className="row">
          <div>
            <label>Expires (optional)</label>
            <input type="datetime-local" value={form.expires_at} onChange={(event) => setForm({ ...form, expires_at: event.target.value })} />
          </div>
          <div>
            <label>Reason</label>
            <input value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} required />
          </div>
        </div>
        <div className="row access-actions">
          <button className="primary" type="submit">{form.effect === "deny" ? "Record deny" : "Grant access"}</button>
          <button className="secondary" type="button" onClick={explain}>Explain current decision</button>
        </div>
      </form>
      {explanation ? (
        <div className="flash">
          <strong>{explanation.allow ? "Allowed" : "Denied"}</strong>
          <span className="muted"> · {explanation.reason} · </span>
          <span className="mono">{explanation.decision_id}</span>
        </div>
      ) : null}
    </div>
  )
}

function Members({ org }: { org: string }) {
  const [rows, setRows] = useState<any[]>([])
  const [form, setForm] = useState({ username: "", password: "", role: "user" })
  const [error, setError] = useState("")

  async function load() {
    try {
      setRows((await api(`/v1/orgs/${org}/members`)).members || [])
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { load() }, [org])

  async function add(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    try {
      await api(`/v1/orgs/${org}/members`, { method: "POST", body: JSON.stringify(form) })
      setForm({ username: "", password: "", role: "user" })
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div>
      {error ? <p className="error">{error}</p> : null}
      <table>
        <thead><tr><th>User</th><th>Role</th></tr></thead>
        <tbody>
          {rows.map((m) => (
            <tr key={m.id}><td>{m.username}</td><td>{m.role}</td></tr>
          ))}
        </tbody>
      </table>
      <h3 style={{ marginTop: 32 }}>Add member</h3>
      <form onSubmit={add}>
        <label>Username</label>
        <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
        <label>Password (12+)</label>
        <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
        <label>Role</label>
        <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          <option value="user">user</option>
          <option value="admin">admin</option>
          <option value="superadmin">superadmin</option>
        </select>
        <button className="primary" type="submit">Add</button>
      </form>
    </div>
  )
}

function PolicyWorkspace({ org, canOrg }: { org: string; canOrg: boolean }) {
  const [scope, setScope] = useState<"org" | "project" | "key">("org")
  const [projects, setProjects] = useState<ProjectRow[]>([])
  const [project, setProject] = useState("")
  const [keys, setKeys] = useState<KeyRow[]>([])
  const [keyId, setKeyId] = useState("")
  const [record, setRecord] = useState<PolicyRecord | null>(null)
  const [document, setDocument] = useState<PolicyDocument>({ defaults: [], minimums: [] })
  const [history, setHistory] = useState<PolicyRecord[]>([])
  const [preview, setPreview] = useState<any>(null)
  const [previewInput, setPreviewInput] = useState({
    action: "keys.resolve",
    actor_type: "agent" as PolicyActorType,
    environment: "dev",
  })
  const [msg, setMsg] = useState("")
  const [error, setError] = useState("")

  const selectedProject = projects.find((item) => item.slug === project)
  const selectedKey = keys.find((item) => item.id === keyId)
  const endpoint =
    scope === "org"
      ? `/v1/orgs/${encodeURIComponent(org)}/policy`
      : scope === "project"
        ? project ? `/v1/orgs/${encodeURIComponent(org)}/projects/${encodeURIComponent(project)}/policy` : ""
        : keyId ? `/v1/keys/${encodeURIComponent(keyId)}/policy` : ""

  useEffect(() => {
    api(`/v1/orgs/${encodeURIComponent(org)}/projects`)
      .then((data) => {
        const next = data.projects || []
        setProjects(next)
        setProject((current) => next.some((item: ProjectRow) => item.slug === current) ? current : next[0]?.slug || "")
      })
      .catch((e: any) => setError(e.message))
  }, [org])

  useEffect(() => {
    setKeys([])
    setKeyId("")
    if (!project) return
    Promise.all(
      ["dev", "prod"].map((env) =>
        api(`/v1/secrets?org=${encodeURIComponent(org)}&project=${encodeURIComponent(project)}&env=${env}`),
      ),
    )
      .then((responses) => {
        const next = responses.flatMap((response) => response.secrets || [])
        setKeys(next)
        setKeyId(next[0]?.id || "")
      })
      .catch((e: any) => setError(e.message))
  }, [org, project])

  async function loadPolicy() {
    if (!endpoint) {
      setRecord(null)
      setDocument({ defaults: [], minimums: [] })
      setHistory([])
      return
    }
    setError("")
    try {
      const [current, versions] = await Promise.all([api(endpoint), api(`${endpoint}/history`)])
      setRecord(current)
      setDocument(current.document)
      setHistory(versions.history || [])
      setPreview(null)
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { loadPolicy() }, [endpoint])

  function updateDefault(index: number, changes: Partial<PolicyDefaultRow>) {
    setDocument((current) => ({
      ...current,
      defaults: current.defaults.map((row, rowIndex) => rowIndex === index ? { ...row, ...changes } : row),
    }))
  }

  function updateMinimum(index: number, changes: Partial<PolicyMinimumRow>) {
    setDocument((current) => ({
      ...current,
      minimums: current.minimums.map((row, rowIndex) => rowIndex === index ? { ...row, ...changes } : row),
    }))
  }

  function toggleTier(kind: "default" | "minimum", index: number, tier: ApprovalTier) {
    const rows = kind === "default" ? document.defaults : document.minimums
    const selected = new Set(rows[index].tiers || [])
    selected.has(tier) ? selected.delete(tier) : selected.add(tier)
    const tiers = (["normal", "elevated", "breakglass"] as ApprovalTier[]).filter((item) => selected.has(item))
    if (kind === "default") updateDefault(index, { tiers })
    else updateMinimum(index, { tiers })
  }

  async function save() {
    if (!record || !endpoint) return
    setError("")
    setMsg("")
    try {
      const saved = await api(endpoint, {
        method: "PUT",
        body: JSON.stringify({ document, expected_version: record.version }),
      })
      setRecord(saved)
      setDocument(saved.document)
      setMsg(`Policy v${saved.version} is active`)
      await loadPolicy()
    } catch (e: any) {
      setError(e.message)
    }
  }

  async function runPreview() {
    setError("")
    try {
      setPreview(await api("/v1/policies/preview", {
        method: "POST",
        body: JSON.stringify({
          org,
          ...(scope !== "org" ? { project } : {}),
          ...(scope === "key" && selectedKey ? { key_ref: selectedKey.ref } : {}),
          candidate_scope: scope,
          candidate: document,
          action: previewInput.action,
          actor_type: previewInput.actor_type,
          ...(previewInput.environment ? { environment: previewInput.environment } : {}),
        }),
      }))
    } catch (e: any) {
      setError(e.message)
    }
  }

  const editable = scope !== "org" || canOrg
  return (
    <section className="access-workspace">
      <div className="page-head">
        <div>
          <h2>Policy workspace</h2>
          <p className="muted">Set action outcomes by berth. Parent minimums always hold the stronger line.</p>
        </div>
        <span className="badge">v{record?.version ?? "—"}</span>
      </div>
      <div className="row">
        <div>
          <label>Policy scope</label>
          <select value={scope} onChange={(event) => setScope(event.target.value as typeof scope)}>
            <option value="org">organization</option>
            <option value="project">project</option>
            <option value="key">key</option>
          </select>
        </div>
        {scope !== "org" ? (
          <div>
            <label>Project</label>
            <select value={project} onChange={(event) => setProject(event.target.value)}>
              {projects.map((item) => <option key={item.id} value={item.slug}>{item.slug}</option>)}
            </select>
          </div>
        ) : null}
        {scope === "key" ? (
          <div>
            <label>Stable key ID</label>
            <select className="mono" value={keyId} onChange={(event) => setKeyId(event.target.value)}>
              {keys.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.id}</option>)}
            </select>
          </div>
        ) : null}
      </div>
      {error ? <p className="error">{error}</p> : null}
      {msg ? <p className="ok">{msg}</p> : null}

      <h3 style={{ marginTop: 28 }}>Action defaults</h3>
      <p className="muted">The most specific matching default chooses deny, automatic approval, or human approval.</p>
      <table>
        <thead><tr><th>Action</th><th>Actor</th><th>Outcome</th><th>Flow</th><th>Tiers</th><th></th></tr></thead>
        <tbody>
          {document.defaults.map((row, index) => (
            <tr key={`default-${index}`}>
              <td><input className="mono" value={row.action} onChange={(event) => updateDefault(index, { action: event.target.value })} /></td>
              <td>
                <select value={row.actor_type} onChange={(event) => updateDefault(index, { actor_type: event.target.value as PolicyActorType })}>
                  <option value="agent">agent</option><option value="human">human</option>
                </select>
              </td>
              <td>
                <select value={row.outcome} onChange={(event) => {
                  const outcome = event.target.value as PolicyDefaultRow["outcome"]
                  updateDefault(index, outcome === "approval_required"
                    ? { outcome, mode: row.mode || "threshold", tiers: row.tiers?.length ? row.tiers : ["normal"] }
                    : { outcome, mode: undefined, tiers: undefined })
                }}>
                  <option value="deny">deny</option>
                  <option value="auto_approve">auto approve</option>
                  <option value="approval_required">approval required</option>
                </select>
              </td>
              <td>{row.outcome === "approval_required" ? (
                <select value={row.mode || "threshold"} onChange={(event) => updateDefault(index, { mode: event.target.value as "threshold" | "sequential" })}>
                  <option value="threshold">threshold</option><option value="sequential">sequential</option>
                </select>
              ) : "—"}</td>
              <td>{row.outcome === "approval_required" ? (["normal", "elevated", "breakglass"] as ApprovalTier[]).map((tier) => (
                <label key={tier} style={{ display: "inline-block", marginRight: 8 }}>
                  <input type="checkbox" style={{ width: "auto" }} checked={row.tiers?.includes(tier) || false} onChange={() => toggleTier("default", index, tier)} /> {tier}
                </label>
              )) : "—"}</td>
              <td><button className="danger" type="button" onClick={() => setDocument({ ...document, defaults: document.defaults.filter((_, rowIndex) => rowIndex !== index) })}>Remove</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="secondary" type="button" onClick={() => setDocument({
        ...document,
        defaults: [...document.defaults, { action: "keys.resolve", actor_type: "agent", outcome: "deny" }],
      })}>Add action default</button>

      <h3 style={{ marginTop: 32 }}>Minimum constraints</h3>
      <p className="muted">Minimums accumulate across organization, project, and key; children cannot lower them.</p>
      <table>
        <thead><tr><th>Action</th><th>Actor</th><th>Minimum</th><th>Flow</th><th>Tiers</th><th></th></tr></thead>
        <tbody>
          {document.minimums.map((row, index) => (
            <tr key={`minimum-${index}`}>
              <td><input className="mono" value={row.action} onChange={(event) => updateMinimum(index, { action: event.target.value })} /></td>
              <td>
                <select value={row.actor_type} onChange={(event) => updateMinimum(index, { actor_type: event.target.value as PolicyActorType })}>
                  <option value="agent">agent</option><option value="human">human</option>
                </select>
              </td>
              <td>
                <select value={row.min} onChange={(event) => {
                  const min = event.target.value as PolicyMinimumRow["min"]
                  updateMinimum(index, min === "auto" || min === "deny"
                    ? { min, mode: undefined, tiers: undefined }
                    : { min, mode: row.mode || "threshold", tiers: row.tiers?.length ? row.tiers : [min] })
                }}>
                  <option value="auto">auto</option><option value="normal">normal</option>
                  <option value="elevated">elevated</option><option value="breakglass">breakglass</option>
                  <option value="deny">deny</option>
                </select>
              </td>
              <td>{row.min !== "auto" && row.min !== "deny" ? (
                <select value={row.mode || "threshold"} onChange={(event) => updateMinimum(index, { mode: event.target.value as "threshold" | "sequential" })}>
                  <option value="threshold">threshold</option><option value="sequential">sequential</option>
                </select>
              ) : "—"}</td>
              <td>{row.min !== "auto" && row.min !== "deny" ? (["normal", "elevated", "breakglass"] as ApprovalTier[]).map((tier) => (
                <label key={tier} style={{ display: "inline-block", marginRight: 8 }}>
                  <input type="checkbox" style={{ width: "auto" }} checked={row.tiers?.includes(tier) || false} onChange={() => toggleTier("minimum", index, tier)} /> {tier}
                </label>
              )) : "—"}</td>
              <td><button className="danger" type="button" onClick={() => setDocument({ ...document, minimums: document.minimums.filter((_, rowIndex) => rowIndex !== index) })}>Remove</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="secondary" type="button" onClick={() => setDocument({
        ...document,
        minimums: [...document.minimums, { action: "keys.reveal", actor_type: "human", min: "normal", mode: "threshold", tiers: ["normal"] }],
      })}>Add minimum</button>

      <h3 style={{ marginTop: 32 }}>Preview candidate</h3>
      <div className="row">
        <div><label>Action</label><input className="mono" value={previewInput.action} onChange={(event) => setPreviewInput({ ...previewInput, action: event.target.value })} /></div>
        <div><label>Actor type</label><select value={previewInput.actor_type} onChange={(event) => setPreviewInput({ ...previewInput, actor_type: event.target.value as PolicyActorType })}><option value="agent">agent</option><option value="human">human</option></select></div>
        <div><label>Berth</label><select value={previewInput.environment} onChange={(event) => setPreviewInput({ ...previewInput, environment: event.target.value })}><option value="dev">dev</option><option value="prod">prod</option></select></div>
      </div>
      <div className="row access-actions">
        <button className="secondary" type="button" onClick={runPreview}>Preview effective policy</button>
        {editable ? <button className="primary" type="button" onClick={save} disabled={!record}>Activate policy</button> : null}
      </div>
      {preview ? (
        <div className="flash">
          <strong>{preview.outcome}</strong>
          <span className="muted"> · {preview.reason}{preview.mode ? ` · ${preview.mode}` : ""}{preview.tiers?.length ? ` · ${preview.tiers.join(" → ")}` : ""}</span>
          {(preview.warnings || []).map((warning: any) => <p className="error" key={warning.code}>⚓ {warning.message}</p>)}
        </div>
      ) : null}

      <h3 style={{ marginTop: 32 }}>Version history</h3>
      <table>
        <thead><tr><th>Version</th><th>Activated</th><th>Operator</th></tr></thead>
        <tbody>{history.map((item) => <tr key={item.version}><td>v{item.version}</td><td className="mono">{item.created_at}</td><td>{item.created_by}</td></tr>)}</tbody>
      </table>
      {scope !== "org" && !selectedProject ? <p className="muted">Choose a project to chart policy.</p> : null}
    </section>
  )
}

function Agents({ org }: { org: string }) {
  const [agents, setAgents] = useState<any[]>([])
  const [grants, setGrants] = useState<any[]>([])
  const [error, setError] = useState("")
  const [form, setForm] = useState({ name: "", owner: "root", purpose: "", scopes: "secrets:read" })

  async function load() {
    const query = `org=${encodeURIComponent(org)}`
    const [a, g] = await Promise.all([api(`/v1/agents?${query}`), api(`/v1/resources?${query}`)])
    setAgents(a.agents || [])
    setGrants(g.grants || [])
  }
  useEffect(() => { load().catch((e) => setError(e.message)) }, [org])

  async function create(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    await api("/v1/agents", {
      method: "POST",
      body: JSON.stringify({
        org,
        name: form.name,
        owner: form.owner,
        purpose: form.purpose,
        risk_tier: "medium",
        scopes: form.scopes.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    })
    await load()
  }

  async function revoke(id: string) {
    await api(`/v1/agents/${id}/revoke`, { method: "POST", body: JSON.stringify({ org }) })
    await load()
  }

  return (
    <section>
      <h2>Agents</h2>
      <p className="muted">Agents knock for clearance. Standing mint is superadmin-only via API.</p>
      {error ? <p className="error">{error}</p> : null}
      <table>
        <thead><tr><th>Name</th><th>Status</th><th>Scopes</th><th></th></tr></thead>
        <tbody>
          {agents.map((a) => (
            <tr key={a.id}>
              <td>{a.name} <span className="badge">{a.risk_tier}</span></td>
              <td>{a.status}</td>
              <td className="mono">{(a.scopes || []).join(", ")}</td>
              <td><button className="danger" type="button" onClick={() => revoke(a.id)}>Revoke</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2 style={{ marginTop: 32 }}>Register agent</h2>
      <form onSubmit={create}>
        <label>Name</label>
        <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        <label>Purpose</label>
        <input value={form.purpose} onChange={(e) => setForm({ ...form, purpose: e.target.value })} required />
        <label>Scopes (comma)</label>
        <input className="mono" value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} />
        <button className="primary" type="submit">Create</button>
      </form>
      <h2 style={{ marginTop: 32 }}>Issued grants</h2>
      <table>
        <thead><tr><th>Agent</th><th>Resource</th></tr></thead>
        <tbody>
          {grants.map((g) => (
            <tr key={`${g.agent_id}:${g.resource}`}>
              <td className="mono">{g.agent_id}</td>
              <td className="mono">{g.resource}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function ApiKeys({ org }: { org: string }) {
  const [keys, setKeys] = useState<any[]>([])
  const [name, setName] = useState("activity")
  const [minted, setMinted] = useState("")
  const [error, setError] = useState("")

  async function load() {
    try {
      setKeys((await api(`/v1/api-keys?org=${encodeURIComponent(org)}`)).keys || [])
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { load() }, [org])

  async function mint(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    try {
      const data = await api("/v1/api-keys", { method: "POST", body: JSON.stringify({ org, name }) })
      setMinted(data.token)
      await load()
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div>
      <p className="muted">
        Activity-only. Cannot resolve secrets. Bearer <span className="mono">haven_ak_…</span>
      </p>
      {minted ? <div className="flash"><div>Key (shown once)</div><div className="mono">{minted}</div></div> : null}
      {error ? <p className="error">{error}</p> : null}
      <form onSubmit={mint} className="row">
        <div>
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <button className="primary" type="submit">Mint key</button>
      </form>
      <table>
        <thead><tr><th>Name</th><th>Prefix</th><th>Status</th></tr></thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.id}>
              <td>{k.name}</td>
              <td className="mono">{k.token_prefix}</td>
              <td>{k.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Logbook({ org }: { org: string }) {
  const [events, setEvents] = useState<Record<string, unknown>[]>([])
  const [error, setError] = useState("")

  async function load() {
    setError("")
    try {
      const data = await api(`/v1/ledger?org=${encodeURIComponent(org)}&limit=100`)
      setEvents((data.events || []).map((e: unknown) => sanitizeLedgerEvent(e)))
    } catch (e: any) {
      setError(e.message)
    }
  }
  useEffect(() => { load() }, [org])

  return (
    <section>
      <h2>Logbook</h2>
      <p className="muted">Who knocked, who was cleared, who was denied. Values never appear.</p>
      <button className="secondary" type="button" onClick={load}>Refresh</button>
      {error ? <p className="error">{error}</p> : null}
      <table>
        <thead><tr><th>Time</th><th>Type</th><th>Outcome</th><th>Actor</th><th>Resource</th></tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={String(e.id)}>
              <td className="mono">{String(e.ts || "")}</td>
              <td>{String(e.type || "")}</td>
              <td>{String(e.outcome || "")}</td>
              <td className="mono">{String(e.actor || e.agent_id || "")}</td>
              <td className="mono">{String(e.resource || "")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

function Account() {
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState("")
  const [msg, setMsg] = useState("")
  const [error, setError] = useState("")

  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setMsg("")
    try {
      await api("/v1/me/password", { method: "POST", body: JSON.stringify({ current, next }) })
      setCurrent("")
      setNext("")
      setMsg("Password updated")
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div>
      <p className="muted">Change your password. 12+ characters.</p>
      <form onSubmit={save}>
        <label>Current password</label>
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        <label>New password</label>
        <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
        <button className="primary" type="submit">Update password</button>
      </form>
      {msg ? <p className="ok">{msg}</p> : null}
      {error ? <p className="error">{error}</p> : null}
    </div>
  )
}
