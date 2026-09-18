/**
 * Haven in-process store: orgs, projects, encrypted keys, humans, knock, ledger.
 */
import { Database } from "bun:sqlite"
import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto"
import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs"
import { join } from "node:path"
import {
  approveAccessRequest as approveStoredAccessRequest,
  cancelAccessRequest as cancelStoredAccessRequest,
  createAccessRequest as createStoredAccessRequest,
  denyAccessRequest as denyStoredAccessRequest,
  escalateAccessRequest as escalateStoredAccessRequest,
  listAccessRequests as listStoredAccessRequests,
  type AccessRequestFilter,
  type AccessRequestWorkflowStore,
  type CreateAccessRequestInput,
} from "./access_requests.ts"
import {
  assignmentScope,
  evaluateHumanAuthorization,
  type AccessAssignment,
  type AccessAssignmentEffect,
  type ResourceLocator,
} from "./authorization.ts"
import {
  evaluatePolicy as evaluateActionPolicy,
  guardrailToActionPolicy,
  validatePolicyDocument,
} from "./action_policy.ts"
import { canaryDigest, generatePackageKeyPair, signWatchPackage } from "./canary_crypto.ts"
import { decrypt, encrypt, parseRootKey } from "./crypto.ts"
import { ledgerEventHash, verifyLedgerContents } from "./ledger_integrity.ts"
import { isPermission, permissionAllowsScope } from "./permissions.ts"
import {
  DEFAULT_GUARDRAIL,
  type AccessRequest,
  type AccessRequestEvent,
  type ActionPolicyDocument,
  type ActionPolicyRecord,
  type Agent,
  type AgentStatus,
  type Guardrail,
  type Human,
  type HumanRole,
  type KeyMeta,
  type Knock,
  type KnockNeed,
  type KnockStatus,
  type LedgerEvent,
  type OnExposure,
  type Org,
  type PolicyActorType,
  type PolicyDefault,
  type Project,
  type RiskTier,
} from "./types.ts"

const PLACEHOLDERS = new Set(["dev-only-change-me", "dev-admin-change-me"])
const ACTIVITY_SCOPES = ["activity:write", "activity:read"] as const
const ACTIVITY_TYPE = /^(activity|log)\.[A-Za-z0-9._-]{1,64}$/
const OUTCOMES = new Set(["success", "denied", "error", "info"])
const SESSION_COOKIE = "haven_session"
const SESSION_TTL = 8 * 3600
const TOKEN_PREFIX = "haven_"
const API_KEY_PREFIX = "haven_ak_"
const BUOY_TOKEN_PREFIX = "haven_buoy_"
const BUOY_KINDS = new Set(["harbor", "custom"])
const WATCH_AUDIENCES = new Set(["harbor", "custom", "all"])

export type HavenOpts = {
  dataDir: string
  tokenSecret: string
  rootKeyHex: string
  canaryPepperHex?: string
  bootstrapUser?: string
  bootstrapPassword?: string
  bootstrapOrg?: string
  uiDist?: string
}

export type ApiKeyRecord = {
  id: string
  name: string
  org_id: string | null
  token_prefix: string
  scopes: string[]
  status: "active" | "revoked"
  created_at: string
  revoked_at: string | null
}

export type Buoy = {
  id: string
  org_id: string
  kind: "harbor" | "custom"
  name: string
  status: "active" | "revoked"
  last_seen_at: string | null
  created_at: string
}

export type Canary = {
  id: string
  org_id: string
  project_id: string | null
  key_ref: string | null
  mode: "decoy_key" | "sibling"
  digest: string
  status: "active" | "revoked"
  planted_at: string
  revoked_at: string | null
}

export type Sighting = {
  id: string
  buoy_id: string
  canary_id: string
  digest: string
  observed_at: string
  received_at: string
  context: Record<string, unknown>
  ledger_event_id: string | null
}

export type Remediation = {
  id: string
  canary_id: string
  key_ref: string | null
  sighting_id: string
  status: "open" | "rotated" | "dismissed"
  on_exposure_applied: OnExposure
  opened_at: string
  closed_at: string | null
}

export type SightingPayload = {
  buoy_id: string
  canary_id: string
  digest: string
  observed_at: string
  context: {
    host?: string
    path?: string
    source: "file" | "env" | "process" | "network" | "other"
    detail?: string
  }
}

export type KnockInput = {
  org: string
  project: string
  agent_name: string
  purpose: string
  need: KnockNeed[]
  ttl_seconds?: number
}

export type KnockResult = Knock & {
  token?: string
  ttl_seconds?: number
  expires_at?: string
}

function now() {
  return new Date().toISOString()
}

function id(prefix: string) {
  return `${prefix}_${randomBytes(12).toString("hex")}`
}

function hashToken(raw: string) {
  return createHash("sha256").update(raw).digest("hex")
}

function parseGuardrail(raw: string | null | undefined): Guardrail {
  if (!raw) return { ...DEFAULT_GUARDRAIL }
  try {
    const g = JSON.parse(raw) as Guardrail
    return {
      default: (["deny", "allow", "approve"] as PolicyDefault[]).includes(g.default) ? g.default : "deny",
      allow_agents: Array.isArray(g.allow_agents) ? g.allow_agents.map(String) : [],
      allow_actions: Array.isArray(g.allow_actions) ? g.allow_actions.map(String) : ["secrets:read"],
      max_ttl_seconds: Math.min(Math.max(Number(g.max_ttl_seconds) || 900, 60), 3600),
      require_approval: Boolean(g.require_approval),
      on_exposure: (["block", "queue", "observe"] as OnExposure[]).includes(g.on_exposure as OnExposure)
        ? (g.on_exposure as OnExposure)
        : "queue",
    }
  } catch {
    return { ...DEFAULT_GUARDRAIL }
  }
}

export function keyRef(org: string, project: string, env: string, name: string) {
  return `haven://${org}/${project}/${env}/${name}`
}

export function parseKeyRef(resource: string): { org: string; project: string; env: string; name: string } | null {
  const m = /^haven:\/\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/.exec(resource.trim())
  if (!m) return null
  return { org: m[1], project: m[2], env: m[3], name: m[4] }
}

export function evaluatePolicy(g: Guardrail, agentName: string, action: string): "allow" | "deny" | "approve" {
  if (g.allow_agents.length && !g.allow_agents.includes("*") && !g.allow_agents.includes(agentName)) {
    return "deny"
  }
  if (g.allow_actions.length && !g.allow_actions.includes("*") && !g.allow_actions.includes(action)) {
    return "deny"
  }
  if (g.require_approval) return "approve"
  return g.default
}

function stripSecretFields(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripSecretFields)
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (k === "value" || k === "secretValue" || k === "client_secret" || k === "token") continue
      out[k] = stripSecretFields(val)
    }
    return out
  }
  return v
}

function requiredSecret(name: string, value: string | undefined) {
  const v = value?.trim() ?? ""
  if (!v || PLACEHOLDERS.has(v)) {
    throw new Error(`Missing or insecure required configuration: ${name}`)
  }
  return v
}

export async function createHaven(opts: HavenOpts) {
  const dataDir = opts.dataDir
  const tokenSecret = requiredSecret("HAVEN_TOKEN_SECRET", opts.tokenSecret)
  const rootKey = parseRootKey(opts.rootKeyHex)
  const canaryPepperHex = opts.canaryPepperHex?.trim().toLowerCase()
  if (canaryPepperHex && !/^[0-9a-f]{64}$/.test(canaryPepperHex)) {
    throw new Error("HAVEN_CANARY_PEPPER must be 32-byte hex")
  }
  if (canaryPepperHex === rootKey.toString("hex")) {
    throw new Error("HAVEN_CANARY_PEPPER must differ from HAVEN_ROOT_ENCRYPTION_KEY")
  }
  const bootstrapOrg = (opts.bootstrapOrg || "demo").trim() || "demo"
  const uiDist = opts.uiDist || ""

  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  chmodSync(dataDir, 0o700)
  const dbPath = join(dataDir, "haven.db")
  const ledgerPath = join(dataDir, "ledger.jsonl")
  const db = new Database(dbPath, { create: true })
  chmodSync(dbPath, 0o600)
  const fd = openSync(ledgerPath, "a", 0o600)
  closeSync(fd)
  chmodSync(ledgerPath, 0o600)

  const migrateSchema = db.transaction(() => {
    db.exec(`
      CREATE TABLE IF NOT EXISTS orgs (
      id TEXT PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      guardrail_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      slug TEXT NOT NULL,
      name TEXT NOT NULL,
      guardrail_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(org_id, slug),
      FOREIGN KEY(org_id) REFERENCES orgs(id)
    );
    CREATE TABLE IF NOT EXISTS keys (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      env TEXT NOT NULL,
      name TEXT NOT NULL,
      version INTEGER NOT NULL,
      ciphertext BLOB NOT NULL,
      guardrail_json TEXT,
      updated_at TEXT NOT NULL,
      UNIQUE(project_id, env, name),
      FOREIGN KEY(project_id) REFERENCES projects(id)
    );
    CREATE TABLE IF NOT EXISTS humans (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_root INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS memberships (
      user_id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      role TEXT NOT NULL,
      PRIMARY KEY (user_id, org_id),
      FOREIGN KEY(user_id) REFERENCES humans(id),
      FOREIGN KEY(org_id) REFERENCES orgs(id)
    );
    CREATE TABLE IF NOT EXISTS access_assignments (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      project_id TEXT,
      key_id TEXT,
      permission TEXT NOT NULL,
      effect TEXT NOT NULL CHECK(effect IN ('allow','deny')),
      reason TEXT NOT NULL,
      grantor_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT,
      revoked_at TEXT,
      revoked_by TEXT,
      FOREIGN KEY(user_id) REFERENCES humans(id),
      FOREIGN KEY(org_id) REFERENCES orgs(id)
    );
    CREATE INDEX IF NOT EXISTS idx_access_assignments_user_org
      ON access_assignments(user_id, org_id);
    CREATE TABLE IF NOT EXISTS action_policies (
      id TEXT PRIMARY KEY,
      scope_type TEXT NOT NULL CHECK(scope_type IN ('org','project','key')),
      scope_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      document_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      created_by TEXT NOT NULL,
      UNIQUE(scope_type, scope_id, version)
    );
    CREATE INDEX IF NOT EXISTS idx_action_policies_scope_version
      ON action_policies(scope_type, scope_id, version DESC);
    CREATE TABLE IF NOT EXISTS access_requests (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT,
      key_id TEXT,
      action TEXT NOT NULL,
      actor_type TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      requester_human_id TEXT,
      agent_owner_human_id TEXT,
      mode TEXT NOT NULL,
      tiers_json TEXT NOT NULL,
      stage_index INTEGER NOT NULL,
      status TEXT NOT NULL,
      policy_version INTEGER NOT NULL,
      policy_snapshot_json TEXT NOT NULL,
      policy_reason TEXT NOT NULL,
      reason_required INTEGER NOT NULL DEFAULT 0,
      max_token_ttl_seconds INTEGER,
      reason TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT,
      resolved_at TEXT,
      consumed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_access_requests_org_status
      ON access_requests(org_id, status, created_at DESC);
    CREATE TABLE IF NOT EXISTS access_request_events (
      id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      type TEXT NOT NULL,
      actor_human_id TEXT NOT NULL,
      tier TEXT,
      reason TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(request_id) REFERENCES access_requests(id)
    );
    CREATE INDEX IF NOT EXISTS idx_access_request_events_request
      ON access_request_events(request_id, created_at, id);
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      owner TEXT NOT NULL,
      purpose TEXT NOT NULL,
      org_id TEXT,
      project_id TEXT,
      risk_tier TEXT NOT NULL,
      scopes_json TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      revoked_at TEXT,
      first_seen_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tokens (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      scopes_json TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(agent_id) REFERENCES agents(id)
    );
    CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
    CREATE TABLE IF NOT EXISTS resource_grants (
      agent_id TEXT NOT NULL,
      resource TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (agent_id, resource),
      FOREIGN KEY(agent_id) REFERENCES agents(id)
    );
    CREATE TABLE IF NOT EXISTS knocks (
      id TEXT PRIMARY KEY,
      access_request_id TEXT,
      org_slug TEXT NOT NULL,
      project_slug TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      purpose TEXT NOT NULL,
      need_json TEXT NOT NULL,
      status TEXT NOT NULL,
      decision_reason TEXT NOT NULL,
      agent_id TEXT,
      created_at TEXT NOT NULL,
      resolved_at TEXT
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      org_id TEXT,
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      scopes_json TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(token_hash);
    CREATE TABLE IF NOT EXISTS buoys (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL,
      credential_hash TEXT NOT NULL,
      last_seen_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(org_id) REFERENCES orgs(id)
    );
    CREATE TABLE IF NOT EXISTS canaries (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      project_id TEXT,
      key_ref TEXT,
      mode TEXT NOT NULL,
      ciphertext BLOB NOT NULL,
      digest TEXT NOT NULL,
      status TEXT NOT NULL,
      planted_at TEXT NOT NULL,
      revoked_at TEXT,
      FOREIGN KEY(org_id) REFERENCES orgs(id),
      FOREIGN KEY(project_id) REFERENCES projects(id)
    );
    CREATE TABLE IF NOT EXISTS watch_packages (
      id TEXT PRIMARY KEY,
      version INTEGER NOT NULL UNIQUE,
      audience TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      published_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sightings (
      id TEXT PRIMARY KEY,
      buoy_id TEXT NOT NULL,
      canary_id TEXT NOT NULL,
      digest TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      received_at TEXT NOT NULL,
      context_json TEXT NOT NULL,
      ledger_event_id TEXT,
      FOREIGN KEY(buoy_id) REFERENCES buoys(id),
      FOREIGN KEY(canary_id) REFERENCES canaries(id)
    );
    CREATE TABLE IF NOT EXISTS remediations (
      id TEXT PRIMARY KEY,
      canary_id TEXT NOT NULL,
      key_ref TEXT,
      sighting_id TEXT NOT NULL,
      status TEXT NOT NULL,
      on_exposure_applied TEXT NOT NULL,
      opened_at TEXT NOT NULL,
      closed_at TEXT,
      FOREIGN KEY(canary_id) REFERENCES canaries(id),
      FOREIGN KEY(sighting_id) REFERENCES sightings(id)
    );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_remediations_open_canary
        ON remediations(canary_id) WHERE status = 'open';
    `)
    const keyColumns = db.query(`PRAGMA table_info(keys)`).all() as Array<{ name: string }>
    if (!keyColumns.some((column) => column.name === "exposure_blocked_at")) {
      db.exec(`ALTER TABLE keys ADD COLUMN exposure_blocked_at TEXT`)
    }
    const humanColumns = db.query(`PRAGMA table_info(humans)`).all() as Array<{ name: string }>
    if (!humanColumns.some((column) => column.name === "is_root")) {
      db.exec(`ALTER TABLE humans ADD COLUMN is_root INTEGER NOT NULL DEFAULT 0`)
    }
    const apiKeyColumns = db.query(`PRAGMA table_info(api_keys)`).all() as Array<{ name: string }>
    if (!apiKeyColumns.some((column) => column.name === "org_id")) {
      db.exec(`ALTER TABLE api_keys ADD COLUMN org_id TEXT`)
    }
    const knockColumns = db.query(`PRAGMA table_info(knocks)`).all() as Array<{ name: string }>
    if (!knockColumns.some((column) => column.name === "access_request_id")) {
      db.exec(`ALTER TABLE knocks ADD COLUMN access_request_id TEXT`)
    }
    const accessRequestColumns = db.query(`PRAGMA table_info(access_requests)`).all() as Array<{ name: string }>
    if (!accessRequestColumns.some((column) => column.name === "reason_required")) {
      db.exec(`ALTER TABLE access_requests ADD COLUMN reason_required INTEGER NOT NULL DEFAULT 0`)
    }
    if (!accessRequestColumns.some((column) => column.name === "max_token_ttl_seconds")) {
      db.exec(`ALTER TABLE access_requests ADD COLUMN max_token_ttl_seconds INTEGER`)
    }
    if (!accessRequestColumns.some((column) => column.name === "policy_reason")) {
      db.exec(`ALTER TABLE access_requests ADD COLUMN policy_reason TEXT NOT NULL DEFAULT 'policy approval required'`)
    }
    if (!accessRequestColumns.some((column) => column.name === "consumed_at")) {
      db.exec(`ALTER TABLE access_requests ADD COLUMN consumed_at TEXT`)
    }

    let bootstrapRow = db.query(`SELECT id FROM orgs WHERE slug = ?`).get(bootstrapOrg) as { id: string } | null
    if (!bootstrapRow) {
      bootstrapRow = { id: id("org") }
      db.query(`INSERT INTO orgs (id, slug, name, guardrail_json, created_at) VALUES (?, ?, ?, ?, ?)`).run(
        bootstrapRow.id,
        bootstrapOrg,
        bootstrapOrg,
        JSON.stringify(DEFAULT_GUARDRAIL),
        now(),
      )
    }
    db.query(`UPDATE api_keys SET org_id = ? WHERE org_id IS NULL`).run(bootstrapRow.id)
  })
  migrateSchema()

  const packagePublicKeyPath = join(dataDir, "watch-package-public.der")
  const packagePrivateKeyPath = join(dataDir, "watch-package-private.der")
  let packagePublicKey: KeyObject
  let packagePrivateKey: KeyObject
  function generateAndPersistPackageKeyPair() {
    const generated = generatePackageKeyPair()
    const suffix = randomBytes(8).toString("hex")
    const publicTempPath = `${packagePublicKeyPath}.${suffix}.tmp`
    const privateTempPath = `${packagePrivateKeyPath}.${suffix}.tmp`
    writeFileSync(publicTempPath, generated.publicKey.export({ format: "der", type: "spki" }), { mode: 0o600 })
    writeFileSync(privateTempPath, generated.privateKey.export({ format: "der", type: "pkcs8" }), { mode: 0o600 })
    renameSync(privateTempPath, packagePrivateKeyPath)
    renameSync(publicTempPath, packagePublicKeyPath)
    return generated
  }
  if (existsSync(packagePublicKeyPath) && existsSync(packagePrivateKeyPath)) {
    try {
      packagePublicKey = createPublicKey({
        key: readFileSync(packagePublicKeyPath),
        format: "der",
        type: "spki",
      })
      packagePrivateKey = createPrivateKey({
        key: readFileSync(packagePrivateKeyPath),
        format: "der",
        type: "pkcs8",
      })
      const derivedPublicKey = createPublicKey(packagePrivateKey)
      const loadedPublicDer = packagePublicKey.export({ format: "der", type: "spki" })
      const derivedPublicDer = derivedPublicKey.export({ format: "der", type: "spki" })
      if (!Buffer.from(loadedPublicDer).equals(Buffer.from(derivedPublicDer))) {
        throw new Error("watch_package_keypair_mismatch")
      }
    } catch {
      const generated = generateAndPersistPackageKeyPair()
      packagePublicKey = generated.publicKey
      packagePrivateKey = generated.privateKey
    }
  } else {
    const generated = generateAndPersistPackageKeyPair()
    packagePublicKey = generated.publicKey
    packagePrivateKey = generated.privateKey
  }
  chmodSync(packagePublicKeyPath, 0o600)
  chmodSync(packagePrivateKeyPath, 0o600)

  function signPayload(payload: string) {
    return createHmac("sha256", tokenSecret).update(payload).digest("base64url")
  }

  function ledgerAppend(
    type: string,
    opts: {
      agent_id?: string | null
      actor?: string
      resource?: string | null
      action?: string | null
      outcome?: LedgerEvent["outcome"]
      detail?: Record<string, unknown>
    } = {},
  ): LedgerEvent {
    const contents = existsSync(ledgerPath) ? readFileSync(ledgerPath, "utf8") : ""
    let prev_hash: string | null = null
    const lastLine = contents.trimEnd().split("\n").at(-1)
    if (lastLine) {
      try {
        const lastEvent = JSON.parse(lastLine) as { hash?: unknown }
        if (typeof lastEvent.hash === "string" && /^[0-9a-f]{64}$/.test(lastEvent.hash)) {
          prev_hash = lastEvent.hash
        }
      } catch {
        // A malformed predecessor is not trusted as a chain head.
      }
    }
    const payload: Omit<LedgerEvent, "hash"> = {
      id: id("led"),
      ts: now(),
      type,
      agent_id: opts.agent_id ?? null,
      actor: opts.actor ?? "system",
      resource: opts.resource ?? null,
      action: opts.action ?? null,
      outcome: opts.outcome ?? "info",
      detail: stripSecretFields(opts.detail ?? {}) as Record<string, unknown>,
      prev_hash,
    }
    const event: LedgerEvent = { ...payload, hash: ledgerEventHash(payload) }
    const separator = contents && !contents.endsWith("\n") ? "\n" : ""
    appendFileSync(ledgerPath, separator + JSON.stringify(event) + "\n")
    return event
  }

  function verifyLedger() {
    return verifyLedgerContents(existsSync(ledgerPath) ? readFileSync(ledgerPath, "utf8") : "")
  }

  function ledgerList(limit = 50, agentId?: string): LedgerEvent[] {
    if (!existsSync(ledgerPath)) return []
    const lines = readFileSync(ledgerPath, "utf8").trim().split("\n").filter(Boolean)
    const events: LedgerEvent[] = []
    for (let i = lines.length - 1; i >= 0 && events.length < limit; i--) {
      try {
        const e = JSON.parse(lines[i]) as LedgerEvent
        if (agentId && e.agent_id !== agentId) continue
        events.push({ ...e, detail: stripSecretFields(e.detail || {}) as Record<string, unknown> })
      } catch {
        /* skip */
      }
    }
    return events
  }

  function ledgerListForOrg(orgId: string, limit = 50, agentId?: string): LedgerEvent[] {
    const org = getOrg(orgId)
    if (!org || !existsSync(ledgerPath)) return []
    const bootstrapOrgId = getOrgBySlug(bootstrapOrg)?.id
    const lines = readFileSync(ledgerPath, "utf8").trim().split("\n").filter(Boolean)
    const events: LedgerEvent[] = []
    for (let i = lines.length - 1; i >= 0 && events.length < limit; i--) {
      try {
        const event = JSON.parse(lines[i]) as LedgerEvent
        if (agentId && event.agent_id !== agentId) continue
        const detail = event.detail || {}
        let eventOrgId = typeof detail.org_id === "string" ? detail.org_id : null
        if (!eventOrgId && event.agent_id) eventOrgId = getAgent(event.agent_id)?.org_id ?? null
        if (!eventOrgId && event.resource) {
          const parsed = parseKeyRef(event.resource)
          eventOrgId = parsed ? (getOrgBySlug(parsed.org)?.id ?? null) : null
        }
        if (!eventOrgId && typeof detail.api_key_id === "string") {
          const apiKey = db.query(`SELECT org_id FROM api_keys WHERE id = ?`).get(detail.api_key_id) as {
            org_id: string | null
          } | null
          eventOrgId = apiKey?.org_id ?? null
        }
        if (!eventOrgId && typeof detail.buoy_id === "string") {
          const buoy = db.query(`SELECT org_id FROM buoys WHERE id = ?`).get(detail.buoy_id) as {
            org_id: string
          } | null
          eventOrgId = buoy?.org_id ?? null
        }
        if (!eventOrgId && typeof detail.canary_id === "string") {
          const canary = db.query(`SELECT org_id FROM canaries WHERE id = ?`).get(detail.canary_id) as {
            org_id: string
          } | null
          eventOrgId = canary?.org_id ?? null
        }
        if (!eventOrgId && typeof detail.knock_id === "string") {
          const knock = db.query(`SELECT org_slug FROM knocks WHERE id = ?`).get(detail.knock_id) as {
            org_slug: string
          } | null
          eventOrgId = knock ? (getOrgBySlug(knock.org_slug)?.id ?? null) : null
        }
        if (eventOrgId ? eventOrgId !== orgId : orgId !== bootstrapOrgId) continue
        events.push({ ...event, detail: stripSecretFields(detail) as Record<string, unknown> })
      } catch {
        /* skip */
      }
    }
    return events
  }

  function rowToOrg(r: any): Org {
    return {
      id: r.id,
      slug: r.slug,
      name: r.name,
      guardrail: parseGuardrail(r.guardrail_json),
      created_at: r.created_at,
    }
  }

  function rowToProject(r: any): Project {
    return {
      id: r.id,
      org_id: r.org_id,
      slug: r.slug,
      name: r.name,
      guardrail: parseGuardrail(r.guardrail_json),
      created_at: r.created_at,
    }
  }

  function rowToAgent(r: any): Agent {
    return {
      id: r.id,
      name: r.name,
      owner: r.owner,
      purpose: r.purpose,
      org_id: r.org_id,
      project_id: r.project_id,
      risk_tier: r.risk_tier as RiskTier,
      scopes: JSON.parse(r.scopes_json),
      status: r.status as AgentStatus,
      created_at: r.created_at,
      updated_at: r.updated_at,
      revoked_at: r.revoked_at,
      first_seen_at: r.first_seen_at,
    }
  }

  function rowToKnock(r: any): Knock {
    return {
      id: r.id,
      access_request_id: r.access_request_id ?? null,
      org_slug: r.org_slug,
      project_slug: r.project_slug,
      agent_name: r.agent_name,
      purpose: r.purpose,
      need: JSON.parse(r.need_json),
      status: r.status as KnockStatus,
      decision_reason: r.decision_reason,
      agent_id: r.agent_id,
      created_at: r.created_at,
      resolved_at: r.resolved_at,
    }
  }

  function listOrgs(): Org[] {
    return db.query(`SELECT * FROM orgs ORDER BY slug`).all().map(rowToOrg)
  }

  function getOrgBySlug(slug: string): Org | null {
    const r = db.query(`SELECT * FROM orgs WHERE slug = ?`).get(slug) as any
    return r ? rowToOrg(r) : null
  }

  function getOrg(orgId: string): Org | null {
    const r = db.query(`SELECT * FROM orgs WHERE id = ?`).get(orgId) as any
    return r ? rowToOrg(r) : null
  }

  function createOrg(slug: string, name: string): Org {
    const org: Org = {
      id: id("org"),
      slug,
      name,
      guardrail: { ...DEFAULT_GUARDRAIL },
      created_at: now(),
    }
    db.query(`INSERT INTO orgs (id, slug, name, guardrail_json, created_at) VALUES (?,?,?,?,?)`).run(
      org.id,
      org.slug,
      org.name,
      JSON.stringify(org.guardrail),
      org.created_at,
    )
    return org
  }

  function createProject(orgId: string, slug: string, name: string): Project {
    const p: Project = {
      id: id("prj"),
      org_id: orgId,
      slug,
      name,
      guardrail: { ...DEFAULT_GUARDRAIL },
      created_at: now(),
    }
    db.query(
      `INSERT INTO projects (id, org_id, slug, name, guardrail_json, created_at) VALUES (?,?,?,?,?,?)`,
    ).run(p.id, p.org_id, p.slug, p.name, JSON.stringify(p.guardrail), p.created_at)
    return p
  }

  function listProjects(orgSlug: string): Project[] {
    const org = getOrgBySlug(orgSlug)
    if (!org) return []
    return db.query(`SELECT * FROM projects WHERE org_id = ? ORDER BY slug`).all(org.id).map(rowToProject)
  }

  function getProject(orgSlug: string, projectSlug: string): Project | null {
    const org = getOrgBySlug(orgSlug)
    if (!org) return null
    const r = db.query(`SELECT * FROM projects WHERE org_id = ? AND slug = ?`).get(org.id, projectSlug) as any
    return r ? rowToProject(r) : null
  }

  const EMPTY_ACTION_POLICY: ActionPolicyDocument = { defaults: [], minimums: [] }

  function rowToActionPolicy(row: any): ActionPolicyRecord {
    let document: ActionPolicyDocument = EMPTY_ACTION_POLICY
    try {
      const parsed = JSON.parse(row.document_json)
      if (validatePolicyDocument(parsed)) document = parsed
    } catch {
      // Corrupt persisted policy remains fail closed through an empty document.
    }
    return {
      scope_type: row.scope_type,
      scope_id: row.scope_id,
      version: row.version,
      document: structuredClone(document),
      created_at: row.created_at,
      created_by: row.created_by,
    }
  }

  function latestStoredPolicy(
    scopeType: ActionPolicyRecord["scope_type"],
    scopeId: string,
  ): ActionPolicyRecord | null {
    const row = db
      .query(
        `SELECT * FROM action_policies
         WHERE scope_type = ? AND scope_id = ?
         ORDER BY version DESC LIMIT 1`,
      )
      .get(scopeType, scopeId) as any
    return row ? rowToActionPolicy(row) : null
  }

  function listPolicyHistory(
    scopeType: ActionPolicyRecord["scope_type"],
    scopeId: string,
  ): ActionPolicyRecord[] {
    return (
      db
        .query(
          `SELECT * FROM action_policies
           WHERE scope_type = ? AND scope_id = ?
           ORDER BY version DESC`,
        )
        .all(scopeType, scopeId) as any[]
    ).map(rowToActionPolicy)
  }

  function syntheticPolicy(
    scopeType: ActionPolicyRecord["scope_type"],
    scopeId: string,
    document: ActionPolicyDocument,
    createdAt: string,
  ): ActionPolicyRecord {
    return {
      scope_type: scopeType,
      scope_id: scopeId,
      version: 0,
      document: structuredClone(document),
      created_at: createdAt,
      created_by: "legacy_guardrail_adapter",
    }
  }

  function policyScopeLedgerContext(
    scopeType: ActionPolicyRecord["scope_type"],
    scopeId: string,
  ): { org_id: string; resource: string } {
    if (scopeType === "org") {
      const row = db.query(`SELECT id, slug FROM orgs WHERE id = ?`).get(scopeId) as {
        id: string
        slug: string
      } | null
      if (!row) throw new Error("org_not_found")
      return { org_id: row.id, resource: `haven://${row.slug}` }
    }
    if (scopeType === "project") {
      const row = db
        .query(
          `SELECT p.id, p.slug AS project_slug, o.id AS org_id, o.slug AS org_slug
           FROM projects p JOIN orgs o ON o.id = p.org_id WHERE p.id = ?`,
        )
        .get(scopeId) as { org_id: string; org_slug: string; project_slug: string } | null
      if (!row) throw new Error("project_not_found")
      return { org_id: row.org_id, resource: `haven://${row.org_slug}/${row.project_slug}` }
    }
    const row = db
      .query(
        `SELECT k.env, k.name, p.slug AS project_slug, o.id AS org_id, o.slug AS org_slug
         FROM keys k
         JOIN projects p ON p.id = k.project_id
         JOIN orgs o ON o.id = p.org_id
         WHERE k.id = ?`,
      )
      .get(scopeId) as {
      org_id: string
      org_slug: string
      project_slug: string
      env: string
      name: string
    } | null
    if (!row) throw new Error("key_not_found")
    return {
      org_id: row.org_id,
      resource: keyRef(row.org_slug, row.project_slug, row.env, row.name),
    }
  }

  function getOrgPolicy(orgSlug: string): ActionPolicyRecord {
    const org = getOrgBySlug(orgSlug)
    if (!org) throw new Error("org_not_found")
    return (
      latestStoredPolicy("org", org.id) ??
      syntheticPolicy("org", org.id, guardrailToActionPolicy(org.guardrail), org.created_at)
    )
  }

  function getProjectPolicy(orgSlug: string, projectSlug: string): ActionPolicyRecord {
    const project = getProject(orgSlug, projectSlug)
    if (!project) throw new Error("project_not_found")
    const stored = latestStoredPolicy("project", project.id)
    if (stored) return stored
    const document =
      JSON.stringify(project.guardrail) === JSON.stringify(DEFAULT_GUARDRAIL)
        ? EMPTY_ACTION_POLICY
        : guardrailToActionPolicy(project.guardrail)
    return syntheticPolicy("project", project.id, document, project.created_at)
  }

  function getKeyPolicy(ref: string): ActionPolicyRecord {
    const parsed = parseKeyRef(ref)
    if (!parsed) throw new Error("bad_resource_uri")
    const row = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (!row) throw new Error("key_not_found")
    const stored = latestStoredPolicy("key", row.id)
    if (stored) return stored
    const document = row.guardrail_json
      ? guardrailToActionPolicy(parseGuardrail(row.guardrail_json))
      : EMPTY_ACTION_POLICY
    return syntheticPolicy("key", row.id, document, row.updated_at)
  }

  function writePolicy(
    scopeType: ActionPolicyRecord["scope_type"],
    scopeId: string,
    document: ActionPolicyDocument,
    expectedVersion: number,
    createdBy: string,
  ): ActionPolicyRecord {
    if (!validatePolicyDocument(document)) throw new Error("invalid_policy")
    if (!Number.isInteger(expectedVersion) || expectedVersion < 0) throw new Error("invalid_expected_version")
    const actor = createdBy.trim()
    if (!actor) throw new Error("created_by_required")
    return db.transaction(() => {
      const ledgerContext = policyScopeLedgerContext(scopeType, scopeId)
      const latest = latestStoredPolicy(scopeType, scopeId)
      const currentVersion = latest?.version ?? 0
      if (currentVersion !== expectedVersion) throw new Error("policy_version_conflict")
      const record: ActionPolicyRecord = {
        scope_type: scopeType,
        scope_id: scopeId,
        version: currentVersion + 1,
        document: structuredClone(document),
        created_at: now(),
        created_by: actor,
      }
      db.query(
        `INSERT INTO action_policies
         (id, scope_type, scope_id, version, document_json, created_at, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        id("pol"),
        record.scope_type,
        record.scope_id,
        record.version,
        JSON.stringify(record.document),
        record.created_at,
        record.created_by,
      )
      ledgerAppend("policy.activated", {
        actor,
        resource: ledgerContext.resource,
        outcome: "success",
        detail: {
          org_id: ledgerContext.org_id,
          scope_type: scopeType,
          scope_id: scopeId,
          policy_version: record.version,
        },
      })
      return record
    })()
  }

  function setOrgPolicy(
    orgSlug: string,
    document: ActionPolicyDocument,
    expectedVersion: number,
    createdBy: string,
  ): ActionPolicyRecord {
    const current = getOrgPolicy(orgSlug)
    return writePolicy("org", current.scope_id, document, expectedVersion, createdBy)
  }

  function setProjectPolicy(
    orgSlug: string,
    projectSlug: string,
    document: ActionPolicyDocument,
    expectedVersion: number,
    createdBy: string,
  ): ActionPolicyRecord {
    const current = getProjectPolicy(orgSlug, projectSlug)
    return writePolicy("project", current.scope_id, document, expectedVersion, createdBy)
  }

  function setKeyPolicy(
    ref: string,
    document: ActionPolicyDocument,
    expectedVersion: number,
    createdBy: string,
  ): ActionPolicyRecord {
    const current = getKeyPolicy(ref)
    return writePolicy("key", current.scope_id, document, expectedVersion, createdBy)
  }

  function previewPolicy(input: {
    org: string
    project?: string
    key_ref?: string
    candidate_scope?: ActionPolicyRecord["scope_type"]
    candidate?: ActionPolicyDocument
    action: string
    actor_type: PolicyActorType
    environment?: string
    agent_id?: string
  }) {
    if ((input.candidate === undefined) !== (input.candidate_scope === undefined)) {
      throw new Error("invalid_preview")
    }
    if (input.candidate && !validatePolicyDocument(input.candidate)) throw new Error("invalid_policy")
    if (
      (input.candidate_scope === "project" && !input.project) ||
      (input.candidate_scope === "key" && !input.key_ref)
    ) {
      throw new Error("policy_scope_mismatch")
    }
    if (input.key_ref) {
      const parsed = parseKeyRef(input.key_ref)
      if (!parsed || parsed.org !== input.org || (input.project !== undefined && parsed.project !== input.project)) {
        throw new Error("policy_scope_mismatch")
      }
    }
    const orgRecord = getOrgPolicy(input.org)
    const projectRecord = input.project ? getProjectPolicy(input.org, input.project) : null
    const keyRecord = input.key_ref ? getKeyPolicy(input.key_ref) : null
    const orgPolicy = input.candidate_scope === "org" && input.candidate ? input.candidate : orgRecord.document
    const projectPolicy =
      input.candidate_scope === "project" && input.candidate
        ? input.candidate
        : projectRecord?.document
    const keyPolicy =
      input.candidate_scope === "key" && input.candidate
        ? input.candidate
        : keyRecord?.document
    return evaluateActionPolicy({
      orgPolicy,
      projectPolicy,
      keyPolicy,
      action: input.action,
      actor_type: input.actor_type,
      environment: input.environment,
      agent_id: input.agent_id,
      policy_version: Math.max(orgRecord.version, projectRecord?.version ?? 0, keyRecord?.version ?? 0),
    })
  }

  function evaluateHumanKeyAction(input: {
    human_id: string
    action: "keys.reveal" | "keys.delete" | "keys.update"
    resource: string
  }) {
    const parsed = parseKeyRef(input.resource)
    if (!parsed) throw new Error("bad_resource_uri")
    const project = getProject(parsed.org, parsed.project)
    if (!project) throw new Error("project_not_found")
    const key = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (!key) throw new Error("key_not_found")
    if (!getHuman(input.human_id)) throw new Error("human_not_found")

    const decision = previewPolicy({
      org: parsed.org,
      project: parsed.project,
      key_ref: input.resource,
      action: input.action,
      actor_type: "human",
      environment: parsed.env,
    })
    if (decision.outcome !== "approval_required") return decision

    const candidates = db
      .query(
        `SELECT id, resolved_at, max_token_ttl_seconds
         FROM access_requests
         WHERE actor_type = 'human'
           AND actor_id = ?
           AND requester_human_id = ?
           AND action = ?
           AND key_id = ?
           AND status = 'approved'
           AND policy_version = ?
           AND policy_snapshot_json = ?
           AND consumed_at IS NULL
         ORDER BY resolved_at DESC, id DESC`,
      )
      .all(
        input.human_id,
        input.human_id,
        input.action,
        key.id,
        decision.policy_version,
        JSON.stringify(decision.snapshot),
      ) as Array<{
        id: string
        resolved_at: string | null
        max_token_ttl_seconds: number | null
      }>
    const currentTime = Date.parse(now())
    for (const candidate of candidates) {
      const resolvedTime = candidate.resolved_at ? Date.parse(candidate.resolved_at) : Number.NaN
      const ttlSeconds = Math.min(300, candidate.max_token_ttl_seconds ?? 300)
      if (!Number.isFinite(resolvedTime) || resolvedTime + ttlSeconds * 1000 <= currentTime) continue
      const consumedAt = now()
      const consumed = db
        .query(`UPDATE access_requests SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`)
        .run(consumedAt, candidate.id)
      if (consumed.changes !== 1) continue
      ledgerAppend("access_request.consumed", {
        actor: input.human_id,
        resource: input.resource,
        action: input.action,
        outcome: "success",
        detail: { access_request_id: candidate.id, key_id: key.id },
      })
      return {
        outcome: "auto_approve" as const,
        reason: "approved_request_consumed",
        policy_version: decision.policy_version,
        snapshot: decision.snapshot,
        access_request_id: candidate.id,
      }
    }
    return decision
  }

  function setOrgGuardrail(orgSlug: string, guardrail: Guardrail) {
    const org = getOrgBySlug(orgSlug)
    if (!org) throw new Error("org_not_found")
    const g = parseGuardrail(JSON.stringify(guardrail))
    db.query(`UPDATE orgs SET guardrail_json = ? WHERE id = ?`).run(JSON.stringify(g), org.id)
    const current = getOrgPolicy(orgSlug)
    writePolicy("org", org.id, guardrailToActionPolicy(g), current.version, "legacy_guardrail_adapter")
    ledgerAppend("guardrail.org", { resource: `haven://${orgSlug}`, outcome: "success", detail: { guardrail: g } })
    return { ...org, guardrail: g }
  }

  function setProjectGuardrail(orgSlug: string, projectSlug: string, guardrail: Guardrail) {
    const p = getProject(orgSlug, projectSlug)
    if (!p) throw new Error("project_not_found")
    const g = parseGuardrail(JSON.stringify(guardrail))
    db.query(`UPDATE projects SET guardrail_json = ? WHERE id = ?`).run(JSON.stringify(g), p.id)
    const current = getProjectPolicy(orgSlug, projectSlug)
    writePolicy("project", p.id, guardrailToActionPolicy(g), current.version, "legacy_guardrail_adapter")
    ledgerAppend("guardrail.project", {
      resource: `haven://${orgSlug}/${projectSlug}`,
      outcome: "success",
      detail: { guardrail: g },
    })
    return { ...p, guardrail: g }
  }

  function setKeyGuardrail(ref: string, guardrail: Guardrail | null) {
    const parsed = parseKeyRef(ref)
    if (!parsed) throw new Error("bad_resource_uri")
    const key = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (!key) throw new Error("key_not_found")
    const g = guardrail ? parseGuardrail(JSON.stringify(guardrail)) : null
    db.query(`UPDATE keys SET guardrail_json = ? WHERE id = ?`).run(g ? JSON.stringify(g) : null, key.id)
    const current = getKeyPolicy(ref)
    writePolicy(
      "key",
      key.id,
      g ? guardrailToActionPolicy(g) : EMPTY_ACTION_POLICY,
      current.version,
      "legacy_guardrail_adapter",
    )
    return listKeys(parsed.org, parsed.project, parsed.env).find((k) => k.name === parsed.name)!
  }

  function getKeyRow(org: string, project: string, env: string, name: string) {
    const p = getProject(org, project)
    if (!p) return null
    return db.query(`SELECT * FROM keys WHERE project_id = ? AND env = ? AND name = ?`).get(p.id, env, name) as any
  }

  function putKey(input: { org: string; project: string; env: string; name: string; value: string }) {
    const env = input.env === "prod" ? "prod" : "dev"
    const name = input.name.trim()
    if (!name || !input.value) throw new Error("name_and_value_required")
    let p = getProject(input.org, input.project)
    if (!p) {
      const org = getOrgBySlug(input.org)
      if (!org) throw new Error("org_not_found")
      p = createProject(org.id, input.project, input.project)
    }
    const existing = db
      .query(`SELECT * FROM keys WHERE project_id = ? AND env = ? AND name = ?`)
      .get(p.id, env, name) as any
    const blob = encrypt(input.value, rootKey)
    const ts = now()
    const ref = keyRef(input.org, p.slug, env, name)
    if (existing) {
      db.query(`UPDATE keys SET version = version + 1, ciphertext = ?, updated_at = ? WHERE id = ?`).run(
        blob,
        ts,
        existing.id,
      )
      ledgerAppend("secret.put", { resource: ref, outcome: "success", detail: { name, env, status: "updated" } })
      return { ok: true, ref, status: "updated" as const, version: existing.version + 1 }
    }
    const kid = id("key")
    db.query(
      `INSERT INTO keys (id, project_id, env, name, version, ciphertext, guardrail_json, updated_at)
       VALUES (?,?,?,?,?,?,NULL,?)`,
    ).run(kid, p.id, env, name, 1, blob, ts)
    ledgerAppend("secret.put", { resource: ref, outcome: "success", detail: { name, env, status: "created" } })
    return { ok: true, ref, status: "created" as const, version: 1 }
  }

  function listKeys(orgSlug: string, projectSlug: string, env: string): KeyMeta[] {
    const p = getProject(orgSlug, projectSlug)
    if (!p) return []
    const rows = db.query(`SELECT * FROM keys WHERE project_id = ? AND env = ? ORDER BY name`).all(p.id, env) as any[]
    return rows.map((r) => ({
      id: r.id,
      project_id: r.project_id,
      env: r.env,
      name: r.name,
      version: r.version,
      updated_at: r.updated_at,
      ref: keyRef(orgSlug, projectSlug, r.env, r.name),
      guardrail: r.guardrail_json ? parseGuardrail(r.guardrail_json) : null,
    }))
  }

  function readKeyValue(resource: string): string {
    const parsed = parseKeyRef(resource)
    if (!parsed) throw new Error("bad_resource_uri")
    const row = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (!row) throw new Error("key_not_found")
    return decrypt(Buffer.from(row.ciphertext), rootKey)
  }

  function revealKey(resource: string, actor: string) {
    const parsed = parseKeyRef(resource)
    if (!parsed) throw new Error("bad_resource_uri")
    const row = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (!row) throw new Error("key_not_found")
    const value = decrypt(Buffer.from(row.ciphertext), rootKey)
    ledgerAppend("secret.reveal", {
      actor,
      resource,
      outcome: "success",
      detail: { name: row.name, env: row.env, version: row.version },
    })
    return { ref: resource, value, version: row.version }
  }

  function deleteKey(resource: string, confirmName: string, actor: string) {
    const parsed = parseKeyRef(resource)
    if (!parsed) throw new Error("bad_resource_uri")
    const row = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (!row) throw new Error("key_not_found")
    if (confirmName !== row.name) throw new Error("confirmation_name_mismatch")
    const closedAt = now()
    db.transaction(() => {
      db.query(`DELETE FROM keys WHERE id = ?`).run(row.id)
      db.query(
        `UPDATE remediations
         SET status = 'dismissed', closed_at = ?
         WHERE key_ref = ? AND status = 'open'`,
      ).run(closedAt, resource)
    })()
    ledgerAppend("secret.delete", {
      actor,
      resource,
      outcome: "success",
      detail: { name: row.name, env: row.env, version: row.version },
    })
    return { ref: resource, deleted: true as const }
  }

  function effectiveGuardrail(org: Org, project: Project, keyGuardrail: Guardrail | null): Guardrail {
    if (keyGuardrail) return keyGuardrail
    if (project.guardrail && JSON.stringify(project.guardrail) !== JSON.stringify(DEFAULT_GUARDRAIL)) {
      return project.guardrail
    }
    // Project default-deny is still a real policy if org has been customized?
    // Spec: if key policy exists, use it; else project; else org; else deny.
    // Always have project and org rows. Use key if set, else project (even default), else org.
    // That would make project default-deny shadow org allow. Spec says "else project; else org".
    // Interpret: use most specific *set* policy. Project always has a row. Use project if it
    // differs from factory default OR if we treat project as always present.
    // Product: org allow should apply when project still factory-default.
    if (JSON.stringify(project.guardrail) !== JSON.stringify(DEFAULT_GUARDRAIL)) return project.guardrail
    return org.guardrail
  }

  async function createHuman(input: { username: string; password: string; orgId: string; role: HumanRole }) {
    const username = input.username.trim().toLowerCase()
    if (!username) throw new Error("invalid_human")
    const existing = db.query(`SELECT * FROM humans WHERE username = ?`).get(username) as any
    let humanId: string
    if (existing) {
      humanId = existing.id
    } else {
      if (input.password.length < 12) throw new Error("invalid_human")
      humanId = id("usr")
      const password_hash = await Bun.password.hash(input.password, "argon2id")
      db.query(`INSERT INTO humans (id, username, password_hash, created_at) VALUES (?,?,?,?)`).run(
        humanId,
        username,
        password_hash,
        now(),
      )
    }
    db.query(`INSERT INTO memberships (user_id, org_id, role) VALUES (?,?,?)
              ON CONFLICT(user_id, org_id) DO UPDATE SET role = excluded.role`).run(
      humanId,
      input.orgId,
      input.role,
    )
    return { id: humanId, username, created_at: now() } as Human
  }

  async function verifyPassword(username: string, password: string): Promise<Human | null> {
    const r = db.query(`SELECT * FROM humans WHERE username = ?`).get(username.trim().toLowerCase()) as any
    if (!r) return null
    const ok = await Bun.password.verify(password, r.password_hash)
    if (!ok) return null
    return { id: r.id, username: r.username, created_at: r.created_at }
  }

  async function changePassword(userId: string, current: string, next: string) {
    const r = db.query(`SELECT * FROM humans WHERE id = ?`).get(userId) as any
    if (!r) throw new Error("not_found")
    const ok = await Bun.password.verify(current, r.password_hash)
    if (!ok) throw new Error("invalid_password")
    if (!next || next.length < 12) throw new Error("invalid_human")
    const password_hash = await Bun.password.hash(next, "argon2id")
    db.query(`UPDATE humans SET password_hash = ? WHERE id = ?`).run(password_hash, userId)
    ledgerAppend("human.password_changed", { actor: r.username, outcome: "success" })
  }

  function roleFor(userId: string, orgId: string): HumanRole | null {
    const r = db.query(`SELECT role FROM memberships WHERE user_id = ? AND org_id = ?`).get(userId, orgId) as any
    return r ? (r.role as HumanRole) : null
  }

  function membershipsFor(userId: string) {
    return db
      .query(
        `SELECT m.role, o.slug, o.id as org_id, o.name FROM memberships m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = ?`,
      )
      .all(userId) as Array<{ role: HumanRole; slug: string; org_id: string; name: string }>
  }

  function getHuman(userId: string): Human | null {
    const r = db.query(`SELECT id, username, created_at FROM humans WHERE id = ?`).get(userId) as any
    return r || null
  }

  function getHumanByUsername(username: string): Human | null {
    const r = db
      .query(`SELECT id, username, created_at FROM humans WHERE username = ?`)
      .get(username.trim().toLowerCase()) as any
    return r || null
  }

  function listMembers(orgSlug: string) {
    const org = getOrgBySlug(orgSlug)
    if (!org) return []
    return db
      .query(
        `SELECT h.id, h.username, h.created_at, m.role FROM memberships m JOIN humans h ON h.id = m.user_id WHERE m.org_id = ? ORDER BY h.username`,
      )
      .all(org.id) as Array<{ id: string; username: string; created_at: string; role: HumanRole }>
  }

  async function addMember(
    orgSlug: string,
    input: { username: string; password: string; role: HumanRole },
  ): Promise<Human> {
    const org = getOrgBySlug(orgSlug)
    if (!org) throw new Error("org_not_found")
    return createHuman({ ...input, orgId: org.id })
  }

  function rowToAccessAssignment(row: any): AccessAssignment {
    return {
      id: row.id,
      user_id: row.user_id,
      org_id: row.org_id,
      project_id: row.project_id,
      key_id: row.key_id,
      permission: row.permission,
      effect: row.effect,
      reason: row.reason,
      grantor_id: row.grantor_id,
      created_at: row.created_at,
      expires_at: row.expires_at,
      revoked_at: row.revoked_at,
      revoked_by: row.revoked_by,
    }
  }

  function isProtectedRoot(userId: string, orgId: string): boolean {
    const human = db.query(`SELECT is_root FROM humans WHERE id = ?`).get(userId) as { is_root: number } | null
    return human?.is_root === 1 && roleFor(userId, orgId) === "superadmin"
  }

  function preventRootLockout(
    userId: string,
    orgId: string,
    permission: string,
    actorId: string,
  ): never {
    ledgerAppend("access.lockout_prevented", {
      actor: actorId,
      action: permission,
      outcome: "denied",
      detail: { user_id: userId, org_id: orgId },
    })
    throw new Error("lockout_prevented")
  }

  function grantAccessAssignment(input: {
    user_id: string
    org_id: string
    project_id?: string | null
    key_id?: string | null
    permission: string
    effect: AccessAssignmentEffect
    reason: string
    grantor_id: string
    expires_at?: string | null
  }): AccessAssignment {
    if (!isPermission(input.permission)) throw new Error("invalid_permission")
    if (input.effect !== "allow" && input.effect !== "deny") throw new Error("invalid_effect")
    const reason = input.reason.trim()
    if (!reason) throw new Error("reason_required")
    if (!getOrg(input.org_id)) throw new Error("org_not_found")
    if (!getHuman(input.user_id) || !roleFor(input.user_id, input.org_id)) throw new Error("member_not_found")
    if (!getHuman(input.grantor_id)) throw new Error("grantor_not_found")

    const projectId = input.project_id ?? null
    const keyId = input.key_id ?? null
    const scope = assignmentScope({ project_id: projectId, key_id: keyId })
    if (!scope || !permissionAllowsScope(input.permission, scope)) throw new Error("invalid_assignment_scope")
    if (projectId) {
      const project = db.query(`SELECT id FROM projects WHERE id = ? AND org_id = ?`).get(projectId, input.org_id)
      if (!project) throw new Error("project_not_found")
    }
    if (keyId) {
      const key = db.query(`SELECT id FROM keys WHERE id = ? AND project_id = ?`).get(keyId, projectId)
      if (!key) throw new Error("key_not_found")
    }
    const expiresAt = input.expires_at ?? null
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) throw new Error("invalid_expiry")

    if (
      input.effect === "deny" &&
      isProtectedRoot(input.user_id, input.org_id) &&
      (input.permission === "org.members.manage" || input.permission === "org.permissions.manage")
    ) {
      preventRootLockout(input.user_id, input.org_id, input.permission, input.grantor_id)
    }

    const assignment: AccessAssignment = {
      id: id("asg"),
      user_id: input.user_id,
      org_id: input.org_id,
      project_id: projectId,
      key_id: keyId,
      permission: input.permission,
      effect: input.effect,
      reason,
      grantor_id: input.grantor_id,
      created_at: now(),
      expires_at: expiresAt,
      revoked_at: null,
      revoked_by: null,
    }
    db.query(
      `INSERT INTO access_assignments
       (id, user_id, org_id, project_id, key_id, permission, effect, reason, grantor_id, created_at, expires_at, revoked_at, revoked_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)`,
    ).run(
      assignment.id,
      assignment.user_id,
      assignment.org_id,
      assignment.project_id,
      assignment.key_id,
      assignment.permission,
      assignment.effect,
      assignment.reason,
      assignment.grantor_id,
      assignment.created_at,
      assignment.expires_at,
    )
    ledgerAppend("access.granted", {
      actor: assignment.grantor_id,
      action: assignment.permission,
      outcome: "success",
      detail: {
        assignment_id: assignment.id,
        user_id: assignment.user_id,
        org_id: assignment.org_id,
        project_id: assignment.project_id,
        key_id: assignment.key_id,
        effect: assignment.effect,
        expires_at: assignment.expires_at,
      },
    })
    return assignment
  }

  function listAccessAssignments(userId?: string, orgId?: string): AccessAssignment[] {
    if (userId && orgId) {
      return (
        db
          .query(`SELECT * FROM access_assignments WHERE user_id = ? AND org_id = ? ORDER BY created_at, id`)
          .all(userId, orgId) as any[]
      ).map(rowToAccessAssignment)
    }
    if (userId) {
      return (
        db.query(`SELECT * FROM access_assignments WHERE user_id = ? ORDER BY created_at, id`).all(userId) as any[]
      ).map(rowToAccessAssignment)
    }
    if (orgId) {
      return (
        db.query(`SELECT * FROM access_assignments WHERE org_id = ? ORDER BY created_at, id`).all(orgId) as any[]
      ).map(rowToAccessAssignment)
    }
    return (db.query(`SELECT * FROM access_assignments ORDER BY created_at, id`).all() as any[]).map(
      rowToAccessAssignment,
    )
  }

  function revokeAccessAssignment(
    assignmentId: string,
    input: { revoked_by: string; reason: string },
  ): AccessAssignment {
    const row = db.query(`SELECT * FROM access_assignments WHERE id = ?`).get(assignmentId) as any
    if (!row) throw new Error("assignment_not_found")
    const assignment = rowToAccessAssignment(row)
    if (assignment.revoked_at) return assignment
    const reason = input.reason.trim()
    if (!reason) throw new Error("reason_required")
    if (!getHuman(input.revoked_by)) throw new Error("revoker_not_found")
    if (
      assignment.effect === "allow" &&
      isProtectedRoot(assignment.user_id, assignment.org_id) &&
      (assignment.permission === "org.members.manage" || assignment.permission === "org.permissions.manage")
    ) {
      preventRootLockout(assignment.user_id, assignment.org_id, assignment.permission, input.revoked_by)
    }
    const revokedAt = now()
    db.query(`UPDATE access_assignments SET revoked_at = ?, revoked_by = ? WHERE id = ?`).run(
      revokedAt,
      input.revoked_by,
      assignment.id,
    )
    ledgerAppend("access.revoked", {
      actor: input.revoked_by,
      action: assignment.permission,
      outcome: "success",
      detail: {
        assignment_id: assignment.id,
        user_id: assignment.user_id,
        org_id: assignment.org_id,
      },
    })
    return { ...assignment, revoked_at: revokedAt, revoked_by: input.revoked_by }
  }

  function authorizeHuman(userId: string, permission: string, resource: ResourceLocator) {
    const decisionId = id("dec")
    const projectValid =
      !resource.projectId ||
      Boolean(db.query(`SELECT id FROM projects WHERE id = ? AND org_id = ?`).get(resource.projectId, resource.orgId))
    const keyValid =
      !resource.keyId ||
      Boolean(db.query(`SELECT id FROM keys WHERE id = ? AND project_id = ?`).get(resource.keyId, resource.projectId))
    const validResource = Boolean(getOrg(resource.orgId)) && projectValid && keyValid
    return evaluateHumanAuthorization({
      decisionId,
      permission,
      resource: validResource ? resource : { orgId: "" },
      role: validResource ? roleFor(userId, resource.orgId) : null,
      assignments: validResource ? listAccessAssignments(userId, resource.orgId) : [],
    })
  }

  function explainAccess(userId: string, permission: string, resource: ResourceLocator) {
    return authorizeHuman(userId, permission, resource)
  }

  function rowToAccessRequestEvent(row: any): AccessRequestEvent {
    return {
      id: row.id,
      request_id: row.request_id,
      type: row.type,
      actor_human_id: row.actor_human_id,
      tier: row.tier,
      reason: row.reason,
      created_at: row.created_at,
    }
  }

  function rowToAccessRequest(row: any): AccessRequest {
    return {
      id: row.id,
      org_id: row.org_id,
      project_id: row.project_id,
      key_id: row.key_id,
      action: row.action,
      actor_type: row.actor_type,
      actor_id: row.actor_id,
      requester_human_id: row.requester_human_id,
      agent_owner_human_id: row.agent_owner_human_id,
      mode: row.mode,
      tiers: JSON.parse(row.tiers_json),
      stage_index: row.stage_index,
      status: row.status,
      policy_version: row.policy_version,
      policy_snapshot: JSON.parse(row.policy_snapshot_json),
      policy_reason: row.policy_reason,
      reason_required: row.reason_required === 1,
      max_token_ttl_seconds: row.max_token_ttl_seconds,
      reason: row.reason,
      created_at: row.created_at,
      expires_at: row.expires_at,
      resolved_at: row.resolved_at,
      events: (
        db
          .query(`SELECT * FROM access_request_events WHERE request_id = ? ORDER BY created_at, id`)
          .all(row.id) as any[]
      ).map(rowToAccessRequestEvent),
    }
  }

  const accessRequestStore: AccessRequestWorkflowStore = {
    now,
    id,
    transaction: <T>(operation: () => T) => db.transaction(operation)(),
    insertRequest: (request) => {
      db.query(
        `INSERT INTO access_requests
         (id, org_id, project_id, key_id, action, actor_type, actor_id, requester_human_id,
          agent_owner_human_id, mode, tiers_json, stage_index, status, policy_version,
          policy_snapshot_json, policy_reason, reason_required, max_token_ttl_seconds, reason, created_at,
          expires_at, resolved_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        request.id,
        request.org_id,
        request.project_id,
        request.key_id,
        request.action,
        request.actor_type,
        request.actor_id,
        request.requester_human_id,
        request.agent_owner_human_id,
        request.mode,
        JSON.stringify(request.tiers),
        request.stage_index,
        request.status,
        request.policy_version,
        JSON.stringify(request.policy_snapshot),
        request.policy_reason,
        request.reason_required ? 1 : 0,
        request.max_token_ttl_seconds,
        request.reason,
        request.created_at,
        request.expires_at,
        request.resolved_at,
      )
    },
    updateRequest: (request, expectedStatus, expectedStage) => {
      const result = db
        .query(
          `UPDATE access_requests
           SET tiers_json = ?, stage_index = ?, status = ?, resolved_at = ?
           WHERE id = ? AND status = ? AND stage_index = ?`,
        )
        .run(
          JSON.stringify(request.tiers),
          request.stage_index,
          request.status,
          request.resolved_at,
          request.id,
          expectedStatus,
          expectedStage,
        )
      if (result.changes !== 1) throw new Error("request_conflict")
    },
    getRequest: (requestId) => {
      const row = db.query(`SELECT * FROM access_requests WHERE id = ?`).get(requestId) as any
      return row ? rowToAccessRequest(row) : null
    },
    listRequests: (filter) => {
      const clauses: string[] = []
      const values: Array<string | null> = []
      for (const [column, value] of Object.entries(filter ?? {}) as Array<
        [keyof AccessRequestFilter, string | null | undefined]
      >) {
        if (value === undefined) continue
        if (value === null) clauses.push(`${column} IS NULL`)
        else {
          clauses.push(`${column} = ?`)
          values.push(value)
        }
      }
      const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : ""
      return (
        db.query(`SELECT * FROM access_requests${where} ORDER BY created_at DESC, id DESC`).all(...values) as any[]
      ).map(rowToAccessRequest)
    },
    insertEvent: (accessEvent) => {
      db.query(
        `INSERT INTO access_request_events
         (id, request_id, type, actor_human_id, tier, reason, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        accessEvent.id,
        accessEvent.request_id,
        accessEvent.type,
        accessEvent.actor_human_id,
        accessEvent.tier,
        accessEvent.reason,
        accessEvent.created_at,
      )
    },
    authorizeHuman,
    ledger: (type, request, actorHumanId, reason, tier) => {
      ledgerAppend(type, {
        actor: actorHumanId ?? request.actor_id,
        action: request.action,
        outcome:
          request.status === "denied" || request.status === "auto_denied" || request.status === "expired"
            ? "denied"
            : request.status === "approved" || request.status === "auto_approved"
              ? "success"
              : "info",
        detail: {
          access_request_id: request.id,
          org_id: request.org_id,
          project_id: request.project_id,
          key_id: request.key_id,
          policy_version: request.policy_version,
          status: request.status,
          stage_index: request.stage_index,
          tier: tier ?? null,
          reason: reason ?? null,
        },
      })
    },
  }

  function createAccessRequest(input: CreateAccessRequestInput) {
    if (!getOrg(input.org_id)) throw new Error("org_not_found")
    if (
      input.project_id &&
      !db.query(`SELECT id FROM projects WHERE id = ? AND org_id = ?`).get(input.project_id, input.org_id)
    ) {
      throw new Error("invalid_resource")
    }
    if (
      input.key_id &&
      (!input.project_id ||
        !db.query(`SELECT id FROM keys WHERE id = ? AND project_id = ?`).get(input.key_id, input.project_id))
    ) {
      throw new Error("invalid_resource")
    }
    return createStoredAccessRequest(accessRequestStore, input)
  }

  function approveAccessRequest(
    requestId: string,
    input: { actor_human_id: string; reason?: string | null },
  ) {
    return approveStoredAccessRequest(accessRequestStore, requestId, input)
  }

  function denyAccessRequest(
    requestId: string,
    input: { actor_human_id: string; reason?: string | null },
  ) {
    return denyStoredAccessRequest(accessRequestStore, requestId, input)
  }

  function escalateAccessRequest(
    requestId: string,
    input: { actor_human_id: string; tier: "normal" | "elevated" | "breakglass"; reason: string },
  ) {
    return escalateStoredAccessRequest(accessRequestStore, requestId, input)
  }

  function cancelAccessRequest(
    requestId: string,
    input: { actor_human_id: string; reason: string },
  ) {
    return cancelStoredAccessRequest(accessRequestStore, requestId, input)
  }

  function listAccessRequests(filter?: AccessRequestFilter) {
    return listStoredAccessRequests(accessRequestStore, filter)
  }

  function canReadKeyValues(userId: string, orgId: string) {
    const role = roleFor(userId, orgId)
    return role === "superadmin" || role === "admin"
  }

  function canWriteOrgGuardrail(userId: string, orgId: string) {
    return roleFor(userId, orgId) === "superadmin"
  }

  function canApprove(userId: string, orgId: string) {
    const role = roleFor(userId, orgId)
    return role === "superadmin" || role === "admin" || role === "user"
  }

  function canWriteKeys(userId: string, orgId: string) {
    return canReadKeyValues(userId, orgId)
  }

  function canCreateProject(userId: string, orgId: string) {
    const role = roleFor(userId, orgId)
    return role === "superadmin" || role === "admin"
  }

  function mintSessionCookie(userId: string): string {
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL
    const nonce = randomBytes(16).toString("hex")
    const payload = `${exp}.${userId}.${nonce}`
    const sig = createHmac("sha256", tokenSecret).update(`sess|${payload}`).digest("base64url")
    return `${SESSION_COOKIE}=${payload}.${sig}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`
  }

  function clearSessionCookie(): string {
    return `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
  }

  function sessionUserId(req: Request): string | null {
    const header = req.headers.get("cookie") || ""
    const part = header
      .split(";")
      .map((s) => s.trim())
      .find((s) => s.startsWith(`${SESSION_COOKIE}=`))
    if (!part) return null
    const value = part.slice(`${SESSION_COOKIE}=`.length)
    const dot = value.lastIndexOf(".")
    if (dot < 0) return null
    const payload = value.slice(0, dot)
    const sig = value.slice(dot + 1)
    const expect = createHmac("sha256", tokenSecret).update(`sess|${payload}`).digest("base64url")
    const a = Buffer.from(sig)
    const b = Buffer.from(expect)
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null
    const [expStr, userId] = payload.split(".")
    const exp = Number(expStr)
    if (!exp || exp * 1000 <= Date.now() || !userId) return null
    return getHuman(userId) ? userId : null
  }

  function getAgent(agentId: string): Agent | null {
    const r = db.query(`SELECT * FROM agents WHERE id = ?`).get(agentId) as any
    return r ? rowToAgent(r) : null
  }

  function getAgentByName(name: string): Agent | null {
    const r = db.query(`SELECT * FROM agents WHERE name = ?`).get(name) as any
    return r ? rowToAgent(r) : null
  }

  function listAgents(): Agent[] {
    return db.query(`SELECT * FROM agents ORDER BY created_at DESC`).all().map(rowToAgent)
  }

  function createAgent(input: {
    name: string
    owner: string
    purpose: string
    risk_tier: RiskTier
    scopes: string[]
    org_id?: string | null
    project_id?: string | null
  }): Agent {
    const ts = now()
    const agent: Agent = {
      id: id("agt"),
      name: input.name,
      owner: input.owner,
      purpose: input.purpose,
      org_id: input.org_id ?? null,
      project_id: input.project_id ?? null,
      risk_tier: input.risk_tier,
      scopes: [...new Set(input.scopes)],
      status: "active",
      created_at: ts,
      updated_at: ts,
      revoked_at: null,
      first_seen_at: ts,
    }
    db.query(
      `INSERT INTO agents (id,name,owner,purpose,org_id,project_id,risk_tier,scopes_json,status,created_at,updated_at,revoked_at,first_seen_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(
      agent.id,
      agent.name,
      agent.owner,
      agent.purpose,
      agent.org_id,
      agent.project_id,
      agent.risk_tier,
      JSON.stringify(agent.scopes),
      agent.status,
      agent.created_at,
      agent.updated_at,
      null,
      agent.first_seen_at,
    )
    ledgerAppend("agent.created", {
      agent_id: agent.id,
      actor: agent.owner,
      outcome: "success",
      detail: { name: agent.name, risk_tier: agent.risk_tier, scopes: agent.scopes },
    })
    return agent
  }

  function revokeAgent(agentId: string): Agent | null {
    const agent = getAgent(agentId)
    if (!agent) return null
    const ts = now()
    db.query(`UPDATE agents SET status='revoked', revoked_at=?, updated_at=? WHERE id=?`).run(ts, ts, agentId)
    db.query(`UPDATE tokens SET revoked_at=? WHERE agent_id=? AND revoked_at IS NULL`).run(ts, agentId)
    ledgerAppend("agent.revoked", { agent_id: agentId, outcome: "success" })
    return getAgent(agentId)
  }

  function resolveAgentRef(agentIdOrName: string): Agent | null {
    return getAgent(agentIdOrName) || getAgentByName(agentIdOrName)
  }

  function resourceMatchesAgentScope(agent: Agent, resource: string): boolean {
    if (!agent.org_id) return false
    const org = getOrg(agent.org_id)
    if (!org) return false
    const project = agent.project_id
      ? (db.query(`SELECT slug FROM projects WHERE id = ? AND org_id = ?`).get(agent.project_id, agent.org_id) as {
          slug: string
        } | null)
      : null
    const prefix = project ? `haven://${org.slug}/${project.slug}/` : `haven://${org.slug}/`
    return resource.startsWith(prefix)
  }

  function mintToken(
    agentIdOrName: string,
    ttlSeconds: number,
    scopes?: string[],
    grantRefs?: string[],
    authorizedOrgId?: string,
  ) {
    let agent = resolveAgentRef(agentIdOrName)
    if (!agent) throw new Error("agent_not_found")
    if (agent.status !== "active") throw new Error("agent_revoked")
    if (grantRefs?.length && (!agent.org_id || !agent.project_id)) {
      const scopes = grantRefs.map((resource) => /^haven:\/\/([^/]+)\/([^/]+)\//.exec(resource))
      if (scopes.some((scope) => !scope)) throw new Error("resource_scope_mismatch")
      const [orgSlug, projectSlug] = scopes[0]!.slice(1)
      if (scopes.some((scope) => scope![1] !== orgSlug || scope![2] !== projectSlug)) {
        throw new Error("resource_scope_mismatch")
      }
      const org = getOrgBySlug(orgSlug)
      const project = getProject(orgSlug, projectSlug)
      if (!org || !project) throw new Error("resource_scope_mismatch")
      if ((agent.org_id && agent.org_id !== org.id) || (agent.project_id && agent.project_id !== project.id)) {
        throw new Error("resource_scope_mismatch")
      }
      db.query(`UPDATE agents SET org_id = ?, project_id = ?, updated_at = ? WHERE id = ?`).run(
        org.id,
        project.id,
        now(),
        agent.id,
      )
      agent = getAgent(agent.id)!
    }
    if (authorizedOrgId && agent.org_id !== authorizedOrgId) throw new Error("agent_scope_mismatch")
    const ttl = Math.min(Math.max(ttlSeconds || 900, 60), 3600)
    const want = scopes?.length ? scopes : agent.scopes
    for (const s of want) {
      if (!agent.scopes.includes(s) && !agent.scopes.includes("*")) throw new Error(`scope_not_granted:${s}`)
    }
    for (const resource of grantRefs ?? []) {
      if (!resource.startsWith("haven://") || !resourceMatchesAgentScope(agent, resource)) {
        throw new Error("resource_scope_mismatch")
      }
    }
    const tokenId = id("tok")
    const exp = new Date(Date.now() + ttl * 1000).toISOString()
    const payload = `${tokenId}.${agent.id}.${exp}.${want.join(",")}`
    const sig = signPayload(payload)
    const raw = `${TOKEN_PREFIX}${Buffer.from(payload).toString("base64url")}.${sig}`
    db.query(
      `INSERT INTO tokens (id,agent_id,token_hash,scopes_json,expires_at,revoked_at,created_at)
       VALUES (?,?,?,?,?,?,?)`,
    ).run(tokenId, agent.id, hashToken(raw), JSON.stringify(want), exp, null, now())
    if (grantRefs) {
      for (const resource of grantRefs) {
        db.query(
          `INSERT INTO resource_grants (agent_id, resource, created_at) VALUES (?, ?, ?)
           ON CONFLICT(agent_id, resource) DO NOTHING`,
        ).run(agent.id, resource, now())
      }
    }
    ledgerAppend("token.minted", {
      agent_id: agent.id,
      outcome: "success",
      detail: { token_id: tokenId, ttl_seconds: ttl, scopes: want, expires_at: exp },
    })
    return { token: raw, token_id: tokenId, agent_id: agent.id, expires_at: exp, scopes: want, ttl_seconds: ttl }
  }

  function introspectToken(raw: string) {
    const row = db.query(`SELECT * FROM tokens WHERE token_hash = ?`).get(hashToken(raw)) as any
    if (!row) return { active: false as const, reason: "unknown" }
    if (row.revoked_at) return { active: false as const, reason: "revoked", token_id: row.id, agent_id: row.agent_id }
    if (new Date(row.expires_at).getTime() <= Date.now())
      return { active: false as const, reason: "expired", token_id: row.id, agent_id: row.agent_id }
    const agent = getAgent(row.agent_id)
    if (!agent || agent.status !== "active")
      return { active: false as const, reason: "agent_inactive", token_id: row.id, agent_id: row.agent_id }
    if (!raw.startsWith(TOKEN_PREFIX)) return { active: false as const, reason: "malformed" }
    const body = raw.slice(TOKEN_PREFIX.length)
    const dot = body.lastIndexOf(".")
    if (dot < 0) return { active: false as const, reason: "malformed" }
    const payloadB64 = body.slice(0, dot)
    const sig = body.slice(dot + 1)
    const payload = Buffer.from(payloadB64, "base64url").toString("utf8")
    const expect = signPayload(payload)
    const a = Buffer.from(sig)
    const b = Buffer.from(expect)
    if (a.length !== b.length || !timingSafeEqual(a, b)) return { active: false as const, reason: "bad_signature" }
    return {
      active: true as const,
      token_id: row.id,
      agent_id: row.agent_id,
      scopes: JSON.parse(row.scopes_json) as string[],
      expires_at: row.expires_at,
      agent_name: agent.name,
      risk_tier: agent.risk_tier,
    }
  }

  function revokeToken(raw: string) {
    const hsh = hashToken(raw)
    const row = db.query(`SELECT * FROM tokens WHERE token_hash = ?`).get(hsh) as any
    if (!row) return null
    db.query(`UPDATE tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL`).run(now(), hsh)
    ledgerAppend("token.revoked", { agent_id: row.agent_id, outcome: "success", detail: { token_id: row.id } })
    return { revoked: true, token_id: row.id }
  }

  function authorize(raw: string, action: string, resource: string) {
    const intro = introspectToken(raw)
    if (!intro.active) {
      const event = ledgerAppend("authz.deny", {
        agent_id: (intro as any).agent_id ?? null,
        action,
        resource,
        outcome: "denied",
        detail: { reason: intro.reason },
      })
      return { allow: false, reason: intro.reason || "inactive_token", decision_id: event.id }
    }
    const scopes = intro.scopes || []
    const allowed =
      scopes.includes(action) ||
      scopes.includes("*") ||
      scopes.some((s) => s.endsWith(":*") && action.startsWith(s.slice(0, -1)))
    if (!allowed) {
      const event = ledgerAppend("authz.deny", {
        agent_id: intro.agent_id,
        action,
        resource,
        outcome: "denied",
        detail: { reason: "scope_missing", have: scopes },
      })
      return { allow: false, reason: "scope_missing", agent_id: intro.agent_id, decision_id: event.id }
    }
    const event = ledgerAppend("authz.allow", {
      agent_id: intro.agent_id,
      action,
      resource,
      outcome: "success",
      detail: { risk_tier: intro.risk_tier, scopes },
    })
    return {
      allow: true,
      reason: "ok",
      agent_id: intro.agent_id,
      agent_name: intro.agent_name,
      risk_tier: intro.risk_tier,
      decision_id: event.id,
    }
  }

  function grantResource(agentId: string, resource: string) {
    const a = getAgent(agentId) || getAgentByName(agentId)
    if (!a) throw new Error("agent_not_found")
    if (a.status !== "active") throw new Error("agent_revoked")
    const res = resource.trim()
    if (!res.startsWith("haven://")) throw new Error("resource_must_use_haven_uri")
    db.query(
      `INSERT INTO resource_grants (agent_id, resource, created_at) VALUES (?, ?, ?)
       ON CONFLICT(agent_id, resource) DO NOTHING`,
    ).run(a.id, res, now())
    ledgerAppend("resource.granted", { agent_id: a.id, resource: res, outcome: "success", actor: "admin" })
    return { agent_id: a.id, resource: res }
  }

  function listResourceGrants(agentId?: string) {
    if (agentId) {
      return db
        .query(`SELECT agent_id, resource, created_at FROM resource_grants WHERE agent_id = ? ORDER BY resource`)
        .all(agentId) as Array<{ agent_id: string; resource: string; created_at: string }>
    }
    return db
      .query(`SELECT agent_id, resource, created_at FROM resource_grants ORDER BY agent_id, resource`)
      .all() as Array<{ agent_id: string; resource: string; created_at: string }>
  }

  function revokeResource(agentId: string, resource: string) {
    db.query(`DELETE FROM resource_grants WHERE agent_id = ? AND resource = ?`).run(agentId, resource)
    ledgerAppend("resource.revoked", { agent_id: agentId, resource, outcome: "success", actor: "admin" })
    return { revoked: true, agent_id: agentId, resource }
  }

  function agentMayAccessResource(agentId: string, resource: string): boolean {
    const exact = db
      .query(`SELECT 1 AS ok FROM resource_grants WHERE agent_id = ? AND resource = ?`)
      .get(agentId, resource) as { ok: number } | null
    if (exact) return true
    const grants = db
      .query(`SELECT resource FROM resource_grants WHERE agent_id = ?`)
      .all(agentId) as Array<{ resource: string }>
    return grants.some((g) => g.resource.endsWith("/") && resource.startsWith(g.resource))
  }

  function resolveSecret(rawToken: string, resource: string) {
    const decision = authorize(rawToken, "secrets:read", resource)
    if (!decision.allow) {
      return { allow: false as const, reason: decision.reason, decision_id: decision.decision_id, agent_id: decision.agent_id }
    }
    const agentId = decision.agent_id!
    if (!parseKeyRef(resource)) {
      const event = ledgerAppend("secret.resolve", {
        agent_id: agentId,
        resource,
        outcome: "denied",
        detail: { reason: "bad_resource_uri" },
      })
      return { allow: false as const, reason: "bad_resource_uri", decision_id: event.id, agent_id: agentId }
    }
    if (!agentMayAccessResource(agentId, resource)) {
      const event = ledgerAppend("authz.deny", {
        agent_id: agentId,
        action: "secrets:read",
        resource,
        outcome: "denied",
        detail: { reason: "resource_not_granted" },
      })
      return { allow: false as const, reason: "resource_not_granted", decision_id: event.id, agent_id: agentId }
    }
    const parsed = parseKeyRef(resource)!
    const key = getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
    if (key?.exposure_blocked_at) {
      const event = ledgerAppend("secret.resolve", {
        agent_id: agentId,
        resource,
        outcome: "denied",
        detail: { reason: "exposure_blocked" },
      })
      return { allow: false as const, reason: "exposure_blocked", decision_id: event.id, agent_id: agentId }
    }
    try {
      const value = readKeyValue(resource)
      const event = ledgerAppend("secret.resolve", {
        agent_id: agentId,
        resource,
        outcome: "success",
        detail: { ref: resource },
      })
      return { allow: true as const, resource, value, decision_id: event.id, agent_id: agentId }
    } catch (e: any) {
      const reason = String(e.message || e)
      const event = ledgerAppend("secret.resolve", {
        agent_id: agentId,
        resource,
        outcome: "error",
        detail: { reason },
      })
      return { allow: false as const, reason, decision_id: event.id, agent_id: agentId }
    }
  }

  function insertKnock(row: Omit<Knock, "id" | "created_at" | "resolved_at"> & { resolved_at?: string | null }): Knock {
    const k: Knock = {
      id: id("knk"),
      created_at: now(),
      resolved_at: row.resolved_at ?? null,
      ...row,
    }
    db.query(
      `INSERT INTO knocks
       (id, access_request_id, org_slug, project_slug, agent_name, purpose, need_json, status,
        decision_reason, agent_id, created_at, resolved_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(
      k.id,
      k.access_request_id,
      k.org_slug,
      k.project_slug,
      k.agent_name,
      k.purpose,
      JSON.stringify(k.need),
      k.status,
      k.decision_reason,
      k.agent_id,
      k.created_at,
      k.resolved_at,
    )
    return k
  }

  function needIsExposureBlocked(need: KnockNeed): boolean {
    if (!need.key_ref) return false
    const parsed = parseKeyRef(need.key_ref)
    if (!parsed) return false
    return Boolean(getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)?.exposure_blocked_at)
  }

  function evaluateNeedActionPolicy(orgSlug: string, projectSlug: string, agent: Agent, need: KnockNeed) {
    const parsed = need.key_ref ? parseKeyRef(need.key_ref) : null
    const keyExists = parsed ? Boolean(getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)) : false
    return previewPolicy({
      org: orgSlug,
      project: projectSlug,
      ...(keyExists && need.key_ref ? { key_ref: need.key_ref } : {}),
      action: need.action === "secrets:read" ? "keys.resolve" : need.action,
      actor_type: "agent",
      environment: parsed?.env,
      agent_id: agent.id,
    })
  }

  function combineActionPolicyDecisions(
    decisions: ReturnType<typeof evaluateNeedActionPolicy>[],
  ): ReturnType<typeof evaluateNeedActionPolicy> {
    const denied = decisions.find((decision) => decision.outcome === "deny")
    if (denied) return denied
    const required = decisions.filter(
      (decision): decision is Extract<typeof decision, { outcome: "approval_required" }> =>
        decision.outcome === "approval_required",
    )
    if (!required.length) {
      const first = decisions[0]
      if (!first || first.outcome !== "auto_approve") {
        throw new Error("invalid_policy_decision")
      }
      const ttls = decisions
        .map((decision) => decision.outcome === "auto_approve" ? decision.max_token_ttl_seconds : undefined)
        .filter((value): value is number => value !== undefined)
      return {
        ...first,
        policy_version: Math.max(...decisions.map((decision) => decision.policy_version)),
        ...(ttls.length ? { max_token_ttl_seconds: Math.min(...ttls) } : {}),
      }
    }
    const tierOrder = ["normal", "elevated", "breakglass"] as const
    const strongest = required
      .flatMap((decision) => decision.tiers)
      .reduce((highest, tier) =>
        tierOrder.indexOf(tier) > tierOrder.indexOf(highest) ? tier : highest, "normal")
    const mode = required.some((decision) => decision.mode === "sequential") ? "sequential" : "threshold"
    const tiers =
      mode === "sequential"
        ? tierOrder.filter((tier) =>
            required.some((decision) => decision.tiers.includes(tier)) &&
            tierOrder.indexOf(tier) <= tierOrder.indexOf(strongest))
        : [strongest]
    const expiries = required
      .map((decision) => decision.expires_in_seconds)
      .filter((value): value is number => value !== undefined)
    const ttls = decisions
      .map((decision) => decision.outcome === "deny" ? undefined : decision.max_token_ttl_seconds)
      .filter((value): value is number => value !== undefined)
    const snapshotSource =
      required.find((decision) => decision.tiers.includes(strongest)) ?? required[0]
    return {
      outcome: "approval_required",
      reason: "combined_approval",
      mode,
      tiers: [...tiers],
      reason_required: required.some((decision) => decision.reason_required),
      ...(expiries.length ? { expires_in_seconds: Math.min(...expiries) } : {}),
      ...(ttls.length ? { max_token_ttl_seconds: Math.min(...ttls) } : {}),
      policy_version: Math.max(...decisions.map((decision) => decision.policy_version)),
      snapshot: structuredClone(snapshotSource.snapshot),
    }
  }

  function knockNeedMatchesScope(orgSlug: string, projectSlug: string, need: KnockNeed): boolean {
    if (need.key_ref) {
      const parsed = parseKeyRef(need.key_ref)
      if (!parsed || parsed.org !== orgSlug || parsed.project !== projectSlug) return false
    }
    if (need.scope) {
      const prefix = `haven://${orgSlug}/${projectSlug}/`
      if (!need.scope.startsWith(prefix)) return false
    }
    return Boolean(need.key_ref || need.scope)
  }

  function knock(input: KnockInput): KnockResult {
    const org = getOrgBySlug(input.org)
    if (!org) throw new Error("org_not_found")
    const project = getProject(input.org, input.project)
    if (!project) throw new Error("project_not_found")
    const agentName = input.agent_name.trim()
    if (!agentName || !input.purpose || !input.need?.length) throw new Error("invalid_knock")
    if (!input.need.every((need) => knockNeedMatchesScope(input.org, input.project, need))) {
      throw new Error("resource_scope_mismatch")
    }
    let existing = getAgentByName(agentName)
    if (
      existing &&
      ((existing.org_id && existing.org_id !== org.id) ||
        (existing.project_id && existing.project_id !== project.id))
    ) {
      throw new Error("agent_scope_mismatch")
    }
    if (existing && (!existing.org_id || !existing.project_id)) {
      db.query(`UPDATE agents SET org_id = ?, project_id = ?, updated_at = ? WHERE id = ?`).run(
        org.id,
        project.id,
        now(),
        existing.id,
      )
      existing = getAgent(existing.id)
    }
    const firstTime = !existing
    const agent =
      existing ||
      createAgent({
        name: agentName,
        owner: "knock",
        purpose: input.purpose,
        risk_tier: "medium",
        scopes: ["secrets:read"],
        org_id: org.id,
        project_id: project.id,
      })

    const policyDecisions = input.need.map((need) =>
      evaluateNeedActionPolicy(input.org, input.project, agent, need))
    let policyDecision = combineActionPolicyDecisions(policyDecisions)
    const exposureBlocked = input.need.some(needIsExposureBlocked)
    if (exposureBlocked) {
      policyDecision = {
        outcome: "deny",
        reason: "exposure_blocked",
        policy_version: policyDecision.policy_version,
        snapshot: structuredClone(policyDecision.snapshot),
      }
    } else if (policyDecision.outcome === "auto_approve" && firstTime) {
      policyDecision = {
        outcome: "approval_required",
        reason: "first_time_agent",
        mode: "threshold",
        tiers: ["normal"],
        reason_required: false,
        max_token_ttl_seconds: policyDecision.max_token_ttl_seconds,
        policy_version: policyDecision.policy_version,
        snapshot: structuredClone(policyDecision.snapshot),
      }
    }

    const maxTtl = Math.min(
      policyDecision.max_token_ttl_seconds ?? 3600,
      Math.min(Math.max(input.ttl_seconds || 900, 60), 3600),
    )
    const refs = input.need.map((n) => n.key_ref || n.scope).filter((r): r is string => Boolean(r))
    const ownerHumanId = getHuman(agent.owner)?.id ?? getHumanByUsername(agent.owner)?.id ?? null
    const accessRequest = createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: agent.id,
      agent_owner_human_id: ownerHumanId,
      policy_decision:
        policyDecision.outcome === "deny"
          ? policyDecision
          : { ...policyDecision, max_token_ttl_seconds: maxTtl },
      reason: input.purpose,
    })

    if (policyDecision.outcome === "deny") {
      const k = insertKnock({
        access_request_id: accessRequest.id,
        org_slug: input.org,
        project_slug: input.project,
        agent_name: agentName,
        purpose: input.purpose,
        need: input.need,
        status: "auto_deny",
        decision_reason: exposureBlocked ? "exposure_blocked" : "guardrail_deny",
        agent_id: agent.id,
        resolved_at: now(),
      })
      ledgerAppend("knock.deny", {
        agent_id: agent.id,
        actor: agentName,
        outcome: "denied",
        detail: { knock_id: k.id, purpose: input.purpose, reason: k.decision_reason },
      })
      return { ...k }
    }

    if (policyDecision.outcome === "approval_required") {
      const k = insertKnock({
        access_request_id: accessRequest.id,
        org_slug: input.org,
        project_slug: input.project,
        agent_name: agentName,
        purpose: input.purpose,
        need: input.need,
        status: "pending",
        decision_reason: firstTime ? "first_time_agent" : "guardrail_approve",
        agent_id: agent.id,
      })
      ledgerAppend("knock.pending", {
        agent_id: agent.id,
        actor: agentName,
        outcome: "info",
        detail: { knock_id: k.id, purpose: input.purpose, first_time: firstTime },
      })
      return { ...k }
    }

    const minted = mintToken(agent.id, maxTtl, ["secrets:read"], refs)
    const k = insertKnock({
      access_request_id: accessRequest.id,
      org_slug: input.org,
      project_slug: input.project,
      agent_name: agentName,
      purpose: input.purpose,
      need: input.need,
      status: "auto_allow",
      decision_reason: "guardrail_allow",
      agent_id: agent.id,
      resolved_at: now(),
    })
    ledgerAppend("knock.allow", {
      agent_id: agent.id,
      actor: agentName,
      outcome: "success",
      detail: { knock_id: k.id, token_id: minted.token_id },
    })
    return { ...k, token: minted.token, ttl_seconds: minted.ttl_seconds, expires_at: minted.expires_at }
  }

  function listKnocks(status?: string) {
    if (status) {
      return db.query(`SELECT * FROM knocks WHERE status = ? ORDER BY created_at DESC`).all(status).map(rowToKnock)
    }
    return db.query(`SELECT * FROM knocks ORDER BY created_at DESC`).all().map(rowToKnock)
  }

  function getKnock(knockId: string): Knock | null {
    const r = db.query(`SELECT * FROM knocks WHERE id = ?`).get(knockId) as any
    return r ? rowToKnock(r) : null
  }

  function decideKnock(
    knockId: string,
    input: { actorId: string; decision: "approve" | "deny"; reason?: string | null },
  ): KnockResult {
    const k = getKnock(knockId)
    if (!k) throw new Error("knock_not_found")
    if (k.status !== "pending") throw new Error("already_resolved")
    const org = getOrgBySlug(k.org_slug)
    if (!org) throw new Error("org_not_found")
    const actor = getHuman(input.actorId)
    const ts = now()
    if (!k.access_request_id) throw new Error("access_request_not_found")
    if (input.decision === "deny") {
      denyAccessRequest(k.access_request_id, {
        actor_human_id: input.actorId,
        reason: input.reason,
      })
      db.query(`UPDATE knocks SET status='denied', decision_reason=?, resolved_at=? WHERE id=?`).run(
        `denied_by:${actor?.username || input.actorId}`,
        ts,
        knockId,
      )
      ledgerAppend("knock.denied", {
        agent_id: k.agent_id,
        actor: actor?.username || input.actorId,
        outcome: "denied",
        detail: { knock_id: knockId },
      })
      return getKnock(knockId)!
    }
    const agent = k.agent_id ? getAgent(k.agent_id) : getAgentByName(k.agent_name)
    if (!agent) throw new Error("agent_not_found")
    if (k.need.some(needIsExposureBlocked)) {
      denyAccessRequest(k.access_request_id, {
        actor_human_id: input.actorId,
        reason: "exposure_blocked",
      })
      const resolvedAt = now()
      db.query(`UPDATE knocks SET status='denied', decision_reason='exposure_blocked', resolved_at=? WHERE id=?`).run(
        resolvedAt,
        knockId,
      )
      ledgerAppend("knock.denied", {
        agent_id: agent.id,
        actor: actor?.username || input.actorId,
        outcome: "denied",
        detail: { knock_id: knockId, reason: "exposure_blocked" },
      })
      return getKnock(knockId)!
    }
    const approvedRequest = approveAccessRequest(k.access_request_id, {
      actor_human_id: input.actorId,
      reason: input.reason,
    })
    if (approvedRequest.status === "pending") {
      db.query(`UPDATE knocks SET decision_reason=? WHERE id=?`).run(
        `approved_stage_by:${actor?.username || input.actorId}`,
        knockId,
      )
      return getKnock(knockId)!
    }
    const refs = k.need.map((n) => n.key_ref || n.scope).filter((r): r is string => Boolean(r))
    const maxTtl = approvedRequest.max_token_ttl_seconds ?? org.guardrail.max_ttl_seconds
    const minted = mintToken(agent.id, maxTtl, ["secrets:read"], refs)
    db.query(`UPDATE knocks SET status='approved', decision_reason=?, resolved_at=? WHERE id=?`).run(
      `approved_by:${actor?.username || input.actorId}`,
      ts,
      knockId,
    )
    ledgerAppend("knock.approved", {
      agent_id: agent.id,
      actor: actor?.username || input.actorId,
      outcome: "success",
      detail: { knock_id: knockId, token_id: minted.token_id },
    })
    const updated = getKnock(knockId)!
    return { ...updated, token: minted.token, ttl_seconds: minted.ttl_seconds, expires_at: minted.expires_at }
  }

  function mintApiKey(name: string, orgId: string | null = null) {
    const trimmed = name.trim()
    if (!trimmed) throw new Error("name_required")
    if (!orgId) throw new Error("org_required")
    if (!getOrg(orgId)) throw new Error("org_not_found")
    const tokenId = id("apk")
    const raw = `${API_KEY_PREFIX}${randomBytes(24).toString("hex")}`
    const token_prefix = `${raw.slice(0, 16)}…`
    const created_at = now()
    db.query(
      `INSERT INTO api_keys (id, name, org_id, token_hash, token_prefix, scopes_json, status, created_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?, 'active', ?, NULL)`,
    ).run(tokenId, trimmed, orgId, hashToken(raw), token_prefix, JSON.stringify([...ACTIVITY_SCOPES]), created_at)
    ledgerAppend("api_key.minted", {
      actor: "admin",
      outcome: "success",
      detail: { api_key_id: tokenId, org_id: orgId, name: trimmed, scopes: [...ACTIVITY_SCOPES] },
    })
    return { id: tokenId, name: trimmed, org_id: orgId, token: raw, token_prefix, scopes: [...ACTIVITY_SCOPES], created_at }
  }

  function rowToApiKey(r: any): ApiKeyRecord {
    return {
      id: r.id,
      name: r.name,
      org_id: r.org_id,
      token_prefix: r.token_prefix,
      scopes: JSON.parse(r.scopes_json),
      status: r.status,
      created_at: r.created_at,
      revoked_at: r.revoked_at,
    }
  }

  function rowToBuoy(r: any): Buoy {
    return {
      id: r.id,
      org_id: r.org_id,
      kind: r.kind,
      name: r.name,
      status: r.status,
      last_seen_at: r.last_seen_at,
      created_at: r.created_at,
    }
  }

  async function registerBuoy(input: {
    orgSlug: string
    kind: "harbor" | "custom"
    name: string
  }) {
    if (!canaryPepperHex) throw new Error("canary_pepper_not_configured")
    const org = getOrgBySlug(input.orgSlug)
    if (!org) throw new Error("org_not_found")
    const name = input.name.trim()
    if (!BUOY_KINDS.has(input.kind) || !name) throw new Error("invalid_buoy")
    const buoy: Buoy = {
      id: id("buoy"),
      org_id: org.id,
      kind: input.kind,
      name,
      status: "active",
      last_seen_at: null,
      created_at: now(),
    }
    const token = `${BUOY_TOKEN_PREFIX}${randomBytes(24).toString("hex")}`
    const credentialHash = await Bun.password.hash(token, "argon2id")
    db.query(
      `INSERT INTO buoys (id, org_id, kind, name, status, credential_hash, last_seen_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
    ).run(buoy.id, buoy.org_id, buoy.kind, buoy.name, buoy.status, credentialHash, buoy.created_at)
    ledgerAppend("buoy.registered", {
      actor: "admin",
      outcome: "success",
      detail: { buoy_id: buoy.id, org_id: buoy.org_id, kind: buoy.kind, name: buoy.name },
    })
    return {
      buoy,
      token,
      canary_pepper_hex: canaryPepperHex,
      package_public_key: Buffer.from(packagePublicKey.export({ format: "der", type: "spki" })).toString("hex"),
    }
  }

  function listBuoys(orgSlug: string): Buoy[] {
    const org = getOrgBySlug(orgSlug)
    if (!org) return []
    return db.query(`SELECT * FROM buoys WHERE org_id = ? ORDER BY created_at DESC`).all(org.id).map(rowToBuoy)
  }

  function revokeBuoy(buoyId: string): Buoy | null {
    const row = db.query(`SELECT * FROM buoys WHERE id = ?`).get(buoyId) as any
    if (!row) return null
    db.query(`UPDATE buoys SET status = 'revoked' WHERE id = ?`).run(buoyId)
    ledgerAppend("buoy.revoked", { actor: "admin", outcome: "success", detail: { buoy_id: buoyId } })
    return rowToBuoy(db.query(`SELECT * FROM buoys WHERE id = ?`).get(buoyId))
  }

  async function rotateBuoyCredential(buoyId: string) {
    if (!canaryPepperHex) throw new Error("canary_pepper_not_configured")
    const row = db.query(`SELECT * FROM buoys WHERE id = ?`).get(buoyId) as any
    if (!row) throw new Error("buoy_not_found")
    if (row.status !== "active") throw new Error("buoy_revoked")
    const token = `${BUOY_TOKEN_PREFIX}${randomBytes(24).toString("hex")}`
    const credentialHash = await Bun.password.hash(token, "argon2id")
    db.query(`UPDATE buoys SET credential_hash = ? WHERE id = ? AND status = 'active'`).run(credentialHash, buoyId)
    ledgerAppend("buoy.credential_rotated", {
      actor: "admin",
      outcome: "success",
      detail: { buoy_id: buoyId },
    })
    const buoy = rowToBuoy(db.query(`SELECT * FROM buoys WHERE id = ?`).get(buoyId))
    return { buoy, token, canary_pepper_hex: canaryPepperHex }
  }

  function authenticateBuoy(req: Request): Buoy | null {
    const buoyId = req.headers.get("x-haven-buoy-id")?.trim() || ""
    if (!buoyId) return null
    const auth = req.headers.get("authorization") || ""
    const match = /^Bearer\s+(\S+)$/i.exec(auth)
    const raw = match?.[1] || ""
    if (!raw.startsWith(BUOY_TOKEN_PREFIX)) return null
    const row = db.query(`SELECT * FROM buoys WHERE id = ? AND status = 'active'`).get(buoyId) as any
    if (!row || !Bun.password.verifySync(raw, row.credential_hash)) return null
    const lastSeenAt = now()
    db.query(`UPDATE buoys SET last_seen_at = ? WHERE id = ?`).run(lastSeenAt, row.id)
    return rowToBuoy({ ...row, last_seen_at: lastSeenAt })
  }

  function rowToCanary(r: any): Canary {
    return {
      id: r.id,
      org_id: r.org_id,
      project_id: r.project_id,
      key_ref: r.key_ref,
      mode: r.mode,
      digest: r.digest,
      status: r.status,
      planted_at: r.planted_at,
      revoked_at: r.revoked_at,
    }
  }

  function watchPackageVersion(): number {
    const row = db
      .query(`SELECT COUNT(*) AS planted, SUM(CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END) AS revoked FROM canaries`)
      .get() as { planted: number; revoked: number | null }
    return row.planted + (row.revoked ?? 0)
  }

  function plantCanary(input: {
    orgSlug: string
    projectSlug: string
    mode: "decoy_key" | "sibling"
    keyRef?: string
    decoy?: string
  }) {
    if (!canaryPepperHex) throw new Error("canary_pepper_not_configured")
    const org = getOrgBySlug(input.orgSlug)
    if (!org) throw new Error("org_not_found")
    const project = getProject(input.orgSlug, input.projectSlug)
    if (!project) throw new Error("project_not_found")
    if (input.mode !== "decoy_key" && input.mode !== "sibling") throw new Error("invalid_canary_mode")

    const canaryId = id("can")
    const decoy = input.decoy || randomBytes(32).toString("base64url")
    let resource = input.keyRef?.trim() || null
    if (input.mode === "sibling") {
      if (!resource) throw new Error("key_ref_required")
      const parsed = parseKeyRef(resource)
      if (
        !parsed ||
        parsed.org !== input.orgSlug ||
        parsed.project !== input.projectSlug ||
        !getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name)
      ) {
        throw new Error("key_not_found")
      }
    } else {
      if (resource) throw new Error("key_ref_not_allowed")
      resource = putKey({
        org: input.orgSlug,
        project: input.projectSlug,
        env: "dev",
        name: `CANARY_${canaryId.slice(-12).toUpperCase()}`,
        value: decoy,
      }).ref
    }

    const plantedAt = now()
    const digest = canaryDigest(Buffer.from(canaryPepperHex, "hex"), decoy)
    db.query(
      `INSERT INTO canaries
       (id, org_id, project_id, key_ref, mode, ciphertext, digest, status, planted_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, NULL)`,
    ).run(canaryId, org.id, project.id, resource, input.mode, encrypt(decoy, rootKey), digest, plantedAt)
    ledgerAppend("canary.planted", {
      actor: "admin",
      resource,
      outcome: "success",
      detail: { canary_id: canaryId, mode: input.mode, digest },
    })
    const canary = rowToCanary(db.query(`SELECT * FROM canaries WHERE id = ?`).get(canaryId))
    return { canary, decoy }
  }

  function listCanaries(orgSlug: string): Canary[] {
    const org = getOrgBySlug(orgSlug)
    if (!org) return []
    return db
      .query(`SELECT * FROM canaries WHERE org_id = ? ORDER BY planted_at DESC`)
      .all(org.id)
      .map(rowToCanary)
  }

  function revokeCanary(canaryId: string): Canary | null {
    const row = db.query(`SELECT * FROM canaries WHERE id = ?`).get(canaryId) as any
    if (!row) return null
    if (row.status === "active") {
      const revokedAt = now()
      db.query(`UPDATE canaries SET status = 'revoked', revoked_at = ? WHERE id = ?`).run(revokedAt, canaryId)
      ledgerAppend("canary.revoked", {
        actor: "admin",
        resource: row.key_ref,
        outcome: "success",
        detail: { canary_id: canaryId },
      })
    }
    return rowToCanary(db.query(`SELECT * FROM canaries WHERE id = ?`).get(canaryId))
  }

  function rowToSighting(r: any): Sighting {
    return {
      id: r.id,
      buoy_id: r.buoy_id,
      canary_id: r.canary_id,
      digest: r.digest,
      observed_at: r.observed_at,
      received_at: r.received_at,
      context: JSON.parse(r.context_json),
      ledger_event_id: r.ledger_event_id,
    }
  }

  function rowToRemediation(r: any): Remediation {
    return {
      id: r.id,
      canary_id: r.canary_id,
      key_ref: r.key_ref,
      sighting_id: r.sighting_id,
      status: r.status,
      on_exposure_applied: r.on_exposure_applied,
      opened_at: r.opened_at,
      closed_at: r.closed_at,
    }
  }

  function getRemediation(remediationId: string): Remediation | null {
    const row = db.query(`SELECT * FROM remediations WHERE id = ?`).get(remediationId) as any
    return row ? rowToRemediation(row) : null
  }

  function listRemediations(orgSlug: string, status?: Remediation["status"]): Remediation[] {
    const org = getOrgBySlug(orgSlug)
    if (!org) return []
    if (status) {
      return db
        .query(
          `SELECT r.* FROM remediations r
           JOIN canaries c ON c.id = r.canary_id
           WHERE c.org_id = ? AND r.status = ?
           ORDER BY r.opened_at DESC`,
        )
        .all(org.id, status)
        .map(rowToRemediation)
    }
    return db
      .query(
        `SELECT r.* FROM remediations r
         JOIN canaries c ON c.id = r.canary_id
         WHERE c.org_id = ?
         ORDER BY r.opened_at DESC`,
      )
      .all(org.id)
      .map(rowToRemediation)
  }

  function dismissRemediation(remediationId: string): Remediation {
    const remediation = getRemediation(remediationId)
    if (!remediation) throw new Error("remediation_not_found")
    if (remediation.status === "rotated") throw new Error("remediation_already_rotated")
    if (remediation.status === "open") {
      const closedAt = now()
      db.query(`UPDATE remediations SET status = 'dismissed', closed_at = ? WHERE id = ?`).run(
        closedAt,
        remediationId,
      )
      ledgerAppend("remediation.dismissed", {
        actor: "admin",
        resource: remediation.key_ref,
        outcome: "success",
        detail: { remediation_id: remediationId, canary_id: remediation.canary_id },
      })
    }
    return getRemediation(remediationId)!
  }

  function rotateRemediation(remediationId: string, revokeCanaryOnRotate = true): Remediation {
    const remediation = getRemediation(remediationId)
    if (!remediation) throw new Error("remediation_not_found")
    const closedAt = now()
    let revokedCanary = false
    db.transaction(() => {
      db.query(`UPDATE remediations SET status = 'rotated', closed_at = ? WHERE id = ?`).run(
        closedAt,
        remediationId,
      )
      if (remediation.key_ref && remediation.on_exposure_applied === "block") {
        const otherOpenBlock = db
          .query(
            `SELECT 1 AS found FROM remediations
             WHERE key_ref = ? AND status = 'open' AND on_exposure_applied = 'block' AND id <> ?
             LIMIT 1`,
          )
          .get(remediation.key_ref, remediationId)
        if (!otherOpenBlock) {
          const parsed = parseKeyRef(remediation.key_ref)
          const key = parsed ? getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name) : null
          if (key) db.query(`UPDATE keys SET exposure_blocked_at = NULL WHERE id = ?`).run(key.id)
        }
      }
      if (revokeCanaryOnRotate) {
        const result = db
          .query(`UPDATE canaries SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'`)
          .run(closedAt, remediation.canary_id)
        revokedCanary = result.changes > 0
      }
    })()
    if (revokedCanary) {
      ledgerAppend("canary.revoked", {
        actor: "admin",
        resource: remediation.key_ref,
        outcome: "success",
        detail: { canary_id: remediation.canary_id },
      })
    }
    ledgerAppend("remediation.rotated", {
      actor: "admin",
      resource: remediation.key_ref,
      outcome: "success",
      detail: {
        remediation_id: remediationId,
        canary_id: remediation.canary_id,
        canary_revoked: revokedCanary,
      },
    })
    return getRemediation(remediationId)!
  }

  function ingestSighting(buoy: Buoy, payload: SightingPayload): {
    sighting: Sighting
    remediation?: Remediation
  } {
    if (buoy.status !== "active" || payload.buoy_id !== buoy.id) throw new Error("invalid_buoy")
    const canary = db.query(`SELECT * FROM canaries WHERE id = ?`).get(payload.canary_id) as any
    if (!canary || canary.org_id !== buoy.org_id) throw new Error("canary_not_found")
    if (canary.status !== "active" || canary.revoked_at) throw new Error("canary_revoked")
    const suppliedDigest = Buffer.from(String(payload.digest), "utf8")
    const plantedDigest = Buffer.from(String(canary.digest), "utf8")
    if (suppliedDigest.length !== plantedDigest.length || !timingSafeEqual(suppliedDigest, plantedDigest)) {
      throw new Error("digest_mismatch")
    }
    if (!payload.observed_at || !Number.isFinite(Date.parse(payload.observed_at))) {
      throw new Error("invalid_observed_at")
    }

    const context = stripSecretFields(payload.context || {}) as Record<string, unknown>
    const receivedAt = now()
    const sightingId = id("sig")
    const event = ledgerAppend("buoy.sighting", {
      actor: buoy.name,
      resource: canary.key_ref,
      outcome: "info",
      detail: {
        buoy_id: buoy.id,
        canary_id: canary.id,
        digest: canary.digest,
        observed_at: payload.observed_at,
        context,
      },
    })
    db.query(
      `INSERT INTO sightings
       (id, buoy_id, canary_id, digest, observed_at, received_at, context_json, ledger_event_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      sightingId,
      buoy.id,
      canary.id,
      canary.digest,
      payload.observed_at,
      receivedAt,
      JSON.stringify(context),
      event.id,
    )
    db.query(`UPDATE buoys SET last_seen_at = ? WHERE id = ?`).run(receivedAt, buoy.id)

    const projectRow = db.query(`SELECT * FROM projects WHERE id = ?`).get(canary.project_id) as any
    const org = getOrg(canary.org_id)
    if (!org || !projectRow) throw new Error("canary_scope_not_found")
    const project = rowToProject(projectRow)
    const parsed = canary.key_ref ? parseKeyRef(canary.key_ref) : null
    const key = parsed ? getKeyRow(parsed.org, parsed.project, parsed.env, parsed.name) : null
    const guardrail = effectiveGuardrail(
      org,
      project,
      key?.guardrail_json ? parseGuardrail(key.guardrail_json) : null,
    )

    let remediation: Remediation | undefined
    if (guardrail.on_exposure === "block" || guardrail.on_exposure === "queue") {
      const openOrCreateRemediation = db.transaction(() => {
        if (guardrail.on_exposure === "block" && key) {
          db.query(`UPDATE keys SET exposure_blocked_at = COALESCE(exposure_blocked_at, ?) WHERE id = ?`).run(
            receivedAt,
            key.id,
          )
        }
        const existing = db
          .query(`SELECT * FROM remediations WHERE canary_id = ? AND status = 'open' ORDER BY opened_at LIMIT 1`)
          .get(canary.id) as any
        if (existing) return rowToRemediation(existing)

        const remediationId = id("rem")
        db.query(
          `INSERT INTO remediations
             (id, canary_id, key_ref, sighting_id, status, on_exposure_applied, opened_at, closed_at)
           VALUES (?, ?, ?, ?, 'open', ?, ?, NULL)`,
        ).run(remediationId, canary.id, canary.key_ref, sightingId, guardrail.on_exposure, receivedAt)
        return rowToRemediation(db.query(`SELECT * FROM remediations WHERE id = ?`).get(remediationId))
      })
      try {
        remediation = openOrCreateRemediation()
      } catch (error) {
        if (!String(error).includes("UNIQUE")) throw error
        const existing = db
          .query(`SELECT * FROM remediations WHERE canary_id = ? AND status = 'open' ORDER BY opened_at LIMIT 1`)
          .get(canary.id) as any
        if (!existing) throw error
        remediation = rowToRemediation(existing)
      }
    }

    const sighting = rowToSighting(db.query(`SELECT * FROM sightings WHERE id = ?`).get(sightingId))
    return remediation ? { sighting, remediation } : { sighting }
  }

  function currentWatchPackage(orgId: string, audience: string) {
    const trimmedAudience = audience.trim()
    if (!WATCH_AUDIENCES.has(trimmedAudience)) throw new Error("invalid_audience")
    if (!getOrg(orgId)) throw new Error("org_not_found")
    const body = {
      version: watchPackageVersion(),
      issued_at: now(),
      audience: trimmedAudience,
      public_key: Buffer.from(packagePublicKey.export({ format: "der", type: "spki" })).toString("hex"),
      public_key_format: "spki-der-hex" as const,
      canaries: (
        db
          .query(`SELECT id, digest, status FROM canaries WHERE org_id = ? ORDER BY planted_at, id`)
          .all(orgId) as Array<{
          id: string
          digest: string
          status: string
        }>
      ).map((canary) => ({
        canary_id: canary.id,
        digest: canary.digest,
        revoked: canary.status === "revoked",
      })),
    }
    const pkg = { ...body, signature: signWatchPackage(body, packagePrivateKey) }
    db.query(
      `INSERT INTO watch_packages (id, version, audience, payload_json, signature, published_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(version) DO UPDATE SET
         audience = excluded.audience,
         payload_json = excluded.payload_json,
         signature = excluded.signature,
         published_at = excluded.published_at`,
    ).run(id("wpkg"), body.version, body.audience, JSON.stringify(body), pkg.signature, body.issued_at)
    return pkg
  }

  function listApiKeys(orgId?: string): ApiKeyRecord[] {
    if (orgId) {
      return db.query(`SELECT * FROM api_keys WHERE org_id = ? ORDER BY created_at DESC`).all(orgId).map(rowToApiKey)
    }
    return db.query(`SELECT * FROM api_keys ORDER BY created_at DESC`).all().map(rowToApiKey)
  }

  function revokeApiKey(keyId: string, orgId?: string): ApiKeyRecord | null {
    const row = (
      orgId
        ? db.query(`SELECT * FROM api_keys WHERE id = ? AND org_id = ?`).get(keyId, orgId)
        : db.query(`SELECT * FROM api_keys WHERE id = ?`).get(keyId)
    ) as any
    if (!row) return null
    const ts = now()
    db.query(`UPDATE api_keys SET status='revoked', revoked_at=? WHERE id=?`).run(ts, keyId)
    ledgerAppend("api_key.revoked", {
      actor: "admin",
      outcome: "success",
      detail: { api_key_id: keyId, org_id: row.org_id },
    })
    return rowToApiKey(db.query(`SELECT * FROM api_keys WHERE id = ?`).get(keyId))
  }

  function authenticateApiKey(req: Request): ApiKeyRecord | null {
    const auth = req.headers.get("authorization") || ""
    const m = /^Bearer\s+(\S+)$/i.exec(auth)
    const raw = m ? m[1] : (req.headers.get("x-haven-api-key") || "").trim()
    if (!raw.startsWith(API_KEY_PREFIX)) return null
    const row = db.query(`SELECT * FROM api_keys WHERE token_hash = ?`).get(hashToken(raw)) as any
    if (!row || row.status !== "active" || row.revoked_at || !row.org_id) return null
    return rowToApiKey(row)
  }

  function ingestActivity(
    key: ApiKeyRecord,
    input: {
      type?: string
      actor?: string
      resource?: string | null
      action?: string | null
      outcome?: string
      detail?: Record<string, unknown>
    },
  ) {
    if (!key.scopes.includes("activity:write")) throw new Error("scope_missing")
    if (!key.org_id || !getOrg(key.org_id)) throw new Error("api_key_org_required")
    const type = String(input.type || "")
    if (!ACTIVITY_TYPE.test(type)) throw new Error("invalid_activity_type")
    const outcome = (input.outcome || "info") as LedgerEvent["outcome"]
    if (!OUTCOMES.has(outcome)) throw new Error("invalid_outcome")
    const detail = stripSecretFields(input.detail && typeof input.detail === "object" ? input.detail : {}) as Record<
      string,
      unknown
    >
    return ledgerAppend(type, {
      actor: String(input.actor || key.name),
      resource: input.resource ? String(input.resource) : null,
      action: input.action ? String(input.action) : null,
      outcome,
      detail: { ...detail, api_key_id: key.id, org_id: key.org_id },
    })
  }

  function migrateLegacyActionPolicies() {
    db.transaction(() => {
      const orgRows = db.query(`SELECT * FROM orgs ORDER BY id`).all() as any[]
      for (const row of orgRows) {
        if (!latestStoredPolicy("org", row.id)) {
          writePolicy(
            "org",
            row.id,
            guardrailToActionPolicy(parseGuardrail(row.guardrail_json)),
            0,
            "legacy_guardrail_migration",
          )
        }
      }
      const projectRows = db.query(`SELECT * FROM projects ORDER BY id`).all() as any[]
      for (const row of projectRows) {
        const guardrail = parseGuardrail(row.guardrail_json)
        if (
          !latestStoredPolicy("project", row.id) &&
          JSON.stringify(guardrail) !== JSON.stringify(DEFAULT_GUARDRAIL)
        ) {
          writePolicy(
            "project",
            row.id,
            guardrailToActionPolicy(guardrail),
            0,
            "legacy_guardrail_migration",
          )
        }
      }
      const keyRows = db
        .query(`SELECT id, guardrail_json FROM keys WHERE guardrail_json IS NOT NULL ORDER BY id`)
        .all() as any[]
      for (const row of keyRows) {
        if (!latestStoredPolicy("key", row.id)) {
          writePolicy(
            "key",
            row.id,
            guardrailToActionPolicy(parseGuardrail(row.guardrail_json)),
            0,
            "legacy_guardrail_migration",
          )
        }
      }
    })()
  }

  // bootstrap
  let org = getOrgBySlug(bootstrapOrg)
  if (!org) org = createOrg(bootstrapOrg, bootstrapOrg)
  if (!getProject(bootstrapOrg, "default")) createProject(org.id, "default", "default")
  const humanCount = (db.query(`SELECT COUNT(*) AS n FROM humans`).get() as { n: number }).n
  if (humanCount === 0) {
    const bootstrapUser = requiredSecret("HAVEN_BOOTSTRAP_USER", opts.bootstrapUser)
    const bootstrapPassword = requiredSecret("HAVEN_BOOTSTRAP_PASSWORD", opts.bootstrapPassword)
    const root = await createHuman({
      username: bootstrapUser,
      password: bootstrapPassword,
      orgId: org.id,
      role: "superadmin",
    })
    db.query(`UPDATE humans SET is_root = 1 WHERE id = ?`).run(root.id)
  } else {
    const rootCount = (db.query(`SELECT COUNT(*) AS n FROM humans WHERE is_root = 1`).get() as { n: number }).n
    if (rootCount === 0) {
      const preferredRoot = opts.bootstrapUser
        ? (db
            .query(
              `SELECT h.id FROM humans h
               JOIN memberships m ON m.user_id = h.id
               WHERE h.username = ? AND m.role = 'superadmin'
               ORDER BY h.created_at LIMIT 1`,
            )
            .get(opts.bootstrapUser.trim().toLowerCase()) as { id: string } | null)
        : null
      const fallbackRoot = db
        .query(
          `SELECT h.id FROM humans h
           JOIN memberships m ON m.user_id = h.id
           WHERE m.role = 'superadmin'
           ORDER BY h.created_at LIMIT 1`,
        )
        .get() as { id: string } | null
      const root = preferredRoot ?? fallbackRoot
      if (root) db.query(`UPDATE humans SET is_root = 1 WHERE id = ?`).run(root.id)
    }
  }
  migrateLegacyActionPolicies()

  return {
    dataDir,
    dbPath,
    ledgerPath,
    packagePublicKey,
    packagePrivateKey,
    uiDist,
    listOrgs,
    getOrg,
    getOrgBySlug,
    createOrg,
    listProjects,
    getProject,
    createProject,
    setOrgGuardrail,
    setProjectGuardrail,
    setKeyGuardrail,
    getOrgPolicy,
    setOrgPolicy,
    getProjectPolicy,
    setProjectPolicy,
    getKeyPolicy,
    setKeyPolicy,
    listPolicyHistory,
    previewPolicy,
    evaluateHumanKeyAction,
    putKey,
    listKeys,
    readKeyValue,
    revealKey,
    deleteKey,
    createHuman,
    verifyPassword,
    changePassword,
    roleFor,
    membershipsFor,
    getHuman,
    getHumanByUsername,
    listMembers,
    addMember,
    grantAccessAssignment,
    revokeAccessAssignment,
    listAccessAssignments,
    authorizeHuman,
    explainAccess,
    createAccessRequest,
    approveAccessRequest,
    denyAccessRequest,
    escalateAccessRequest,
    cancelAccessRequest,
    listAccessRequests,
    canReadKeyValues,
    canWriteOrgGuardrail,
    canApprove,
    canWriteKeys,
    canCreateProject,
    mintSessionCookie,
    clearSessionCookie,
    sessionUserId,
    createAgent,
    listAgents,
    getAgent,
    getAgentByName,
    revokeAgent,
    mintToken,
    introspectToken,
    revokeToken,
    authorize,
    grantResource,
    listResourceGrants,
    revokeResource,
    resolveSecret,
    knock,
    listKnocks,
    getKnock,
    decideKnock,
    mintApiKey,
    listApiKeys,
    revokeApiKey,
    authenticateApiKey,
    registerBuoy,
    listBuoys,
    revokeBuoy,
    rotateBuoyCredential,
    authenticateBuoy,
    plantCanary,
    listCanaries,
    revokeCanary,
    ingestSighting,
    listRemediations,
    dismissRemediation,
    rotateRemediation,
    currentWatchPackage,
    ingestActivity,
    listActivityForOrg: (orgId: string, limit = 50) => ledgerListForOrg(orgId, limit),
    ledgerList,
    ledgerListForOrg,
    ledgerAppend,
    verifyLedger,
    close: () => db.close(),
  }
}

export type Haven = Awaited<ReturnType<typeof createHaven>>

export function envAlias(...names: string[]): string | undefined {
  for (const n of names) {
    const v = process.env[n]?.trim()
    if (v) return v
  }
  return undefined
}

export async function createHavenFromEnv() {
  return createHaven({
    dataDir: process.env.HAVEN_DATA_DIR || "./data",
    tokenSecret: requiredSecret("HAVEN_TOKEN_SECRET", process.env.HAVEN_TOKEN_SECRET),
    rootKeyHex: requiredSecret("HAVEN_ROOT_ENCRYPTION_KEY", process.env.HAVEN_ROOT_ENCRYPTION_KEY),
    canaryPepperHex: requiredSecret("HAVEN_CANARY_PEPPER", envAlias("HAVEN_CANARY_PEPPER")),
    bootstrapUser: envAlias("HAVEN_BOOTSTRAP_USER") || "root",
    bootstrapPassword: envAlias("HAVEN_BOOTSTRAP_PASSWORD") || "",
    bootstrapOrg: envAlias("HAVEN_BOOTSTRAP_ORG") || "demo",
    uiDist: process.env.HAVEN_UI_DIST,
  })
}
