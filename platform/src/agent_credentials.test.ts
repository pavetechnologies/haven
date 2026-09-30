import { afterEach, describe, expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { createHash } from "node:crypto"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createApp } from "./app.ts"
import { createHaven } from "./haven.ts"

const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

async function setup() {
  const dataDir = mkdtempSync(join(tmpdir(), "haven-agk-"))
  dirs.push(dataDir)
  const uiDist = join(dataDir, "ui")
  mkdirSync(uiDist, { recursive: true })
  writeFileSync(join(uiDist, "index.html"), "<!doctype html><title>Haven</title>")
  const haven = await createHaven({
    dataDir,
    tokenSecret: "token-secret-not-a-placeholder-32bxx",
    rootKeyHex: "ab".repeat(32),
    canaryPepperHex: "cd".repeat(32),
    bootstrapUser: "root",
    bootstrapPassword: "correct-horse-battery",
    bootstrapOrg: "demo",
    uiDist,
  })
  const handle = createApp(haven)
  const login = await handle(
    new Request("http://127.0.0.1/v1/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
    }),
  )
  const cookie = (login.headers.get("set-cookie") || "").split(";")[0]
  return { haven, handle, cookie, dataDir }
}

const allowAll = {
  default: "allow" as const,
  allow_agents: ["*"],
  allow_actions: ["secrets:read"],
  max_ttl_seconds: 120,
  require_approval: false,
  on_exposure: "queue" as const,
}

const needPing = [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }]

function knockReq(headers: Record<string, string>, body: Record<string, unknown>) {
  return new Request("http://127.0.0.1/v1/knock", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  })
}

function knockBody(extra: Record<string, unknown> = {}) {
  return { org: "demo", project: "default", purpose: "read ping", need: needPing, ...extra }
}

function counts(dataDir: string) {
  const db = new Database(join(dataDir, "haven.db"), { readonly: true })
  const out = {
    knocks: (db.query(`SELECT COUNT(*) AS n FROM knocks`).get() as any).n as number,
    agents: (db.query(`SELECT COUNT(*) AS n FROM agents`).get() as any).n as number,
    access_requests: (db.query(`SELECT COUNT(*) AS n FROM access_requests`).get() as any).n as number,
  }
  db.close()
  return out
}

function ledgerText(dataDir: string) {
  const p = join(dataDir, "ledger.jsonl")
  return existsSync(p) ? readFileSync(p, "utf8") : ""
}

async function createAgentViaApi(handle: (r: Request) => Promise<Response>, cookie: string, name = "pilot") {
  const res = await handle(
    new Request("http://127.0.0.1/v1/agents", {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({ org: "demo", name, owner: "root", purpose: "read", risk_tier: "low" }),
    }),
  )
  expect(res.status).toBe(201)
  return (await res.json()) as any
}

describe("agent credentials (haven)", () => {
  test("issue returns raw once with haven_agk_ prefix; only hash stored", async () => {
    const { haven, dataDir } = await setup()
    const agent = haven.createAgent({ name: "a1", owner: "root", purpose: "p", risk_tier: "low", scopes: ["secrets:read"] })
    const cred = haven.issueAgentCredential(agent.id, "root")
    expect(cred.token.startsWith("haven_agk_")).toBe(true)
    expect(cred.token.length).toBe("haven_agk_".length + 64)
    expect(cred.token_prefix).toBe(`${cred.token.slice(0, 18)}…`)
    const listed = haven.listAgentCredentials(agent.id)
    expect(listed.length).toBe(1)
    expect(JSON.stringify(listed)).not.toContain(cred.token)
    expect(listed[0]).not.toHaveProperty("token_hash")
    expect(listed[0]).not.toHaveProperty("token")
    // ISC-8: DB holds only the hash
    const db = new Database(join(dataDir, "haven.db"), { readonly: true })
    const rows = db.query(`SELECT * FROM agent_credentials`).all() as any[]
    db.close()
    expect(rows.length).toBe(1)
    expect(JSON.stringify(rows)).not.toContain(cred.token)
    expect(rows[0].token_hash).toBe(createHash("sha256").update(cred.token).digest("hex"))
    expect(ledgerText(dataDir)).not.toContain(cred.token)
    expect(ledgerText(dataDir)).toContain("agent.credential.issued")
  })

  test("issue rejects unknown and revoked agents", async () => {
    const { haven } = await setup()
    expect(() => haven.issueAgentCredential("agt_missing", "root")).toThrow(/agent_not_found/)
    const agent = haven.createAgent({ name: "a2", owner: "root", purpose: "p", risk_tier: "low", scopes: [] })
    haven.revokeAgent(agent.id)
    expect(() => haven.issueAgentCredential(agent.id, "root")).toThrow(/agent_revoked/)
  })

  test("authenticateAgent accepts Bearer and x-haven-agent-key, rejects others", async () => {
    const { haven } = await setup()
    const agent = haven.createAgent({ name: "a3", owner: "root", purpose: "p", risk_tier: "low", scopes: [] })
    const cred = haven.issueAgentCredential(agent.id, "root")
    const bearer = new Request("http://x", { headers: { authorization: `Bearer ${cred.token}` } })
    expect(haven.authenticateAgent(bearer)?.id).toBe(agent.id)
    const header = new Request("http://x", { headers: { "x-haven-agent-key": cred.token } })
    expect(haven.authenticateAgent(header)?.id).toBe(agent.id)
    expect(haven.listAgentCredentials(agent.id)[0].last_used_at).not.toBeNull()
    expect(haven.authenticateAgent(new Request("http://x"))).toBeNull()
    expect(
      haven.authenticateAgent(new Request("http://x", { headers: { authorization: `Bearer haven_agk_${"0".repeat(64)}` } })),
    ).toBeNull()
    const apiKey = haven.mintApiKey("k", haven.getOrgBySlug("demo")!.id)
    expect(
      haven.authenticateAgent(new Request("http://x", { headers: { authorization: `Bearer ${apiKey.token}` } })),
    ).toBeNull()
    haven.revokeAgentCredential(agent.id, cred.id, "root")
    expect(haven.authenticateAgent(bearer)).toBeNull()
  })

  test("revokeAgent revokes all credentials (ISC-5)", async () => {
    const { haven } = await setup()
    const agent = haven.createAgent({ name: "a4", owner: "root", purpose: "p", risk_tier: "low", scopes: [] })
    const c1 = haven.issueAgentCredential(agent.id, "root")
    const c2 = haven.issueAgentCredential(agent.id, "root")
    haven.revokeAgent(agent.id)
    expect(haven.listAgentCredentials(agent.id).every((c) => c.status === "revoked" && c.revoked_at)).toBe(true)
    for (const c of [c1, c2]) {
      expect(haven.authenticateAgent(new Request("http://x", { headers: { authorization: `Bearer ${c.token}` } }))).toBeNull()
    }
  })

  test("knock no longer auto-registers unknown agents (ISC-4)", async () => {
    const { haven } = await setup()
    haven.setOrgGuardrail("demo", allowAll)
    const before = haven.listAgents().length
    expect(() => haven.knock({ ...knockBody(), agent_id: "agt_nope" } as any)).toThrow(/agent_not_found/)
    expect(haven.listAgents().length).toBe(before)
    expect(haven.getAgentByName("stranger")).toBeNull()
  })

  test("knock rejects mismatched agent_name and revoked agents", async () => {
    const { haven } = await setup()
    const a = haven.createAgent({ name: "alpha", owner: "root", purpose: "p", risk_tier: "low", scopes: [] })
    haven.createAgent({ name: "beta", owner: "root", purpose: "p", risk_tier: "low", scopes: [] })
    expect(() => haven.knock({ ...knockBody(), agent_id: a.id, agent_name: "beta" })).toThrow(/agent_identity_mismatch/)
    haven.revokeAgent(a.id)
    expect(() => haven.knock({ ...knockBody(), agent_id: a.id })).toThrow(/agent_revoked/)
  })

  test("registered agent with a valid key gets auto_allow on its FIRST knock under org allow and can resolve (ISC-9)", async () => {
    const { haven, handle, cookie } = await setup()
    haven.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    haven.setOrgGuardrail("demo", allowAll)
    const a = await createAgentViaApi(handle, cookie, "fresh")
    expect(haven.listKnocks().length).toBe(0)
    const res = await handle(knockReq({ authorization: `Bearer ${a.credential.token}` }, knockBody()))
    expect(res.status).toBe(200)
    const first = await res.json()
    expect(first.status).toBe("auto_allow")
    expect(first.decision_reason).toBe("guardrail_allow")
    expect(first.agent_name).toBe("fresh")
    expect(first.token.startsWith("haven_")).toBe(true)
    const resolved = await handle(
      new Request("http://127.0.0.1/v1/secrets/resolve", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: first.token, resource: "haven://demo/default/dev/PING" }),
      }),
    )
    const body = await resolved.json()
    expect(body.allow).toBe(true)
    expect(body.value).toBe("dock")
  })

  test("approve policy queues a registered agent's knock with guardrail_approve", async () => {
    const { haven } = await setup()
    haven.setOrgGuardrail("demo", { ...allowAll, default: "approve" })
    const a = haven.createAgent({ name: "queued", owner: "root", purpose: "p", risk_tier: "low", scopes: ["secrets:read"] })
    const k = haven.knock({ ...knockBody(), agent_id: a.id })
    expect(k.status).toBe("pending")
    expect(k.decision_reason).toBe("guardrail_approve")
    expect(k.token).toBeUndefined()
  })
})

describe("POST /v1/knock requires an agent credential", () => {
  test("no credential → 401 with no knock/agent/access-request/ledger writes (ISC-1)", async () => {
    const { haven, handle, dataDir } = await setup()
    haven.setOrgGuardrail("demo", allowAll)
    haven.createAgent({ name: "pilot", owner: "root", purpose: "p", risk_tier: "low", scopes: ["secrets:read"] })
    const before = counts(dataDir)
    const ledgerBefore = ledgerText(dataDir)
    for (const body of [knockBody({ agent_name: "pilot" }), knockBody({ agent_name: "stranger" }), {}]) {
      const res = await handle(knockReq({}, body))
      expect(res.status).toBe(401)
      expect((await res.json()).error).toBe("agent_credential_required")
    }
    const bad = await handle(new Request("http://127.0.0.1/v1/knock", { method: "POST", body: "not json" }))
    expect(bad.status).toBe(401)
    expect(counts(dataDir)).toEqual(before)
    expect(ledgerText(dataDir)).toBe(ledgerBefore)
  })

  test("human session alone cannot knock", async () => {
    const { handle, cookie } = await setup()
    const res = await handle(knockReq({ cookie }, knockBody({ agent_name: "pilot" })))
    expect(res.status).toBe(401)
  })

  test("invalid, wrong-type, or revoked credential → 401 (ISC-2)", async () => {
    const { haven, handle, cookie, dataDir } = await setup()
    const agent = await createAgentViaApi(handle, cookie)
    const apiKey = haven.mintApiKey("k", haven.getOrgBySlug("demo")!.id)
    const before = counts(dataDir)
    for (const token of [`haven_agk_${"f".repeat(64)}`, apiKey.token, "garbage"]) {
      const res = await handle(knockReq({ authorization: `Bearer ${token}` }, knockBody()))
      expect(res.status).toBe(401)
    }
    const revoke = await handle(
      new Request(`http://127.0.0.1/v1/agents/${agent.id}/credentials/${agent.credential.id}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(revoke.status).toBe(200)
    const res = await handle(knockReq({ authorization: `Bearer ${agent.credential.token}` }, knockBody()))
    expect(res.status).toBe(401)
    expect(counts(dataDir)).toEqual(before)
  })

  test("credential for agent A naming agent B → 403 (ISC-3)", async () => {
    const { handle, cookie, haven } = await setup()
    const a = await createAgentViaApi(handle, cookie, "agent-a")
    await createAgentViaApi(handle, cookie, "agent-b")
    const res = await handle(
      knockReq({ authorization: `Bearer ${a.credential.token}` }, knockBody({ agent_name: "agent-b" })),
    )
    expect(res.status).toBe(403)
    expect(haven.listKnocks().length).toBe(0)
  })

  test("revoked agent's credential stops working (ISC-5)", async () => {
    const { handle, cookie, haven } = await setup()
    haven.setOrgGuardrail("demo", allowAll)
    const a = await createAgentViaApi(handle, cookie)
    const ok = await handle(knockReq({ "x-haven-agent-key": a.credential.token }, knockBody()))
    expect(ok.status).toBe(200)
    const minted = (await ok.json()).token as string
    const revoke = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(revoke.status).toBe(200)
    const res = await handle(knockReq({ authorization: `Bearer ${a.credential.token}` }, knockBody()))
    expect(res.status).toBe(401)
    expect(haven.introspectToken(minted).active).toBe(false)
  })

  test("valid credential under approve policy: pending, human approves, token resolves", async () => {
    const { haven, handle, cookie } = await setup()
    haven.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    haven.setOrgGuardrail("demo", { ...allowAll, default: "approve" })
    const a = await createAgentViaApi(handle, cookie)
    const auth = { authorization: `Bearer ${a.credential.token}` }
    const first = await handle(knockReq(auth, knockBody({ agent_name: "pilot" })))
    expect(first.status).toBe(202)
    const k1 = await first.json()
    expect(k1.decision_reason).toBe("guardrail_approve")
    expect(k1.agent_name).toBe("pilot")
    const approve = await handle(
      new Request(`http://127.0.0.1/v1/knocks/${k1.id}/approve`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: "{}",
      }),
    )
    expect(approve.status).toBe(200)
    const k2 = await approve.json()
    expect(k2.status).toBe("approved")
    const resolved = await handle(
      new Request("http://127.0.0.1/v1/secrets/resolve", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: k2.token, resource: "haven://demo/default/dev/PING" }),
      }),
    )
    expect((await resolved.json()).value).toBe("dock")
  })
})

describe("agent credential is knock-only (ISC-6)", () => {
  test("rejected by resolve, authorize, introspect, activity and human routes", async () => {
    const { haven, handle, cookie } = await setup()
    haven.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    const a = await createAgentViaApi(handle, cookie)
    const raw = a.credential.token as string
    const bearer = { "content-type": "application/json", authorization: `Bearer ${raw}` }

    const resolve = await handle(
      new Request("http://127.0.0.1/v1/secrets/resolve", {
        method: "POST",
        headers: bearer,
        body: JSON.stringify({ token: raw, resource: "haven://demo/default/dev/PING" }),
      }),
    )
    const resolveBody = await resolve.json()
    expect(resolveBody.allow).not.toBe(true)
    expect(JSON.stringify(resolveBody)).not.toContain("dock")

    const authz = await handle(
      new Request("http://127.0.0.1/v1/authorize", {
        method: "POST",
        headers: bearer,
        body: JSON.stringify({ token: raw, action: "secrets:read", resource: "haven://demo/default/dev/PING" }),
      }),
    )
    expect(authz.status).toBe(403)
    expect((await authz.json()).allow).toBe(false)

    const intro = await handle(
      new Request("http://127.0.0.1/v1/tokens/introspect", {
        method: "POST",
        headers: bearer,
        body: JSON.stringify({ token: raw }),
      }),
    )
    expect((await intro.json()).active).toBe(false)

    const actGet = await handle(new Request("http://127.0.0.1/v1/activity", { headers: bearer }))
    expect(actGet.status).toBe(401)
    const actPost = await handle(
      new Request("http://127.0.0.1/v1/activity", {
        method: "POST",
        headers: bearer,
        body: JSON.stringify({ type: "activity.test" }),
      }),
    )
    expect(actPost.status).toBe(401)

    for (const [method, path] of [
      ["GET", "/v1/secrets?org=demo&project=default&env=dev"],
      ["GET", "/v1/agents?org=demo"],
      ["GET", "/v1/ledger?org=demo"],
      ["GET", "/v1/me"],
      ["POST", "/v1/tokens"],
      ["GET", `/v1/agents/${a.id}/credentials?org=demo`],
      ["GET", "/v1/watch-packages/current"],
    ]) {
      const res = await handle(
        new Request(`http://127.0.0.1${path}`, {
          method,
          headers: { ...bearer, "x-haven-agent-key": raw },
          body: method === "GET" ? undefined : JSON.stringify({ agent_id: a.id }),
        }),
      )
      expect([path, res.status]).toEqual([path, 401])
    }
  })
})

describe("agent credential admin routes (ISC-7)", () => {
  test("create returns credential once; issue/list/revoke; ledger never holds raw", async () => {
    const { handle, cookie, dataDir } = await setup()
    const h = { "content-type": "application/json", cookie }
    const a = await createAgentViaApi(handle, cookie)
    expect(a.credential.token.startsWith("haven_agk_")).toBe(true)
    expect(a.credential.id).toBeTruthy()
    expect(a.credential.token_prefix).toBeTruthy()

    const getAgent = await handle(new Request(`http://127.0.0.1/v1/agents/${a.id}?org=demo`, { headers: h }))
    expect(JSON.stringify(await getAgent.json())).not.toContain(a.credential.token)

    const issued = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(issued.status).toBe(201)
    const c2 = await issued.json()
    expect(c2.token.startsWith("haven_agk_")).toBe(true)
    expect(c2.token).not.toBe(a.credential.token)

    const list = await handle(new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials?org=demo`, { headers: h }))
    expect(list.status).toBe(200)
    const listed = await list.json()
    expect(listed.credentials.length).toBe(2)
    const listText = JSON.stringify(listed)
    expect(listText).not.toContain(a.credential.token)
    expect(listText).not.toContain(c2.token)
    expect(listText).not.toContain("token_hash")
    expect(listed.credentials.every((c: any) => c.status === "active")).toBe(true)

    const revoke = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials/${a.credential.id}/revoke`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(revoke.status).toBe(200)
    expect((await revoke.json()).status).toBe("revoked")
    const missing = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials/agc_missing/revoke`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(missing.status).toBe(404)

    const ledger = await handle(new Request("http://127.0.0.1/v1/ledger?org=demo&limit=500", { headers: h }))
    const ledgerBody = await ledger.text()
    expect(ledgerBody).toContain("agent.credential.issued")
    expect(ledgerBody).toContain("agent.credential.revoked")
    expect(ledgerBody).not.toContain(a.credential.token)
    expect(ledgerBody).not.toContain(c2.token)
    expect(ledgerText(dataDir)).not.toContain(a.credential.token)
    expect(ledgerText(dataDir)).not.toContain(c2.token)

    const db = new Database(join(dataDir, "haven.db"), { readonly: true })
    const dump = JSON.stringify(db.query(`SELECT * FROM agent_credentials`).all())
    db.close()
    expect(dump).not.toContain(a.credential.token)
    expect(dump).not.toContain(c2.token)
    expect(dump).toContain(createHash("sha256").update(c2.token).digest("hex"))
  })

  test("credential routes are org-scoped", async () => {
    const { haven, handle, cookie } = await setup()
    const other = haven.createOrg("other", "Other")
    const otherAgent = haven.createAgent({
      name: "other-agent",
      owner: "root",
      purpose: "p",
      risk_tier: "low",
      scopes: [],
      org_id: other.id,
    })
    const cred = haven.issueAgentCredential(otherAgent.id, "root")
    const h = { "content-type": "application/json", cookie }
    const issue = await handle(
      new Request(`http://127.0.0.1/v1/agents/${otherAgent.id}/credentials`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(issue.status).toBe(404)
    const list = await handle(
      new Request(`http://127.0.0.1/v1/agents/${otherAgent.id}/credentials?org=demo`, { headers: h }),
    )
    expect(list.status).toBe(404)
    const revoke = await handle(
      new Request(`http://127.0.0.1/v1/agents/${otherAgent.id}/credentials/${cred.id}/revoke`, {
        method: "POST",
        headers: h,
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(revoke.status).toBe(404)
    expect(haven.listAgentCredentials(otherAgent.id)[0].status).toBe("active")
  })

  test("unauthenticated credential routes → 401", async () => {
    const { handle, haven } = await setup()
    const agent = haven.createAgent({ name: "x", owner: "root", purpose: "p", risk_tier: "low", scopes: [] })
    const res = await handle(
      new Request(`http://127.0.0.1/v1/agents/${agent.id}/credentials`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(res.status).toBe(401)
  })
})

describe("deleting revoked agent keys", () => {
  function post(path: string, cookie: string, body: Record<string, unknown> = { org: "demo" }) {
    return new Request(`http://127.0.0.1${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify(body),
    })
  }

  test("a revoked key can be deleted; it disappears from the list and the ledger records it", async () => {
    const { handle, cookie } = await setup()
    const created = await handle(post("/v1/agents", cookie, { org: "demo", name: "tidy", owner: "root", purpose: "p" }))
    const a = await created.json()
    const base = `/v1/agents/${a.id}/credentials/${a.credential.id}`

    expect((await handle(post(`${base}/revoke`, cookie))).status).toBe(200)
    const del = await handle(post(`${base}/delete`, cookie))
    expect(del.status).toBe(200)
    expect((await del.json()).deleted).toBe(true)

    const list = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials?org=demo`, { headers: { cookie } }),
    )
    expect((await list.json()).credentials).toEqual([])

    const ledger = await (
      await handle(new Request("http://127.0.0.1/v1/ledger?org=demo&limit=500", { headers: { cookie } }))
    ).text()
    expect(ledger).toContain("agent.credential.deleted")
    expect(ledger).not.toContain(a.credential.token)

    expect((await handle(post(`${base}/delete`, cookie))).status).toBe(404)
  })

  test("an active key cannot be deleted (409) and keeps working", async () => {
    const { handle, cookie } = await setup()
    const a = await (
      await handle(post("/v1/agents", cookie, { org: "demo", name: "live", owner: "root", purpose: "p" }))
    ).json()
    const del = await handle(post(`/v1/agents/${a.id}/credentials/${a.credential.id}/delete`, cookie))
    expect(del.status).toBe(409)
    expect((await del.json()).error).toBe("credential_active")
    const list = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials?org=demo`, { headers: { cookie } }),
    )
    expect((await list.json()).credentials[0].status).toBe("active")
  })

  test("delete is org-scoped, agent-scoped, and requires a session", async () => {
    const { haven, handle, cookie } = await setup()
    const a = await (
      await handle(post("/v1/agents", cookie, { org: "demo", name: "mine", owner: "root", purpose: "p" }))
    ).json()
    const b = await (
      await handle(post("/v1/agents", cookie, { org: "demo", name: "other", owner: "root", purpose: "p" }))
    ).json()
    haven.revokeAgentCredential(a.id, a.credential.id, "root")

    expect((await handle(post(`/v1/agents/${b.id}/credentials/${a.credential.id}/delete`, cookie))).status).toBe(404)
    const anon = await handle(
      new Request(`http://127.0.0.1/v1/agents/${a.id}/credentials/${a.credential.id}/delete`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(anon.status).toBe(401)
    expect(haven.listAgentCredentials(a.id).length).toBe(1)
  })

  test("keys revoked by revoking the agent can be deleted too", async () => {
    const { haven, handle, cookie } = await setup()
    const a = await (
      await handle(post("/v1/agents", cookie, { org: "demo", name: "gone", owner: "root", purpose: "p" }))
    ).json()
    haven.revokeAgent(a.id)
    expect((await handle(post(`/v1/agents/${a.id}/credentials/${a.credential.id}/delete`, cookie))).status).toBe(200)
    expect(haven.listAgentCredentials(a.id)).toEqual([])
  })
})
