import { afterEach, describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createApp } from "./app.ts"
import { createHaven } from "./haven.ts"

const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

async function app() {
  const dataDir = mkdtempSync(join(tmpdir(), "haven-http-"))
  dirs.push(dataDir)
  const uiDist = join(dataDir, "ui")
  mkdirSync(uiDist, { recursive: true })
  writeFileSync(join(uiDist, "index.html"), "<!doctype html><title>Haven</title><h1>Haven</h1>")
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
  return { handle: createApp(haven), haven }
}

function cookieFrom(res: Response) {
  return res.headers.get("set-cookie") || ""
}

describe("health and UI", () => {
  test("GET /health identifies Haven with no vendor field", async () => {
    const { handle } = await app()
    const res = await handle(new Request("http://127.0.0.1/health"))
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body.ok).toBe(true)
    expect(body.service).toBe("haven")
    expect(body.planes).toContain("secrets")
    expect(body.planes).toContain("knock")
    expect(body.planes).toContain("buoys")
    expect(JSON.stringify(body)).not.toMatch(/infisical/i)
  })

  test("GET / serves the operator UI", async () => {
    const { handle } = await app()
    const res = await handle(new Request("http://127.0.0.1/"))
    expect(res.status).toBe(200)
    expect(await res.text()).toContain("Haven")
  })
})

describe("human session", () => {
  test("POST /v1/session logs in with username and password", async () => {
    const { handle } = await app()
    const res = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    expect(res.status).toBe(200)
    const set = cookieFrom(res)
    expect(set.toLowerCase()).toContain("httponly")
    expect(set).toContain("haven_session=")
    const cookie = set.split(";")[0]
    const me = await handle(new Request("http://127.0.0.1/v1/me", { headers: { cookie } }))
    expect(me.status).toBe(200)
    const body = await me.json()
    expect(body.username).toBe("root")
    expect(body.orgs[0].role).toBe("superadmin")
  })

  test("rejects a bad password", async () => {
    const { handle } = await app()
    const res = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "admin", password: "nope" }),
      }),
    )
    expect(res.status).toBe(401)
  })
})

describe("access assignment HTTP API", () => {
  async function rootSession(handle: (req: Request) => Promise<Response>) {
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    return {
      "content-type": "application/json",
      cookie: cookieFrom(login).split(";")[0],
    }
  }

  test("lists the versioned permission catalog and effective member access", async () => {
    const { handle, haven } = await app()
    const alice = await haven.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const headers = await rootSession(handle)

    const catalog = await handle(new Request("http://127.0.0.1/v1/permissions", { headers }))
    expect(catalog.status).toBe(200)
    expect(await catalog.json()).toMatchObject({
      version: 1,
      permissions: expect.arrayContaining([
        { permission: "keys.reveal", scopes: ["org", "project", "key"] },
      ]),
    })

    const access = await handle(
      new Request(`http://127.0.0.1/v1/orgs/demo/users/${alice.id}/access`, { headers }),
    )
    expect(access.status).toBe(200)
    expect(await access.json()).toMatchObject({
      user: { id: alice.id, username: "alice", role: "user" },
      assigned: [],
      inherited: expect.arrayContaining(["projects.list", "keys.list"]),
      effective: expect.arrayContaining([
        expect.objectContaining({ permission: "projects.list", allow: true, reason: "role_template" }),
        expect.objectContaining({ permission: "keys.reveal", allow: false, reason: "missing_permission" }),
      ]),
    })
  })

  test("creates, explains, and revokes a scoped assignment with required reasons", async () => {
    const { handle, haven } = await app()
    const alice = await haven.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const project = haven.getProject("demo", "default")!
    const headers = await rootSession(handle)

    const missingReason = await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/access-assignments", {
        method: "POST",
        headers,
        body: JSON.stringify({
          user_id: alice.id,
          project_id: project.id,
          permission: "keys.reveal",
          effect: "allow",
        }),
      }),
    )
    expect(missingReason.status).toBe(400)
    expect((await missingReason.json()).error).toBe("reason_required")

    const created = await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/access-assignments", {
        method: "POST",
        headers,
        body: JSON.stringify({
          user_id: alice.id,
          project_id: project.id,
          permission: "keys.reveal",
          effect: "allow",
          reason: "on-call key recovery",
        }),
      }),
    )
    expect(created.status).toBe(201)
    const assignment = await created.json()
    const assignmentId = assignment.id
    expect(assignmentId).toStartWith("asg_")
    expect(assignment).toMatchObject({
      user_id: alice.id,
      project_id: project.id,
      permission: "keys.reveal",
      effect: "allow",
      reason: "on-call key recovery",
    })

    const explained = await handle(
      new Request("http://127.0.0.1/v1/authorization/explain", {
        method: "POST",
        headers,
        body: JSON.stringify({
          org: "demo",
          user_id: alice.id,
          project_id: project.id,
          permission: "keys.reveal",
        }),
      }),
    )
    expect(explained.status).toBe(200)
    expect(await explained.json()).toMatchObject({
      allow: true,
      reason: "explicit_allow",
      matched: { grants: [expect.objectContaining({ id: assignmentId })] },
    })

    const missingRevokeReason = await handle(
      new Request(`http://127.0.0.1/v1/orgs/demo/access-assignments/${assignmentId}/revoke`, {
        method: "POST",
        headers,
        body: "{}",
      }),
    )
    expect(missingRevokeReason.status).toBe(400)
    expect((await missingRevokeReason.json()).error).toBe("reason_required")

    const revoked = await handle(
      new Request(`http://127.0.0.1/v1/orgs/demo/access-assignments/${assignmentId}/revoke`, {
        method: "POST",
        headers,
        body: JSON.stringify({ reason: "rotation complete" }),
      }),
    )
    expect(revoked.status).toBe(200)
    expect(await revoked.json()).toMatchObject({
      id: assignmentId,
      revoked_at: expect.any(String),
      revoked_by: haven.getHumanByUsername("root")!.id,
    })
  })

  test("fails closed for invalid assignment scopes and unauthorized managers", async () => {
    const { handle, haven } = await app()
    const alice = await haven.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const rootHeaders = await rootSession(handle)
    const invalidScope = await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/access-assignments", {
        method: "POST",
        headers: rootHeaders,
        body: JSON.stringify({
          user_id: alice.id,
          project_id: haven.getProject("demo", "default")!.id,
          permission: "org.members.manage",
          effect: "allow",
          reason: "invalid project-scoped org permission",
        }),
      }),
    )
    expect(invalidScope.status).toBe(400)
    expect((await invalidScope.json()).error).toBe("invalid_assignment_scope")

    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "alice", password: "correct-horse-battery" }),
      }),
    )
    const denied = await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/access-assignments", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: cookieFrom(login).split(";")[0],
        },
        body: JSON.stringify({
          user_id: alice.id,
          permission: "keys.reveal",
          effect: "allow",
          reason: "self escalation",
        }),
      }),
    )
    expect(denied.status).toBe(403)
  })
})

describe("access request HTTP API", () => {
  async function session(handle: (req: Request) => Promise<Response>, username = "root", password = "correct-horse-battery") {
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password }),
      }),
    )
    return {
      "content-type": "application/json",
      cookie: cookieFrom(login).split(";")[0],
    }
  }

  function approvalDecision(
    tiers: Array<"normal" | "elevated" | "breakglass"> = ["normal"],
    expiresInSeconds?: number,
  ) {
    return {
      outcome: "approval_required" as const,
      reason: "policy approval required",
      mode: "threshold" as const,
      tiers,
      reason_required: tiers.some((tier) => tier !== "normal"),
      policy_version: 1,
      snapshot: { org: null, project: null, key: null },
      ...(expiresInSeconds ? { expires_in_seconds: expiresInSeconds } : {}),
    }
  }

  test("lists and gets org-scoped access requests with approval details", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const project = haven.getProject("demo", "default")!
    const owner = haven.getHumanByUsername("root")!
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-http-list",
      agent_owner_human_id: owner.id,
      policy_decision: approvalDecision(),
      reason: "deploy needs a scoped key",
    })
    const headers = await session(handle)

    const listed = await handle(new Request("http://127.0.0.1/v1/access-requests?org=demo&status=pending", { headers }))
    expect(listed.status).toBe(200)
    expect(await listed.json()).toMatchObject({
      access_requests: [
        {
          id: request.id,
          action: "keys.resolve",
          actor_type: "agent",
          stage_index: 0,
          tiers: ["normal"],
          policy_reason: "policy approval required",
          reason: "deploy needs a scoped key",
        },
      ],
    })

    const fetched = await handle(new Request(`http://127.0.0.1/v1/access-requests/${request.id}`, { headers }))
    expect(fetched.status).toBe(200)
    expect(await fetched.json()).toMatchObject({ id: request.id, status: "pending" })
  })

  test("lists only requests eligible for the reviewer at the request scope", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const defaultProject = haven.getProject("demo", "default")!
    const scopedProject = haven.createProject(org.id, "scoped", "Scoped")
    const reviewer = await haven.addMember("demo", {
      username: "scoped-reviewer",
      password: "reviewer-password-12",
      role: "user",
    })
    const root = haven.getHumanByUsername("root")!
    haven.grantAccessAssignment({
      user_id: reviewer.id,
      org_id: org.id,
      project_id: scopedProject.id,
      permission: "approvals.elevated",
      effect: "allow",
      reason: "review scoped project",
      grantor_id: root.id,
    })
    const eligible = haven.createAccessRequest({
      org_id: org.id,
      project_id: scopedProject.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-scoped",
      agent_owner_human_id: root.id,
      policy_decision: approvalDecision(["elevated"]),
    })
    haven.createAccessRequest({
      org_id: org.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-org",
      agent_owner_human_id: root.id,
      policy_decision: approvalDecision(["elevated"]),
    })
    haven.createAccessRequest({
      org_id: org.id,
      project_id: scopedProject.id,
      action: "keys.update",
      actor_type: "human",
      actor_id: reviewer.id,
      requester_human_id: reviewer.id,
      policy_decision: approvalDecision(["elevated"]),
    })
    haven.createAccessRequest({
      org_id: org.id,
      project_id: defaultProject.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-other-project",
      agent_owner_human_id: root.id,
      policy_decision: approvalDecision(["elevated"]),
    })
    const headers = await session(handle, "scoped-reviewer", "reviewer-password-12")

    const response = await handle(
      new Request("http://127.0.0.1/v1/access-requests?org=demo&status=pending", { headers }),
    )
    expect(response.status).toBe(200)
    expect((await response.json()).access_requests.map((request: { id: string }) => request.id)).toEqual([
      eligible.id,
    ])
  })

  test("returns 403 when a human approves their own access request", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const requester = haven.getHumanByUsername("root")!
    const request = haven.createAccessRequest({
      org_id: org.id,
      action: "keys.update",
      actor_type: "human",
      actor_id: requester.id,
      requester_human_id: requester.id,
      policy_decision: approvalDecision(),
    })
    const headers = await session(handle)

    const response = await handle(
      new Request(`http://127.0.0.1/v1/access-requests/${request.id}/approve`, {
        method: "POST",
        headers,
        body: "{}",
      }),
    )
    expect(response.status).toBe(403)
    expect((await response.json()).error).toBe("self_approval")
  })

  test("requires an escalation reason", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const owner = haven.getHumanByUsername("root")!
    const request = haven.createAccessRequest({
      org_id: org.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-http-escalate",
      agent_owner_human_id: owner.id,
      policy_decision: approvalDecision(),
    })
    const headers = await session(handle)

    const response = await handle(
      new Request(`http://127.0.0.1/v1/access-requests/${request.id}/escalate`, {
        method: "POST",
        headers,
        body: JSON.stringify({ tier: "elevated" }),
      }),
    )
    expect(response.status).toBe(400)
    expect((await response.json()).error).toBe("reason_required")
  })

  test("returns 410 for a transition after request expiry", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const owner = haven.getHumanByUsername("root")!
    const request = haven.createAccessRequest({
      org_id: org.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-http-expiry",
      agent_owner_human_id: owner.id,
      policy_decision: approvalDecision(["normal"], 1),
    })
    const headers = await session(handle)
    await Bun.sleep(1_050)

    const response = await handle(
      new Request(`http://127.0.0.1/v1/access-requests/${request.id}/deny`, {
        method: "POST",
        headers,
        body: "{}",
      }),
    )
    expect(response.status).toBe(410)
    expect((await response.json()).error).toBe("request_expired")
  })

  test("enforces the current approval tier permission", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const reviewer = await haven.addMember("demo", {
      username: "normal-reviewer",
      password: "reviewer-password-12",
      role: "user",
    })
    const request = haven.createAccessRequest({
      org_id: org.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-http-tier",
      agent_owner_human_id: reviewer.id,
      policy_decision: approvalDecision(["elevated"]),
    })
    const headers = await session(handle, "normal-reviewer", "reviewer-password-12")

    const response = await handle(
      new Request(`http://127.0.0.1/v1/access-requests/${request.id}/approve`, {
        method: "POST",
        headers,
        body: JSON.stringify({ reason: "reviewed" }),
      }),
    )
    expect(response.status).toBe(403)
    expect((await response.json()).error).toBe("forbidden")
  })
})

describe("secrets and knock HTTP", () => {
  test("user with keys.reveal assignment can reveal; without cannot", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const project = haven.getProject("demo", "default")!
    const key = haven.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "ASSIGNED_REVEAL",
      value: "assigned-plaintext",
    })
    haven.setKeyPolicy(
      key.ref,
      {
        defaults: [{ action: "keys.reveal", actor_type: "human", outcome: "auto_approve" }],
        minimums: [],
      },
      0,
      "test",
    )
    const keyMeta = haven.listKeys("demo", "default", "dev").find((item) => item.ref === key.ref)!
    const alice = await haven.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const root = haven.getHumanByUsername("root")!
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "alice", password: "correct-horse-battery" }),
      }),
    )
    const headers = {
      "content-type": "application/json",
      cookie: cookieFrom(login).split(";")[0],
    }
    const reveal = () =>
      handle(
        new Request("http://127.0.0.1/v1/secrets/reveal", {
          method: "POST",
          headers,
          body: JSON.stringify({ ref: key.ref }),
        }),
      )

    const denied = await reveal()
    expect(denied.status).toBe(403)
    const denial = await denied.json()
    expect(denial.decision_id).toStartWith("dec_")
    expect(JSON.stringify(denial)).not.toContain("assigned-plaintext")
    haven.grantAccessAssignment({
      user_id: alice.id,
      org_id: org.id,
      project_id: project.id,
      key_id: keyMeta.id,
      permission: "keys.reveal",
      effect: "allow",
      reason: "assigned reveal test",
      grantor_id: root.id,
    })
    const allowed = await reveal()
    expect(allowed.status).toBe(200)
    expect(await allowed.json()).toMatchObject({ ref: key.ref, value: "assigned-plaintext" })
  })

  test("project.create denied for user template without grant", async () => {
    const { handle, haven } = await app()
    await haven.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "alice", password: "correct-horse-battery" }),
      }),
    )
    const response = await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/projects", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: cookieFrom(login).split(";")[0],
        },
        body: JSON.stringify({ slug: "denied-project" }),
      }),
    )

    expect(response.status).toBe(403)
    expect((await response.json()).decision_id).toStartWith("dec_")
  })

  test("put then masked list never returns the value", async () => {
    const { handle } = await app()
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]
    const put = await handle(
      new Request("http://127.0.0.1/v1/secrets", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo", project: "default", env: "dev", name: "UI_PING", value: "should-never-list" }),
      }),
    )
    expect(put.status).toBe(200)
    const listed = await handle(
      new Request("http://127.0.0.1/v1/secrets?org=demo&project=default&env=dev", { headers: { cookie } }),
    )
    const text = await listed.text()
    expect(listed.status).toBe(200)
    expect(text).not.toContain("should-never-list")
    expect(JSON.parse(text).secrets).toContainEqual(
      expect.objectContaining({
        id: expect.stringMatching(/^key_/),
        name: "UI_PING",
        ref: "haven://demo/default/dev/UI_PING",
      }),
    )
  })

  test("only superadmins can reveal and delete key values", async () => {
    const { handle, haven } = await app()
    const put = haven.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "SUPERADMIN_ONLY",
      value: "one-time-plaintext",
    })
    haven.setKeyPolicy(
      put.ref,
      {
        defaults: [
          { action: "keys.reveal", actor_type: "human", outcome: "auto_approve" },
          { action: "keys.delete", actor_type: "human", outcome: "auto_approve" },
        ],
        minimums: [],
      },
      0,
      "test",
    )
    const org = haven.getOrgBySlug("demo")!
    await haven.createHuman({ username: "ops", password: "correct-horse-battery", orgId: org.id, role: "admin" })

    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const superCookie = cookieFrom(login).split(";")[0]
    const revealed = await handle(
      new Request("http://127.0.0.1/v1/secrets/reveal", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: superCookie },
        body: JSON.stringify({ ref: put.ref }),
      }),
    )
    expect(revealed.status).toBe(200)
    expect(await revealed.json()).toMatchObject({ ref: put.ref, value: "one-time-plaintext", version: 1 })

    const adminLogin = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "ops", password: "correct-horse-battery" }),
      }),
    )
    const adminCookie = cookieFrom(adminLogin).split(";")[0]
    const forbidden = await handle(
      new Request("http://127.0.0.1/v1/secrets/reveal", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: adminCookie },
        body: JSON.stringify({ ref: put.ref }),
      }),
    )
    expect(forbidden.status).toBe(403)

    const deleted = await handle(
      new Request("http://127.0.0.1/v1/secrets/delete", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: superCookie },
        body: JSON.stringify({ ref: put.ref, confirm_name: "SUPERADMIN_ONLY" }),
      }),
    )
    expect(deleted.status).toBe(200)
    expect(await deleted.json()).toEqual({ ref: put.ref, deleted: true })
    expect(JSON.stringify(haven.ledgerList(10))).not.toContain("one-time-plaintext")
  })

  test("approved human reveal request grants exactly one reveal", async () => {
    const { handle, haven } = await app()
    const put = haven.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "APPROVED_REVEAL",
      value: "one-approved-plaintext",
    })
    haven.setKeyPolicy(
      put.ref,
      {
        defaults: [
          {
            action: "keys.reveal",
            actor_type: "human",
            outcome: "approval_required",
            mode: "threshold",
            tiers: ["elevated"],
            expires_in_seconds: 300,
          },
        ],
        minimums: [],
      },
      0,
      "test",
    )
    const org = haven.getOrgBySlug("demo")!
    const reviewer = await haven.createHuman({
      username: "reviewer",
      password: "correct-horse-battery",
      orgId: org.id,
      role: "admin",
    })
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]
    const reveal = () =>
      handle(
        new Request("http://127.0.0.1/v1/secrets/reveal", {
          method: "POST",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({ ref: put.ref }),
        }),
      )

    const requested = await reveal()
    expect(requested.status).toBe(202)
    const requestedBody = await requested.json()
    expect(requestedBody.access_request_id).toMatch(/^arq_/)
    const stored = haven.listAccessRequests().find((item) => item.id === requestedBody.access_request_id)
    expect(stored).toMatchObject({
      actor_type: "human",
      requester_human_id: haven.getHumanByUsername("root")!.id,
      action: "keys.reveal",
      key_id: expect.stringMatching(/^key_/),
    })

    expect(
      haven.approveAccessRequest(requestedBody.access_request_id, {
        actor_human_id: reviewer.id,
        reason: "approved one-time reveal",
      }).status,
    ).toBe("approved")
    const revealed = await reveal()
    expect(revealed.status).toBe(200)
    expect(await revealed.json()).toMatchObject({ ref: put.ref, value: "one-approved-plaintext" })

    const requestedAgain = await reveal()
    expect(requestedAgain.status).toBe(202)
    expect((await requestedAgain.json()).access_request_id).not.toBe(requestedBody.access_request_id)
  })

  test("pending human reveal request is not reused when the exact policy snapshot changes", async () => {
    const { handle, haven } = await app()
    const put = haven.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "SNAPSHOT_REUSE",
      value: "snapshot-sensitive",
    })
    const approvalPolicy = {
      defaults: [
        {
          action: "keys.reveal",
          actor_type: "human" as const,
          outcome: "approval_required" as const,
          mode: "threshold" as const,
          tiers: ["normal" as const],
        },
      ],
      minimums: [],
    }
    haven.setKeyPolicy(put.ref, approvalPolicy, 0, "test")
    haven.setKeyPolicy(put.ref, approvalPolicy, 1, "test")
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const reveal = () =>
      handle(
        new Request("http://127.0.0.1/v1/secrets/reveal", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: cookieFrom(login).split(";")[0],
          },
          body: JSON.stringify({ ref: put.ref }),
        }),
      )

    const first = await reveal()
    expect(first.status).toBe(202)
    const firstId = (await first.json()).access_request_id
    const firstRequest = haven.listAccessRequests().find((request) => request.id === firstId)!
    expect(firstRequest.policy_version).toBe(2)
    const identical = await reveal()
    expect((await identical.json()).access_request_id).toBe(firstId)

    haven.setOrgPolicy(
      "demo",
      {
        defaults: [{ action: "keys.update", actor_type: "human", outcome: "auto_approve" }],
        minimums: [],
      },
      haven.getOrgPolicy("demo").version,
      "test",
    )

    const second = await reveal()
    expect(second.status).toBe(202)
    const secondId = (await second.json()).access_request_id
    const secondRequest = haven.listAccessRequests().find((request) => request.id === secondId)!
    expect(secondRequest.policy_version).toBe(firstRequest.policy_version)
    expect(secondRequest.policy_snapshot).not.toEqual(firstRequest.policy_snapshot)
    expect(secondId).not.toBe(firstId)
  })

  test("human key update waits for policy approval before changing the value", async () => {
    const { handle, haven } = await app()
    const put = haven.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "APPROVED_UPDATE",
      value: "before",
    })
    haven.setKeyPolicy(
      put.ref,
      {
        defaults: [
          {
            action: "keys.update",
            actor_type: "human",
            outcome: "approval_required",
            mode: "threshold",
            tiers: ["normal"],
          },
        ],
        minimums: [],
      },
      0,
      "test",
    )
    const org = haven.getOrgBySlug("demo")!
    const reviewer = await haven.createHuman({
      username: "update-reviewer",
      password: "correct-horse-battery",
      orgId: org.id,
      role: "user",
    })
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]
    const update = () =>
      handle(
        new Request("http://127.0.0.1/v1/secrets", {
          method: "POST",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify({
            org: "demo",
            project: "default",
            env: "dev",
            name: "APPROVED_UPDATE",
            value: "after",
          }),
        }),
      )

    const requested = await update()
    expect(requested.status).toBe(202)
    const requestId = (await requested.json()).access_request_id
    expect(haven.readKeyValue(put.ref)).toBe("before")

    expect(haven.approveAccessRequest(requestId, { actor_human_id: reviewer.id }).status).toBe("approved")
    expect((await update()).status).toBe(200)
    expect(haven.readKeyValue(put.ref)).toBe("after")
  })

  test("human delete denied by policy leaves the key intact", async () => {
    const { handle, haven } = await app()
    const put = haven.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "DENIED_DELETE",
      value: "still-present",
    })
    haven.setKeyPolicy(
      put.ref,
      {
        defaults: [{ action: "keys.delete", actor_type: "human", outcome: "deny" }],
        minimums: [],
      },
      0,
      "test",
    )
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const response = await handle(
      new Request("http://127.0.0.1/v1/secrets/delete", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: cookieFrom(login).split(";")[0] },
        body: JSON.stringify({ ref: put.ref, confirm_name: "DENIED_DELETE" }),
      }),
    )

    expect(response.status).toBe(403)
    expect(haven.readKeyValue(put.ref)).toBe("still-present")
  })

  test("knock auto-allow then resolve", async () => {
    const { handle, haven } = await app()
    haven.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    haven.setOrgGuardrail("demo", {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 120,
      require_approval: false,
      on_exposure: "queue",
    })
    haven.createAgent({ name: "pilot", owner: "admin", purpose: "read", risk_tier: "low", scopes: ["secrets:read"] })
    const knocked = await handle(
      new Request("http://127.0.0.1/v1/knock", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          org: "demo",
          project: "default",
          agent_name: "pilot",
          purpose: "read ping",
          need: [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }],
        }),
      }),
    )
    expect(knocked.status).toBe(200)
    const k = await knocked.json()
    expect(k.status).toBe("auto_allow")
    expect(k.token.startsWith("haven_")).toBe(true)
    const resolved = await handle(
      new Request("http://127.0.0.1/v1/secrets/resolve", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: k.token, resource: "haven://demo/default/dev/PING" }),
      }),
    )
    const body = await resolved.json()
    expect(resolved.status).toBe(200)
    expect(body.allow).toBe(true)
    expect(body.value).toBe("dock")
  })
})

describe("org-scoped operator routes", () => {
  test("org A admin cannot see or revoke org B agents and grants", async () => {
    const { handle, haven } = await app()
    const demoOrg = haven.getOrgBySlug("demo")!
    const other = haven.createOrg("other", "Other")
    haven.createProject(other.id, "default", "default")
    const demoAgent = haven.createAgent({
      name: "demo-agent",
      owner: "admin",
      purpose: "demo work",
      org_id: demoOrg.id,
      risk_tier: "low",
      scopes: ["secrets:read"],
    })
    const otherAgent = haven.createAgent({
      name: "other-agent",
      owner: "other",
      purpose: "other work",
      org_id: other.id,
      risk_tier: "low",
      scopes: ["secrets:read"],
    })
    const demoResource = "haven://demo/default/dev/DEMO_KEY"
    const otherResource = "haven://other/default/dev/OTHER_KEY"
    haven.grantResource(demoAgent.id, demoResource)
    haven.grantResource(otherAgent.id, otherResource)

    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]

    const agents = await handle(new Request("http://127.0.0.1/v1/agents?org=demo", { headers: { cookie } }))
    expect(agents.status).toBe(200)
    expect((await agents.json()).agents.map((agent: { id: string }) => agent.id)).toEqual([demoAgent.id])

    const hiddenAgent = await handle(
      new Request(`http://127.0.0.1/v1/agents/${otherAgent.id}?org=demo`, { headers: { cookie } }),
    )
    expect(hiddenAgent.status).toBe(404)

    const revokeAgent = await handle(
      new Request(`http://127.0.0.1/v1/agents/${otherAgent.id}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(revokeAgent.status).toBe(404)
    expect(haven.getAgent(otherAgent.id)?.status).toBe("active")

    const grants = await handle(
      new Request("http://127.0.0.1/v1/resources?org=demo", { headers: { cookie } }),
    )
    expect(grants.status).toBe(200)
    expect((await grants.json()).grants).toEqual([
      expect.objectContaining({ agent_id: demoAgent.id, resource: demoResource }),
    ])

    const revokeGrant = await handle(
      new Request("http://127.0.0.1/v1/resources/revoke", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo", agent_id: otherAgent.id, resource: otherResource }),
      }),
    )
    expect(revokeGrant.status).toBe(404)
    expect(haven.listResourceGrants(otherAgent.id)).toContainEqual(
      expect.objectContaining({ agent_id: otherAgent.id, resource: otherResource }),
    )

    const crossOrgResource = await handle(
      new Request("http://127.0.0.1/v1/resources/grant", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo", agent_id: demoAgent.id, resource: otherResource }),
      }),
    )
    expect(crossOrgResource.status).toBe(400)
  })

  test("API keys and ledger results are scoped to the authorized org", async () => {
    const { handle, haven } = await app()
    const demoOrg = haven.getOrgBySlug("demo")!
    const other = haven.createOrg("other", "Other")
    haven.createProject(other.id, "default", "default")
    const otherKey = haven.mintApiKey("other-key", other.id)
    haven.ledgerAppend("test.demo", { detail: { org_id: demoOrg.id, marker: "demo-only" } })
    haven.ledgerAppend("test.other", { detail: { org_id: other.id, marker: "other-only" } })

    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]
    const minted = await handle(
      new Request("http://127.0.0.1/v1/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo", name: "demo-key" }),
      }),
    )
    expect(minted.status).toBe(201)

    const keys = await handle(new Request("http://127.0.0.1/v1/api-keys?org=demo", { headers: { cookie } }))
    expect(keys.status).toBe(200)
    const keyIds = (await keys.json()).keys.map((key: { id: string }) => key.id)
    expect(keyIds).toContain((await minted.clone().json()).id)
    expect(keyIds).not.toContain(otherKey.id)

    const revoke = await handle(
      new Request(`http://127.0.0.1/v1/api-keys/${otherKey.id}/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo" }),
      }),
    )
    expect(revoke.status).toBe(404)
    expect(haven.listApiKeys(other.id)).toContainEqual(expect.objectContaining({ id: otherKey.id, status: "active" }))

    const ledger = await handle(
      new Request("http://127.0.0.1/v1/ledger?org=demo&limit=100", { headers: { cookie } }),
    )
    expect(ledger.status).toBe(200)
    const ledgerText = JSON.stringify(await ledger.json())
    expect(ledgerText).toContain("demo-only")
    expect(ledgerText).not.toContain("other-only")

    const verification = await handle(
      new Request("http://127.0.0.1/v1/ledger/verify?org=demo", { headers: { cookie } }),
    )
    expect(verification.status).toBe(200)
    expect(await verification.json()).toMatchObject({ valid: true })

    await haven.createHuman({
      username: "other-user",
      password: "correct-horse-battery",
      orgId: other.id,
      role: "user",
    })
    const otherLogin = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "other-user", password: "correct-horse-battery" }),
      }),
    )
    const deniedLedger = await handle(
      new Request("http://127.0.0.1/v1/ledger?org=other", {
        headers: { cookie: cookieFrom(otherLogin).split(";")[0] },
      }),
    )
    expect(deniedLedger.status).toBe(403)
    const deniedVerification = await handle(
      new Request("http://127.0.0.1/v1/ledger/verify?org=other", {
        headers: { cookie: cookieFrom(otherLogin).split(";")[0] },
      }),
    )
    expect(deniedVerification.status).toBe(403)
  })

  test("knock decisions require a human session before loading the knock", async () => {
    const { handle, haven } = await app()
    const demoOrg = haven.getOrgBySlug("demo")!
    haven.setOrgGuardrail("demo", {
      default: "approve",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 120,
      require_approval: true,
      on_exposure: "queue",
    })
    const knock = haven.knock({
      org: "demo",
      project: "default",
      agent_name: "pending-agent",
      purpose: "request access",
      need: [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }],
    })
    const apiKey = haven.mintApiKey("machine-only", demoOrg.id)
    const headers = { Authorization: `Bearer ${apiKey.token}` }

    const missing = await handle(
      new Request("http://127.0.0.1/v1/knocks/missing/approve", { method: "POST", headers }),
    )
    const existing = await handle(
      new Request(`http://127.0.0.1/v1/knocks/${knock.id}/approve`, { method: "POST", headers }),
    )
    expect(missing.status).toBe(401)
    expect(existing.status).toBe(401)
  })

  test("legacy knock decisions require the linked request's current approval tier", async () => {
    const { handle, haven } = await app()
    const org = haven.getOrgBySlug("demo")!
    const project = haven.getProject("demo", "default")!
    haven.setOrgPolicy(
      "demo",
      {
        defaults: [
          {
            action: "keys.resolve",
            actor_type: "agent",
            outcome: "approval_required",
            mode: "threshold",
            tiers: ["elevated"],
          },
        ],
        minimums: [],
      },
      haven.getOrgPolicy("demo").version,
      "test",
    )
    haven.createAgent({
      name: "elevated-agent",
      owner: "admin",
      purpose: "elevated request",
      risk_tier: "high",
      scopes: ["secrets:read"],
      org_id: org.id,
      project_id: project.id,
    })
    const reviewer = await haven.createHuman({
      username: "normal-reviewer",
      password: "correct-horse-battery",
      orgId: org.id,
      role: "user",
    })
    const root = haven.getHumanByUsername("root")!
    haven.grantAccessAssignment({
      user_id: reviewer.id,
      org_id: org.id,
      project_id: project.id,
      permission: "approvals.normal",
      effect: "deny",
      reason: "elevated-only reviewer",
      grantor_id: root.id,
    })
    haven.grantAccessAssignment({
      user_id: reviewer.id,
      org_id: org.id,
      project_id: project.id,
      permission: "approvals.elevated",
      effect: "allow",
      reason: "elevated reviewer",
      grantor_id: root.id,
    })
    const knock = haven.knock({
      org: "demo",
      project: "default",
      agent_name: "elevated-agent",
      purpose: "elevated access",
      need: [{ action: "secrets:read", scope: "haven://demo/default/dev/" }],
    })
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: reviewer.username, password: "correct-horse-battery" }),
      }),
    )

    const response = await handle(
      new Request(`http://127.0.0.1/v1/knocks/${knock.id}/approve`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: cookieFrom(login).split(";")[0],
        },
        body: JSON.stringify({ reason: "elevated review complete" }),
      }),
    )

    expect(response.status).toBe(200)
    expect(haven.getKnock(knock.id)?.status).toBe("approved")
  })
})

describe("activity API keys", () => {
  test("operator mints a key that can ingest activity, not secrets", async () => {
    const { handle } = await app()
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]
    const minted = await handle(
      new Request("http://127.0.0.1/v1/api-keys", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo", name: "test-ingest" }),
      }),
    )
    expect(minted.status).toBe(201)
    const keyBody = await minted.json()
    expect(keyBody.token.startsWith("haven_ak_")).toBe(true)
    const posted = await handle(
      new Request("http://127.0.0.1/v1/activity", {
        method: "POST",
        headers: { "content-type": "application/json", Authorization: `Bearer ${keyBody.token}` },
        body: JSON.stringify({
          type: "activity.agent_run",
          action: "complete",
          resource: "agent/kai",
          outcome: "success",
          detail: { note: "ok", value: "should-strip" },
        }),
      }),
    )
    expect(posted.status).toBe(201)
    expect(JSON.stringify(await posted.json())).not.toContain("should-strip")
    const secrets = await handle(
      new Request("http://127.0.0.1/v1/secrets?org=demo&project=default&env=dev", {
        headers: { Authorization: `Bearer ${keyBody.token}` },
      }),
    )
    expect(secrets.status).toBe(401)
  })

  test("activity reads only return events from the API key organization", async () => {
    const { handle, haven } = await app()
    const demoOrg = haven.getOrgBySlug("demo")!
    const other = haven.createOrg("other", "Other")
    haven.createProject(other.id, "default", "default")
    const demoKey = haven.mintApiKey("demo-activity", demoOrg.id)
    const otherKey = haven.mintApiKey("other-activity", other.id)

    for (const [token, marker] of [
      [demoKey.token, "demo-event"],
      [otherKey.token, "other-event"],
    ]) {
      const posted = await handle(
        new Request("http://127.0.0.1/v1/activity", {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: JSON.stringify({
            type: "activity.tenant_test",
            outcome: "info",
            detail: { marker },
          }),
        }),
      )
      expect(posted.status).toBe(201)
    }

    const response = await handle(
      new Request("http://127.0.0.1/v1/activity?limit=100", {
        headers: { authorization: `Bearer ${demoKey.token}` },
      }),
    )
    expect(response.status).toBe(200)
    const text = JSON.stringify(await response.json())
    expect(text).toContain("demo-event")
    expect(text).not.toContain("other-event")
  })
})

describe("standing token mint", () => {
  test("superadmin in one org cannot mint a token for another org's agent", async () => {
    const { handle, haven } = await app()
    const other = haven.createOrg("other", "Other")
    const project = haven.createProject(other.id, "default", "default")
    const agent = haven.createAgent({
      name: "other-agent",
      owner: "other-owner",
      purpose: "other tenant",
      risk_tier: "low",
      scopes: ["secrets:read"],
      org_id: other.id,
      project_id: project.id,
    })
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )

    const response = await handle(
      new Request("http://127.0.0.1/v1/tokens", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: cookieFrom(login).split(";")[0],
        },
        body: JSON.stringify({ agent_id: agent.id, ttl_seconds: 300 }),
      }),
    )

    expect(response.status).toBe(403)
  })
})

describe("buoy HTTP", () => {
  test("watch package only includes canaries from the authenticated buoy organization", async () => {
    const { handle, haven } = await app()
    const otherOrg = haven.createOrg("other", "Other")
    haven.createProject(otherOrg.id, "default", "default")
    const ownCanary = haven.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "decoy_key",
      decoy: "demo-canary-decoy",
    }).canary
    const otherCanary = haven.plantCanary({
      orgSlug: "other",
      projectSlug: "default",
      mode: "decoy_key",
      decoy: "other-canary-decoy",
    }).canary
    const registration = await haven.registerBuoy({
      orgSlug: "demo",
      kind: "harbor",
      name: "demo-harbor",
    })

    const response = await handle(
      new Request("http://127.0.0.1/v1/watch-packages/current", {
        headers: {
          authorization: `Bearer ${registration.token}`,
          "x-haven-buoy-id": registration.buoy.id,
        },
      }),
    )
    expect(response.status).toBe(200)
    const pkg = await response.json()
    expect(pkg.audience).toBe("harbor")
    expect(pkg.canaries.map((canary: { canary_id: string }) => canary.canary_id)).toEqual([ownCanary.id])
    expect(JSON.stringify(pkg)).not.toContain(otherCanary.digest)
    expect(JSON.stringify(pkg)).not.toContain(otherCanary.key_ref)
  })

  test("watch package rejects invalid and mismatched audiences", async () => {
    const { handle, haven } = await app()
    const registration = await haven.registerBuoy({
      orgSlug: "demo",
      kind: "harbor",
      name: "audience-harbor",
    })
    const headers = {
      authorization: `Bearer ${registration.token}`,
      "x-haven-buoy-id": registration.buoy.id,
    }

    const invalid = await handle(
      new Request("http://127.0.0.1/v1/watch-packages/current?audience=unknown", { headers }),
    )
    expect(invalid.status).toBe(400)
    expect((await invalid.json()).error).toBe("invalid_query")

    const mismatched = await handle(
      new Request("http://127.0.0.1/v1/watch-packages/current?audience=custom", { headers }),
    )
    expect(mismatched.status).toBe(400)

    const all = await handle(
      new Request("http://127.0.0.1/v1/watch-packages/current?audience=all", { headers }),
    )
    expect(all.status).toBe(200)
  })

  test("buoy routes reject a valid token without X-Haven-Buoy-Id", async () => {
    const { handle, haven } = await app()
    const registration = await haven.registerBuoy({
      orgSlug: "demo",
      kind: "harbor",
      name: "header-required-harbor",
    })

    const response = await handle(
      new Request("http://127.0.0.1/v1/watch-packages/current", {
        headers: { authorization: `Bearer ${registration.token}` },
      }),
    )

    expect(response.status).toBe(401)
    expect((await response.json()).message).toContain("X-Haven-Buoy-Id")
  })

  test("registers, plants, serves a package, ingests a sighting, and lists remediation", async () => {
    const { handle } = await app()
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    const cookie = cookieFrom(login).split(";")[0]

    const registered = await handle(
      new Request("http://127.0.0.1/v1/buoys", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ org: "demo", kind: "harbor", name: "test-harbor" }),
      }),
    )
    expect(registered.status).toBe(201)
    const registration = await registered.json()
    expect(registration.token).toStartWith("haven_buoy_")
    expect(registration.package_public_key).toMatch(/^[0-9a-f]+$/)

    const planted = await handle(
      new Request("http://127.0.0.1/v1/canaries", {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({
          org: "demo",
          project: "default",
          mode: "decoy_key",
          decoy: "http-route-decoy",
        }),
      }),
    )
    expect(planted.status).toBe(201)
    const planting = await planted.json()
    expect(planting.canary.digest).toBeString()

    const buoyHeaders = {
      authorization: `Bearer ${registration.token}`,
      "x-haven-buoy-id": registration.buoy.id,
    }
    const packaged = await handle(
      new Request("http://127.0.0.1/v1/watch-packages/current?audience=harbor", {
        headers: buoyHeaders,
      }),
    )
    expect(packaged.status).toBe(200)
    expect(packaged.headers.get("x-haven-buoy-id")).toBe(registration.buoy.id)
    const pkg = await packaged.json()
    expect(pkg.canaries).toContainEqual({
      canary_id: planting.canary.id,
      digest: planting.canary.digest,
      revoked: false,
    })

    const sighted = await handle(
      new Request("http://127.0.0.1/v1/sightings", {
        method: "POST",
        headers: { ...buoyHeaders, "content-type": "application/json" },
        body: JSON.stringify({
          buoy_id: registration.buoy.id,
          canary_id: planting.canary.id,
          digest: planting.canary.digest,
          observed_at: new Date().toISOString(),
          context: { source: "file", path: "/tmp/canary-fixture" },
        }),
      }),
    )
    expect(sighted.status).toBe(201)
    const sighting = await sighted.json()
    expect(sighting.remediation.status).toBe("open")

    const listed = await handle(
      new Request("http://127.0.0.1/v1/remediations?org=demo&status=open", {
        headers: { cookie },
      }),
    )
    expect(listed.status).toBe(200)
    expect((await listed.json()).remediations).toContainEqual(sighting.remediation)
  })
})

describe("policy HTTP API", () => {
  async function policySession(handle: (req: Request) => Promise<Response>) {
    const login = await handle(
      new Request("http://127.0.0.1/v1/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
      }),
    )
    return {
      "content-type": "application/json",
      cookie: cookieFrom(login).split(";")[0],
    }
  }

  test("org policy PUT uses optimistic concurrency and exposes history", async () => {
    const { handle } = await app()
    const headers = await policySession(handle)
    const current = await handle(new Request("http://127.0.0.1/v1/orgs/demo/policy", { headers }))
    expect(current.status).toBe(200)
    const initial = await current.json()
    const document = {
      defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "auto_approve" }],
      minimums: [],
    }

    const update = () =>
      handle(
        new Request("http://127.0.0.1/v1/orgs/demo/policy", {
          method: "PUT",
          headers,
          body: JSON.stringify({ document, expected_version: initial.version }),
        }),
      )
    const written = await update()
    expect(written.status).toBe(200)
    expect(await written.json()).toMatchObject({ version: initial.version + 1, document })

    const stale = await update()
    expect(stale.status).toBe(409)
    expect((await stale.json()).error).toBe("policy_version_conflict")

    const history = await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/policy/history", { headers }),
    )
    expect(history.status).toBe(200)
    expect((await history.json()).history).toEqual([
      expect.objectContaining({ version: initial.version + 1, document }),
      expect.objectContaining({ version: initial.version }),
    ])
  })

  test("preview warns when a parent minimum neutralizes a child default", async () => {
    const { handle } = await app()
    const headers = await policySession(handle)
    const org = await (
      await handle(new Request("http://127.0.0.1/v1/orgs/demo/policy", { headers }))
    ).json()
    await handle(
      new Request("http://127.0.0.1/v1/orgs/demo/policy", {
        method: "PUT",
        headers,
        body: JSON.stringify({
          expected_version: org.version,
          document: {
            defaults: [],
            minimums: [{ action: "keys.delete", actor_type: "human", min: "elevated" }],
          },
        }),
      }),
    )

    const preview = await handle(
      new Request("http://127.0.0.1/v1/policies/preview", {
        method: "POST",
        headers,
        body: JSON.stringify({
          org: "demo",
          project: "default",
          candidate_scope: "project",
          candidate: {
            defaults: [{ action: "keys.delete", actor_type: "human", outcome: "auto_approve" }],
            minimums: [],
          },
          action: "keys.delete",
          actor_type: "human",
        }),
      }),
    )
    expect(preview.status).toBe(200)
    expect(await preview.json()).toMatchObject({
      outcome: "approval_required",
      tiers: ["elevated"],
      warnings: [expect.objectContaining({ code: "parent_minimum_neutralizes_candidate" })],
    })
  })

  test("preview fails closed when a referenced key does not exist", async () => {
    const { handle } = await app()
    const headers = await policySession(handle)
    const preview = await handle(
      new Request("http://127.0.0.1/v1/policies/preview", {
        method: "POST",
        headers,
        body: JSON.stringify({
          org: "demo",
          key_ref: "haven://demo/default/dev/MISSING",
          action: "keys.resolve",
          actor_type: "agent",
        }),
      }),
    )

    expect(preview.status).toBe(404)
    expect((await preview.json()).error).toBe("not_found")
  })

  test("key policy routes use the stable key id and enforce stale writes", async () => {
    const { handle, haven } = await app()
    const headers = await policySession(handle)
    haven.putKey({ org: "demo", project: "default", env: "dev", name: "POLICY_KEY", value: "opaque" })
    const key = haven.listKeys("demo", "default", "dev").find((item) => item.name === "POLICY_KEY")!
    const current = await handle(new Request(`http://127.0.0.1/v1/keys/${key.id}/policy`, { headers }))
    expect(current.status).toBe(200)
    expect(await current.json()).toMatchObject({ scope_type: "key", scope_id: key.id })

    const saved = await handle(
      new Request(`http://127.0.0.1/v1/keys/${key.id}/policy`, {
        method: "PUT",
        headers,
        body: JSON.stringify({
          expected_version: 0,
          document: {
            defaults: [{ action: "keys.reveal", actor_type: "human", outcome: "approval_required", tiers: ["normal"] }],
            minimums: [],
          },
        }),
      }),
    )
    expect(saved.status).toBe(200)
    expect(await saved.json()).toMatchObject({ scope_id: key.id, version: 1 })
  })
})
