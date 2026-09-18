import { afterEach, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { evaluateHumanAuthorization, type AccessAssignment } from "./authorization.ts"
import { createHaven } from "./haven.ts"

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function openTestHaven() {
  const dataDir = mkdtempSync(join(tmpdir(), "haven-authz-"))
  dirs.push(dataDir)
  return createHaven({
    dataDir,
    tokenSecret: "token-secret-not-a-placeholder-32bxx",
    rootKeyHex: "ab".repeat(32),
    bootstrapUser: "root",
    bootstrapPassword: "correct-horse-battery",
    bootstrapOrg: "demo",
  })
}

describe("human authorization", () => {
  test("org grant inherits to project key unless denied", async () => {
    const h = await openTestHaven()
    const org = h.getOrgBySlug("demo")!
    const proj = h.listProjects("demo")[0]
    h.putKey({ org: "demo", project: proj.slug, env: "dev", name: "X", value: "v" })
    const key = h.listKeys("demo", proj.slug, "dev").find((k) => k.name === "X")!
    const member = await h.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const root = h.getHumanByUsername("root")!

    h.grantAccessAssignment({
      user_id: member.id,
      org_id: org.id,
      permission: "keys.reveal",
      effect: "allow",
      reason: "breakglass drill",
      grantor_id: root.id,
    })
    expect(
      h.authorizeHuman(member.id, "keys.reveal", { orgId: org.id, projectId: proj.id, keyId: key.id }).allow,
    ).toBe(true)

    h.grantAccessAssignment({
      user_id: member.id,
      org_id: org.id,
      project_id: proj.id,
      key_id: key.id,
      permission: "keys.reveal",
      effect: "deny",
      reason: "lock this key",
      grantor_id: root.id,
    })
    const denied = h.authorizeHuman(member.id, "keys.reveal", {
      orgId: org.id,
      projectId: proj.id,
      keyId: key.id,
    })
    expect(denied.allow).toBe(false)
    expect(denied.reason).toBe("explicit_deny")
    expect(denied.matched.denies).toHaveLength(1)
  })

  test("expired assignment is ignored", async () => {
    const h = await openTestHaven()
    const org = h.getOrgBySlug("demo")!
    const member = await h.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })

    h.grantAccessAssignment({
      user_id: member.id,
      org_id: org.id,
      permission: "keys.reveal",
      effect: "allow",
      reason: "temporary reveal",
      grantor_id: h.getHumanByUsername("root")!.id,
      expires_at: "2000-01-01T00:00:00.000Z",
    })

    const decision = h.authorizeHuman(member.id, "keys.reveal", { orgId: org.id })
    expect(decision.allow).toBe(false)
    expect(decision.reason).toBe("missing_permission")
    expect(decision.matched.expired).toHaveLength(1)
  })

  test("revoked assignment is ignored", async () => {
    const h = await openTestHaven()
    const org = h.getOrgBySlug("demo")!
    const root = h.getHumanByUsername("root")!
    const member = await h.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const assignment = h.grantAccessAssignment({
      user_id: member.id,
      org_id: org.id,
      permission: "keys.reveal",
      effect: "allow",
      reason: "temporary reveal",
      grantor_id: root.id,
    })

    h.revokeAccessAssignment(assignment.id, {
      revoked_by: root.id,
      reason: "drill complete",
    })

    expect(h.authorizeHuman(member.id, "keys.reveal", { orgId: org.id }).allow).toBe(false)
    expect(h.listAccessAssignments(member.id, org.id)[0].revoked_at).not.toBeNull()
    expect(h.ledgerList(10).some((event) => event.type === "access.revoked")).toBe(true)
  })

  test("root superadmin cannot be stripped of org.permissions.manage", async () => {
    const h = await openTestHaven()
    const org = h.getOrgBySlug("demo")!
    const root = h.getHumanByUsername("root")!

    expect(() =>
      h.grantAccessAssignment({
        user_id: root.id,
        org_id: org.id,
        permission: "org.permissions.manage",
        effect: "deny",
        reason: "remove root access",
        grantor_id: root.id,
      }),
    ).toThrow("lockout_prevented")

    expect(h.authorizeHuman(root.id, "org.permissions.manage", { orgId: org.id }).allow).toBe(true)
    expect(h.ledgerList(10).some((event) => event.type === "access.lockout_prevented")).toBe(true)

    const grant = h.grantAccessAssignment({
      user_id: root.id,
      org_id: org.id,
      permission: "org.permissions.manage",
      effect: "allow",
      reason: "record explicit root access",
      grantor_id: root.id,
    })
    expect(() =>
      h.revokeAccessAssignment(grant.id, {
        revoked_by: root.id,
        reason: "remove root access",
      }),
    ).toThrow("lockout_prevented")
  })

  test("unknown permissions fail closed", async () => {
    const h = await openTestHaven()
    const org = h.getOrgBySlug("demo")!
    const root = h.getHumanByUsername("root")!

    const decision = h.explainAccess(root.id, "not.a.permission", { orgId: org.id })
    expect(decision.allow).toBe(false)
    expect(decision.reason).toBe("unknown_permission")
  })

  test("malformed role data fails closed", () => {
    const decision = evaluateHumanAuthorization({
      decisionId: "dec_test",
      permission: "projects.list",
      resource: { orgId: "org_test" },
      role: "owner" as never,
      assignments: [],
    })

    expect(decision.allow).toBe(false)
    expect(decision.reason).toBe("missing_permission")
  })

  test("applicable assignments with malformed expiry or effect fail closed", () => {
    const baseAssignment: AccessAssignment = {
      id: "asg_test",
      user_id: "human_test",
      org_id: "org_test",
      project_id: null,
      key_id: null,
      permission: "projects.list",
      effect: "allow",
      reason: "stored only",
      grantor_id: "human_root",
      created_at: "2026-08-14T00:00:00.000Z",
      expires_at: null,
      revoked_at: null,
      revoked_by: null,
    }

    for (const assignment of [
      { ...baseAssignment, expires_at: "not-a-date" },
      { ...baseAssignment, effect: "unexpected" as never },
    ]) {
      const decision = evaluateHumanAuthorization({
        decisionId: "dec_test",
        permission: "projects.list",
        resource: { orgId: "org_test" },
        role: "superadmin",
        assignments: [assignment],
      })

      expect(decision.allow).toBe(false)
      expect(decision.reason).toBe("malformed_assignment")
      expect(decision.matched.malformed).toHaveLength(1)
    }
  })

  test("empty project and key resource IDs fail closed", () => {
    for (const resource of [
      { orgId: "org_test", projectId: "" },
      { orgId: "org_test", projectId: "project_test", keyId: "" },
    ]) {
      const decision = evaluateHumanAuthorization({
        decisionId: "dec_test",
        permission: "projects.list",
        resource,
        role: "superadmin",
        assignments: [],
      })

      expect(decision.allow).toBe(false)
      expect(decision.reason).toBe("invalid_resource")
    }
  })

  test("ledger and explain output omit assignment and revocation reasons", async () => {
    const h = await openTestHaven()
    const org = h.getOrgBySlug("demo")!
    const root = h.getHumanByUsername("root")!
    const member = await h.addMember("demo", {
      username: "alice",
      password: "correct-horse-battery",
      role: "user",
    })
    const secretLikeReason = "credential=super-secret-value"
    const assignment = h.grantAccessAssignment({
      user_id: member.id,
      org_id: org.id,
      permission: "keys.reveal",
      effect: "allow",
      reason: secretLikeReason,
      grantor_id: root.id,
    })

    expect(JSON.stringify(h.explainAccess(member.id, "keys.reveal", { orgId: org.id }))).not.toContain(secretLikeReason)
    h.revokeAccessAssignment(assignment.id, { revoked_by: root.id, reason: secretLikeReason })
    expect(JSON.stringify(h.ledgerList(20))).not.toContain(secretLikeReason)
  })
})
