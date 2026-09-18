import { afterEach, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createHaven, type Haven } from "./haven.ts"
import type { ApprovalMode, ApprovalTier } from "./types.ts"

const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function openTestHaven() {
  const dataDir = mkdtempSync(join(tmpdir(), "haven-access-request-"))
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

async function humans(haven: Haven) {
  const org = haven.getOrgBySlug("demo")!
  const project = haven.getProject("demo", "default")!
  const rootUser = (await haven.verifyPassword("root", "correct-horse-battery"))!
  const admin = await haven.createHuman({
    username: "admin",
    password: "admin-password-12",
    orgId: org.id,
    role: "admin",
  })
  const reviewer = await haven.createHuman({
    username: "reviewer",
    password: "reviewer-password-12",
    orgId: org.id,
    role: "user",
  })
  return { org, project, rootUser, admin, reviewer }
}

function approvalDecision(
  mode: ApprovalMode,
  tiers: ApprovalTier[],
  policyVersion = 1,
) {
  return {
    outcome: "approval_required" as const,
    reason: "default_approval",
    mode,
    tiers,
    reason_required: tiers.some((tier) => tier !== "normal"),
    policy_version: policyVersion,
    snapshot: {
      org: {
        defaults: [
          {
            action: "keys.resolve",
            actor_type: "agent" as const,
            outcome: "approval_required" as const,
            mode,
            tiers,
          },
        ],
        minimums: [],
      },
      project: null,
      key: null,
    },
  }
}

describe("access request workflow", () => {
  test("threshold elevated requires approvals.elevated at scope", async () => {
    const haven = await openTestHaven()
    const { org, project, admin, reviewer } = await humans(haven)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-1",
      agent_owner_human_id: reviewer.id,
      policy_decision: approvalDecision("threshold", ["elevated"]),
    })

    expect(() =>
      haven.approveAccessRequest(request.id, {
        actor_human_id: reviewer.id,
        reason: "reviewed",
      }),
    ).toThrow(/forbidden/)
    expect(
      haven.approveAccessRequest(request.id, {
        actor_human_id: admin.id,
        reason: "reviewed",
      }).status,
    ).toBe("approved")
  })

  test("sequential requires distinct humans per stage", async () => {
    const haven = await openTestHaven()
    const { org, project, rootUser, admin } = await humans(haven)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-2",
      agent_owner_human_id: rootUser.id,
      policy_decision: approvalDecision("sequential", ["normal", "elevated"]),
    })

    const staged = haven.approveAccessRequest(request.id, {
      actor_human_id: admin.id,
      reason: "first stage",
    })
    expect(staged).toMatchObject({ status: "pending", stage_index: 1 })
    expect(() =>
      haven.approveAccessRequest(request.id, {
        actor_human_id: admin.id,
        reason: "second stage",
      }),
    ).toThrow(/same_approver/)
    expect(
      haven.approveAccessRequest(request.id, {
        actor_human_id: rootUser.id,
        reason: "second stage",
      }).status,
    ).toBe("approved")
  })

  test("human cannot approve own human request", async () => {
    const haven = await openTestHaven()
    const { org, project, admin } = await humans(haven)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.update",
      actor_type: "human",
      actor_id: admin.id,
      requester_human_id: admin.id,
      policy_decision: approvalDecision("threshold", ["normal"]),
    })

    expect(() =>
      haven.approveAccessRequest(request.id, { actor_human_id: admin.id }),
    ).toThrow(/self_approval/)
  })

  test("agent owner may approve agent request", async () => {
    const haven = await openTestHaven()
    const { org, project, reviewer } = await humans(haven)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-3",
      agent_owner_human_id: reviewer.id,
      policy_decision: approvalDecision("threshold", ["normal"]),
    })

    expect(
      haven.approveAccessRequest(request.id, {
        actor_human_id: reviewer.id,
      }).status,
    ).toBe("approved")
  })

  test("escalation is upward-only and does not count as approval", async () => {
    const haven = await openTestHaven()
    const { org, project, admin } = await humans(haven)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-4",
      agent_owner_human_id: admin.id,
      policy_decision: approvalDecision("threshold", ["normal"]),
    })

    expect(() =>
      haven.escalateAccessRequest(request.id, {
        actor_human_id: admin.id,
        tier: "elevated",
        reason: "",
      }),
    ).toThrow(/reason_required/)
    const escalated = haven.escalateAccessRequest(request.id, {
      actor_human_id: admin.id,
      tier: "elevated",
      reason: "higher risk",
    })
    expect(escalated).toMatchObject({
      status: "pending",
      stage_index: 0,
      tiers: ["elevated"],
    })
    expect(escalated.events.filter((event) => event.type === "approved_stage")).toHaveLength(0)
    expect(() =>
      haven.escalateAccessRequest(request.id, {
        actor_human_id: admin.id,
        tier: "normal",
        reason: "lower",
      }),
    ).toThrow(/escalation_not_upward/)
  })

  test("policy change does not mutate pending snapshot", async () => {
    const haven = await openTestHaven()
    const { org, project, reviewer } = await humans(haven)
    const decision = approvalDecision("threshold", ["normal"], 7)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-5",
      agent_owner_human_id: reviewer.id,
      policy_decision: decision,
    })
    decision.snapshot.org!.defaults[0].tiers = ["breakglass"]
    haven.setOrgPolicy(
      "demo",
      {
        defaults: [
          {
            action: "keys.resolve",
            actor_type: "agent",
            outcome: "deny",
          },
        ],
        minimums: [],
      },
      haven.getOrgPolicy("demo").version,
      reviewer.id,
    )

    const pending = haven.listAccessRequests({ org_id: org.id })[0]
    expect(pending.policy_version).toBe(7)
    expect(pending.policy_snapshot).toEqual(request.policy_snapshot)
    expect(pending.tiers).toEqual(["normal"])
  })

  test("cancel and deny are final fail-closed transitions", async () => {
    const haven = await openTestHaven()
    const { org, project, admin } = await humans(haven)
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-6",
      agent_owner_human_id: admin.id,
      policy_decision: approvalDecision("threshold", ["normal"]),
    })
    const cancelled = haven.cancelAccessRequest(request.id, {
      actor_human_id: admin.id,
      reason: "policy changed",
    })
    expect(cancelled.status).toBe("cancelled")
    expect(() =>
      haven.denyAccessRequest(request.id, {
        actor_human_id: admin.id,
        reason: "too late",
      }),
    ).toThrow(/request_not_pending/)
  })

  test("knock and decideKnock adapt to the unified workflow", async () => {
    const haven = await openTestHaven()
    const { org, reviewer } = await humans(haven)
    haven.createAgent({
      name: "workflow-agent",
      owner: reviewer.id,
      purpose: "resolve",
      risk_tier: "low",
      scopes: ["secrets:read"],
      org_id: org.id,
      project_id: haven.getProject("demo", "default")!.id,
    })
    haven.setOrgPolicy(
      "demo",
      {
        defaults: [
          {
            action: "keys.resolve",
            actor_type: "agent",
            outcome: "approval_required",
            mode: "threshold",
            tiers: ["normal"],
            max_token_ttl_seconds: 120,
          },
        ],
        minimums: [],
      },
      haven.getOrgPolicy("demo").version,
      reviewer.id,
    )

    const knock = haven.knock({
      org: "demo",
      project: "default",
      agent_name: "workflow-agent",
      purpose: "read",
      need: [{ action: "secrets:read", scope: "haven://demo/default/dev/" }],
    })
    const request = haven.listAccessRequests({ org_id: org.id })[0]

    expect(knock).toMatchObject({ status: "pending", access_request_id: request.id })
    expect(request).toMatchObject({
      actor_type: "agent",
      actor_id: haven.getAgentByName("workflow-agent")!.id,
      agent_owner_human_id: reviewer.id,
      tiers: ["normal"],
    })
    const approved = haven.decideKnock(knock.id, {
      actorId: reviewer.id,
      decision: "approve",
    })
    expect(approved.status).toBe("approved")
    expect(approved.ttl_seconds).toBeLessThanOrEqual(120)
    expect(haven.listAccessRequests({ org_id: org.id })[0].status).toBe("approved")
  })

  test("policy reason requirement applies to normal approval", async () => {
    const haven = await openTestHaven()
    const { org, project, reviewer } = await humans(haven)
    const decision = approvalDecision("threshold", ["normal"])
    decision.reason_required = true
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-reason",
      agent_owner_human_id: reviewer.id,
      policy_decision: decision,
    })

    expect(() =>
      haven.approveAccessRequest(request.id, { actor_human_id: reviewer.id }),
    ).toThrow(/reason_required/)
  })

  test("listing marks elapsed requests expired", async () => {
    const haven = await openTestHaven()
    const { org, project, reviewer } = await humans(haven)
    const decision = {
      ...approvalDecision("threshold", ["normal"]),
      expires_in_seconds: 1,
    }
    const request = haven.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      action: "keys.resolve",
      actor_type: "agent",
      actor_id: "agent-expiry",
      agent_owner_human_id: reviewer.id,
      policy_decision: decision,
    })

    await Bun.sleep(1_050)
    expect(haven.listAccessRequests({ org_id: org.id })[0]).toMatchObject({
      id: request.id,
      status: "expired",
    })
    expect(() =>
      haven.approveAccessRequest(request.id, { actor_human_id: reviewer.id }),
    ).toThrow(/request_expired/)
  })

  test("creation rejects spoofed requester and invalid resource hierarchy", async () => {
    const haven = await openTestHaven()
    const { org, project, admin, reviewer } = await humans(haven)
    expect(() =>
      haven.createAccessRequest({
        org_id: org.id,
        project_id: project.id,
        action: "keys.update",
        actor_type: "human",
        actor_id: admin.id,
        requester_human_id: reviewer.id,
        policy_decision: approvalDecision("threshold", ["normal"]),
      }),
    ).toThrow(/invalid_request/)
    expect(() =>
      haven.createAccessRequest({
        org_id: org.id,
        project_id: "prj_outside",
        action: "keys.resolve",
        actor_type: "agent",
        actor_id: "agent-invalid",
        policy_decision: approvalDecision("threshold", ["normal"]),
      }),
    ).toThrow(/invalid_resource/)
  })
})
