import { afterEach, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { evaluatePolicy, policyStrength } from "./action_policy.ts"
import { createHaven } from "./haven.ts"
import type { ActionPolicyDocument } from "./types.ts"

const EMPTY_POLICY: ActionPolicyDocument = { defaults: [], minimums: [] }
const dirs: string[] = []

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function openTestHaven() {
  const dataDir = mkdtempSync(join(tmpdir(), "haven-policy-"))
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

describe("action policy evaluator", () => {
  test("key auto_approve is raised by org minimum elevated", () => {
    const decision = evaluatePolicy({
      orgPolicy: {
        defaults: [],
        minimums: [{ action: "keys.delete", actor_type: "human", min: "elevated" }],
      },
      projectPolicy: EMPTY_POLICY,
      keyPolicy: {
        defaults: [{ action: "keys.delete", actor_type: "human", outcome: "auto_approve" }],
        minimums: [],
      },
      action: "keys.delete",
      actor_type: "human",
    })

    expect(decision.outcome).toBe("approval_required")
    expect(decision.tiers).toEqual(["elevated"])
  })

  test("most-specific default wins when no minimum raises it", () => {
    const decision = evaluatePolicy({
      orgPolicy: {
        defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "deny" }],
        minimums: [],
      },
      projectPolicy: {
        defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "approval_required", tiers: ["normal"] }],
        minimums: [],
      },
      keyPolicy: {
        defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "auto_approve" }],
        minimums: [],
      },
      action: "keys.resolve",
      actor_type: "agent",
    })

    expect(decision.outcome).toBe("auto_approve")
  })

  test("equal-specificity environment and agent defaults choose the stronger outcome", () => {
    const decision = evaluatePolicy({
      orgPolicy: {
        defaults: [
          {
            action: "keys.resolve",
            actor_type: "agent",
            environment: "prod",
            outcome: "auto_approve",
          },
          {
            action: "keys.resolve",
            actor_type: "agent",
            agent_id: "deploy-agent",
            outcome: "deny",
          },
        ],
        minimums: [],
      },
      action: "keys.resolve",
      actor_type: "agent",
      environment: "prod",
      agent_id: "deploy-agent",
    })

    expect(decision.outcome).toBe("deny")
  })

  test("minimum constraints accumulate to the strongest result", () => {
    const decision = evaluatePolicy({
      orgPolicy: {
        defaults: [{ action: "keys.reveal", actor_type: "human", outcome: "auto_approve" }],
        minimums: [{ action: "keys.reveal", actor_type: "human", min: "normal" }],
      },
      projectPolicy: {
        defaults: [],
        minimums: [{ action: "keys.reveal", actor_type: "human", min: "breakglass" }],
      },
      keyPolicy: {
        defaults: [],
        minimums: [{ action: "keys.reveal", actor_type: "human", min: "elevated" }],
      },
      action: "keys.reveal",
      actor_type: "human",
    })

    expect(decision.outcome).toBe("approval_required")
    expect(decision.tiers).toEqual(["breakglass"])
  })

  test("malformed and unmatched policies fail closed", () => {
    const malformed = {
      defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "auto_approve", surprise: true }],
      minimums: [],
    } as unknown as ActionPolicyDocument
    expect(
      evaluatePolicy({
        orgPolicy: malformed,
        action: "keys.resolve",
        actor_type: "agent",
      }).outcome,
    ).toBe("deny")
    expect(
      evaluatePolicy({
        orgPolicy: EMPTY_POLICY,
        action: "keys.resolve",
        actor_type: "agent",
      }).outcome,
    ).toBe("deny")
  })

  test("uncloneable malformed policies deny without throwing", () => {
    const malformed = {
      defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "auto_approve", bad: () => true }],
      minimums: [],
    } as unknown as ActionPolicyDocument

    expect(() =>
      evaluatePolicy({
        orgPolicy: malformed,
        action: "keys.resolve",
        actor_type: "agent",
      }),
    ).not.toThrow()
    expect(
      evaluatePolicy({
        orgPolicy: malformed,
        action: "keys.resolve",
        actor_type: "agent",
      }),
    ).toMatchObject({ outcome: "deny", reason: "invalid_policy" })
  })

  test("rejects contradictory outcome options", () => {
    const contradictory = {
      defaults: [
        {
          action: "keys.resolve",
          actor_type: "agent",
          outcome: "auto_approve",
          tiers: ["elevated"],
        },
      ],
      minimums: [],
    } as unknown as ActionPolicyDocument
    expect(
      evaluatePolicy({
        orgPolicy: contradictory,
        action: "keys.resolve",
        actor_type: "agent",
      }).outcome,
    ).toBe("deny")
  })

  test("policy strength is total and ordered", () => {
    expect(["auto", "normal", "elevated", "breakglass", "deny"].sort(policyStrength)).toEqual([
      "auto",
      "normal",
      "elevated",
      "breakglass",
      "deny",
    ])
    expect(policyStrength("deny", "auto")).toBeGreaterThan(0)
  })
})

describe("action policy store", () => {
  test("writes immutable versions with optimistic concurrency", async () => {
    const h = await openTestHaven()
    const initial = h.getOrgPolicy("demo")
    const document: ActionPolicyDocument = {
      defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "auto_approve" }],
      minimums: [],
    }

    const written = h.setOrgPolicy("demo", document, initial.version, "admin")
    expect(written.version).toBe(initial.version + 1)
    expect(h.getOrgPolicy("demo")).toEqual(written)
    expect(() => h.setOrgPolicy("demo", EMPTY_POLICY, initial.version, "admin")).toThrow(/policy_version_conflict/)
  })

  test("rejects malformed documents without replacing the active version", async () => {
    const h = await openTestHaven()
    const initial = h.getOrgPolicy("demo")
    const malformed = {
      defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "allow" }],
      minimums: [],
    } as unknown as ActionPolicyDocument

    expect(() => h.setOrgPolicy("demo", malformed, initial.version, "admin")).toThrow(/invalid_policy/)
    expect(h.getOrgPolicy("demo")).toEqual(initial)
  })

  test("preview composes stored parent policy with a candidate child", async () => {
    const h = await openTestHaven()
    const org = h.getOrgPolicy("demo")
    h.setOrgPolicy(
      "demo",
      {
        defaults: [],
        minimums: [{ action: "keys.delete", actor_type: "human", min: "elevated" }],
      },
      org.version,
      "admin",
    )

    const decision = h.previewPolicy({
      org: "demo",
      project: "default",
      candidate_scope: "project",
      candidate: {
        defaults: [{ action: "keys.delete", actor_type: "human", outcome: "auto_approve" }],
        minimums: [],
      },
      action: "keys.delete",
      actor_type: "human",
    })
    expect(decision.outcome).toBe("approval_required")
    expect(decision.tiers).toEqual(["elevated"])
    expect(decision.snapshot).not.toBe(decision.snapshot.org)
  })

  test("preview rejects resources outside the requested hierarchy", async () => {
    const h = await openTestHaven()
    const other = h.createOrg("other", "Other")
    h.createProject(other.id, "default", "default")
    const key = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "SCOPED",
      value: "never-log-this",
    })

    expect(() =>
      h.previewPolicy({
        org: "other",
        project: "default",
        key_ref: key.ref,
        action: "keys.resolve",
        actor_type: "agent",
      }),
    ).toThrow(/policy_scope_mismatch/)
  })

  test("preview requires candidate and candidate_scope together", async () => {
    const h = await openTestHaven()

    expect(() =>
      h.previewPolicy({
        org: "demo",
        candidate: EMPTY_POLICY,
        action: "keys.resolve",
        actor_type: "agent",
      }),
    ).toThrow(/invalid_preview/)
    expect(() =>
      h.previewPolicy({
        org: "demo",
        candidate_scope: "org",
        action: "keys.resolve",
        actor_type: "agent",
      }),
    ).toThrow(/invalid_preview/)
  })

  test("legacy guardrails remain readable and synthesize compatible policy defaults", async () => {
    const h = await openTestHaven()
    const legacy = h.setProjectGuardrail("demo", "default", {
      default: "approve",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 300,
      require_approval: true,
      on_exposure: "queue",
    })

    expect(legacy.guardrail.default).toBe("approve")
    const policy = h.getProjectPolicy("demo", "default")
    expect(policy.document.defaults).toContainEqual(
      expect.objectContaining({
        action: "keys.resolve",
        actor_type: "agent",
        outcome: "approval_required",
        tiers: ["normal"],
        max_token_ttl_seconds: 300,
      }),
    )
  })
})
