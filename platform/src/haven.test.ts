import { afterEach, describe, expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { createHash, createPublicKey } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { verifyWatchPackage } from "./canary_crypto.ts"
import { createHaven } from "./haven.ts"

const dirs: string[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

async function openTestHaven(extra: Record<string, string> = {}) {
  const dataDir = extra.dataDir ?? mkdtempSync(join(tmpdir(), "haven-"))
  if (!extra.dataDir) dirs.push(dataDir)
  return createHaven({
    dataDir,
    tokenSecret: extra.tokenSecret ?? "token-secret-not-a-placeholder-32bxx",
    rootKeyHex: extra.rootKeyHex ?? "ab".repeat(32),
    canaryPepperHex: extra.canaryPepperHex,
    bootstrapUser: extra.bootstrapUser ?? "root",
    bootstrapPassword: extra.bootstrapPassword ?? "correct-horse-battery",
    bootstrapOrg: extra.bootstrapOrg ?? "demo",
  })
}

describe("createHaven", () => {
  test("rejects canary pepper identical to root encryption key", async () => {
    const sharedKey = "ab".repeat(32)
    await expect(openTestHaven({ rootKeyHex: sharedKey, canaryPepperHex: sharedKey })).rejects.toThrow(
      /HAVEN_CANARY_PEPPER must differ from HAVEN_ROOT_ENCRYPTION_KEY/,
    )
  })

  test("register buoy returns token once and authenticates", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { buoy, token, package_public_key } = await h.registerBuoy({
      orgSlug: "demo",
      kind: "harbor",
      name: "harbor-1",
    })
    expect(buoy.kind).toBe("harbor")
    expect(token.startsWith("haven_buoy_")).toBe(true)
    expect(package_public_key).toMatch(/^[0-9a-f]+$/)
    const req = new Request("http://x", {
      headers: { authorization: `Bearer ${token}`, "x-haven-buoy-id": buoy.id },
    })
    expect(h.authenticateBuoy(req)?.id).toBe(buoy.id)
    expect(
      h.authenticateBuoy(new Request("http://x", { headers: { authorization: `Bearer ${token}` } })),
    ).toBeNull()
    expect(
      h.authenticateBuoy(
        new Request("http://x", {
          headers: { authorization: `Bearer ${token}`, "x-haven-buoy-id": "buoy_wrong" },
        }),
      ),
    ).toBeNull()
  })

  test("rotate on revoked buoy fails", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { buoy } = await h.registerBuoy({
      orgSlug: "demo",
      kind: "harbor",
      name: "harbor-1",
    })
    h.revokeBuoy(buoy.id)
    await expect(h.rotateBuoyCredential(buoy.id)).rejects.toThrow(/buoy_revoked/)
  })

  test("revoked buoy can no longer authenticate", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { buoy, token } = await h.registerBuoy({
      orgSlug: "demo",
      kind: "harbor",
      name: "harbor-1",
    })
    const req = new Request("http://x", {
      headers: { authorization: `Bearer ${token}`, "x-haven-buoy-id": buoy.id },
    })
    expect(h.authenticateBuoy(req)?.id).toBe(buoy.id)
    h.revokeBuoy(buoy.id)
    expect(h.authenticateBuoy(req)).toBeNull()
  })

  test("bootstraps org and superadmin", async () => {
    const h = await openTestHaven()
    const orgs = h.listOrgs()
    expect(orgs.map((o) => o.slug)).toEqual(["demo"])
    const user = await h.verifyPassword("root", "correct-horse-battery")
    expect(user).not.toBeNull()
    expect(h.roleFor(user!.id, orgs[0].id)).toBe("superadmin")
  })

  test("detects the first tampered event in the ledger hash chain", async () => {
    const h = await openTestHaven()
    const baseline = h.verifyLedger()
    if (!baseline.valid) throw new Error("expected valid bootstrap ledger")
    h.ledgerAppend("test.first", { detail: { marker: "first" } })
    h.ledgerAppend("test.second", { detail: { marker: "second" } })
    h.ledgerAppend("test.third", { detail: { marker: "third" } })

    expect(h.verifyLedger()).toEqual({ valid: true, events: baseline.events + 3 })

    const lines = readFileSync(h.ledgerPath, "utf8").trim().split("\n")
    const middle = JSON.parse(lines[baseline.events + 1])
    middle.detail.marker = "tampered"
    lines[baseline.events + 1] = JSON.stringify(middle)
    writeFileSync(h.ledgerPath, `${lines.join("\n")}\n`)

    expect(h.verifyLedger()).toMatchObject({
      valid: false,
      events: baseline.events + 1,
      first_break: { line: baseline.events + 2, reason: "hash_mismatch" },
    })
  })

  test("fails closed on legacy unchained lines while new appends start a chain", async () => {
    const h = await openTestHaven()
    writeFileSync(
      h.ledgerPath,
      `${JSON.stringify({
        id: "led_legacy",
        ts: "2026-08-14T00:00:00.000Z",
        type: "legacy.event",
        agent_id: null,
        actor: "system",
        resource: null,
        action: null,
        outcome: "info",
        detail: {},
      })}\n`,
    )

    const appended = h.ledgerAppend("test.chained")
    expect(appended.prev_hash).toBeNull()
    expect(appended.hash).toMatch(/^[0-9a-f]{64}$/)
    expect(h.verifyLedger()).toMatchObject({
      valid: false,
      events: 0,
      first_break: { line: 1, reason: "missing_hash" },
    })
  })

  test("stores encrypted values and lists without them", async () => {
    const h = await openTestHaven()
    const put = h.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "never-list-me" })
    expect(put.ref).toBe("haven://demo/default/dev/PING")
    const listed = h.listKeys("demo", "default", "dev")
    expect(JSON.stringify(listed)).not.toContain("never-list-me")
    expect(listed.some((k) => k.name === "PING" && k.ref === put.ref)).toBe(true)
    expect(h.readKeyValue(put.ref)).toBe("never-list-me")
  })

  test("human key actions fail closed when policy denies", async () => {
    const h = await openTestHaven()
    const put = h.putKey({ org: "demo", project: "default", env: "dev", name: "DENIED", value: "opaque" })
    const human = h.getHumanByUsername("root")!

    expect(
      h.evaluateHumanKeyAction({
        human_id: human.id,
        action: "keys.reveal",
        resource: put.ref,
      }),
    ).toMatchObject({ outcome: "deny", reason: "no_matching_default" })
  })

  test("policy activation ledger events carry their owning organization and resource", async () => {
    const h = await openTestHaven()
    const demoOrg = h.getOrgBySlug("demo")!
    const other = h.createOrg("other", "Other")
    h.createProject(other.id, "default", "default")
    h.setOrgPolicy(
      "other",
      {
        defaults: [{ action: "keys.resolve", actor_type: "agent", outcome: "deny" }],
        minimums: [],
      },
      h.getOrgPolicy("other").version,
      "test",
    )

    const otherEvents = h.ledgerListForOrg(other.id, 100)
    const activation = otherEvents.find(
      (event) => event.type === "policy.activated" && event.detail.scope_id === other.id,
    )
    expect(activation).toMatchObject({
      resource: "haven://other",
      detail: { org_id: other.id, scope_type: "org" },
    })
    expect(
      h.ledgerListForOrg(demoOrg.id, 100).some(
        (event) => event.type === "policy.activated" && event.detail.scope_id === other.id,
      ),
    ).toBe(false)
  })

  test("approved human action cannot bypass a changed policy snapshot", async () => {
    const h = await openTestHaven()
    const put = h.putKey({ org: "demo", project: "default", env: "dev", name: "STALE_GRANT", value: "opaque" })
    h.setKeyPolicy(
      put.ref,
      {
        defaults: [
          {
            action: "keys.reveal",
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
    h.setKeyPolicy(put.ref, h.getKeyPolicy(put.ref).document, 1, "test")
    const org = h.getOrgBySlug("demo")!
    const project = h.getProject("demo", "default")!
    const key = h.listKeys("demo", "default", "dev").find((item) => item.ref === put.ref)!
    const requester = h.getHumanByUsername("root")!
    const reviewer = await h.createHuman({
      username: "snapshot-reviewer",
      password: "correct-horse-battery",
      orgId: org.id,
      role: "user",
    })
    const initialDecision = h.evaluateHumanKeyAction({
      human_id: requester.id,
      action: "keys.reveal",
      resource: put.ref,
    })
    if (initialDecision.outcome !== "approval_required") throw new Error("expected approval policy")
    const request = h.createAccessRequest({
      org_id: org.id,
      project_id: project.id,
      key_id: key.id,
      action: "keys.reveal",
      actor_type: "human",
      actor_id: requester.id,
      requester_human_id: requester.id,
      policy_decision: initialDecision,
    })
    h.approveAccessRequest(request.id, { actor_human_id: reviewer.id })
    h.setOrgPolicy(
      "demo",
      {
        defaults: [],
        minimums: [{ action: "keys.reveal", actor_type: "human", min: "elevated" }],
      },
      h.getOrgPolicy("demo").version,
      "test",
    )

    expect(
      h.evaluateHumanKeyAction({
        human_id: requester.id,
        action: "keys.reveal",
        resource: put.ref,
      }),
    ).toMatchObject({ outcome: "approval_required", tiers: ["elevated"] })
  })

  test("reveals once with an audited event and hard-deletes a key", async () => {
    const h = await openTestHaven()
    const put = h.putKey({ org: "demo", project: "default", env: "dev", name: "DELETE_ME", value: "do-not-log-me" })

    expect(h.revealKey(put.ref, "root")).toEqual({
      ref: put.ref,
      value: "do-not-log-me",
      version: 1,
    })
    expect(JSON.stringify(h.ledgerList(10))).not.toContain("do-not-log-me")

    expect(() => h.deleteKey(put.ref, "wrong-name", "root")).toThrow(/confirmation_name_mismatch/)
    expect(h.deleteKey(put.ref, "DELETE_ME", "root")).toEqual({ ref: put.ref, deleted: true })
    expect(h.listKeys("demo", "default", "dev")).not.toContainEqual(expect.objectContaining({ ref: put.ref }))
    expect(() => h.readKeyValue(put.ref)).toThrow(/key_not_found/)
  })

  test("plant canary publishes digest in watch package", async () => {
    const pepper = "cd".repeat(32)
    const h = await openTestHaven({ canaryPepperHex: pepper })
    h.putKey({ org: "demo", project: "default", env: "dev", name: "REAL", value: "live-secret" })
    const { canary, decoy } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: "haven://demo/default/dev/REAL",
      decoy: "canary-decoy-value",
    })
    const pkg = h.currentWatchPackage(h.getOrgBySlug("demo")!.id, "harbor")
    expect(pkg.canaries.some((c) => c.canary_id === canary.id && c.digest === canary.digest)).toBe(true)
    expect(JSON.stringify(pkg)).not.toContain("canary-decoy-value")
    expect(JSON.stringify(pkg)).not.toContain("live-secret")
    expect(decoy).toBe("canary-decoy-value")
  })

  test("decoy-key canary creates a retrievable key", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { canary, decoy } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "decoy_key",
      decoy: "generated-key-decoy",
    })
    expect(canary.key_ref).toStartWith("haven://demo/default/dev/CANARY_")
    expect(h.readKeyValue(canary.key_ref!)).toBe(decoy)
  })

  test("list canaries excludes plaintext decoys", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "decoy_key",
      decoy: "list-must-hide-this-decoy",
    })
    const listed = h.listCanaries("demo")
    expect(listed.some((item) => item.id === canary.id)).toBe(true)
    expect(JSON.stringify(listed)).not.toContain("list-must-hide-this-decoy")
  })

  test("revoke canary bumps package version and marks digest revoked", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "decoy_key",
    })
    const plantedPackage = h.currentWatchPackage(h.getOrgBySlug("demo")!.id, "harbor")
    const revoked = h.revokeCanary(canary.id)
    const revokedPackage = h.currentWatchPackage(h.getOrgBySlug("demo")!.id, "harbor")
    expect(revoked?.status).toBe("revoked")
    expect(revokedPackage.version).toBe(plantedPackage.version + 1)
    expect(revokedPackage.canaries.find((item) => item.canary_id === canary.id)?.revoked).toBe(true)
  })

  test("watch package includes its SPKI public key and verifies", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const pkg = h.currentWatchPackage(h.getOrgBySlug("demo")!.id, "harbor")
    expect(pkg.public_key_format).toBe("spki-der-hex")
    const publicKey = createPublicKey({
      key: Buffer.from(pkg.public_key, "hex"),
      format: "der",
      type: "spki",
    })
    expect(verifyWatchPackage(pkg, publicKey)).toBe(true)
  })

  test("sighting block fails closed resolve", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "EXPOSED",
      value: "live-secret",
    })
    h.setKeyGuardrail(ref, {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 300,
      require_approval: false,
      on_exposure: "block",
    })
    h.createAgent({
      name: "resolver",
      owner: "root",
      purpose: "resolve",
      risk_tier: "low",
      scopes: ["secrets:read"],
    })
    const { token } = h.mintToken("resolver", 300, ["secrets:read"], [ref])
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "sibling-decoy",
    })
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "harbor", name: "harbor-1" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!

    const ingested = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file", path: "/tmp/fixture" },
    })
    const resolved = h.resolveSecret(token, ref)

    expect(ingested.remediation?.on_exposure_applied).toBe("block")
    expect(resolved.allow).toBe(false)
    expect(resolved.reason).toBe("exposure_blocked")
    expect(JSON.stringify(resolved)).not.toContain("live-secret")
  })

  test("sighting queue opens one remediation", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "QUEUED",
      value: "live-secret",
    })
    h.setKeyGuardrail(ref, {
      default: "deny",
      allow_agents: [],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 900,
      require_approval: false,
      on_exposure: "queue",
    })
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "queued-decoy",
    })
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "custom", name: "custom-1" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    const payload = {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "network" as const, host: "fixture.local" },
    }

    const first = h.ingestSighting(buoy, payload)
    const second = h.ingestSighting(buoy, payload)

    expect(first.sighting.id).not.toBe(second.sighting.id)
    expect(first.remediation?.status).toBe("open")
    expect(second.remediation?.id).toBe(first.remediation?.id)
    expect(second.remediation?.on_exposure_applied).toBe("queue")
  })

  test("lists remediations by organization and optional status", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "decoy_key",
      decoy: "queued-decoy",
    })
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "custom", name: "custom-1" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    const { remediation } = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "network" },
    })

    expect(h.listRemediations("demo")).toEqual([remediation])
    expect(h.listRemediations("demo", "open")).toEqual([remediation])
    expect(h.listRemediations("demo", "dismissed")).toEqual([])
    expect(h.listRemediations("missing")).toEqual([])
  })

  test("dismisses remediation without clearing the exposure block", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "DISMISSED",
      value: "live-secret",
    })
    h.setKeyGuardrail(ref, {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 300,
      require_approval: false,
      on_exposure: "block",
    })
    h.createAgent({ name: "dismiss-resolver", owner: "root", purpose: "resolve", risk_tier: "low", scopes: ["secrets:read"] })
    const { token } = h.mintToken("dismiss-resolver", 300, ["secrets:read"], [ref])
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "dismiss-decoy",
    })
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "harbor", name: "dismiss-harbor" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    const { remediation } = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file" },
    })

    const dismissed = h.dismissRemediation(remediation!.id)

    expect(dismissed.status).toBe("dismissed")
    expect(dismissed.closed_at).not.toBeNull()
    expect(h.resolveSecret(token, ref).reason).toBe("exposure_blocked")
    expect(h.listCanaries("demo")[0].status).toBe("active")
  })

  test("rotates remediation by clearing the block and revoking its canary by default", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "ROTATED",
      value: "rotated-secret",
    })
    h.setKeyGuardrail(ref, {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 300,
      require_approval: false,
      on_exposure: "block",
    })
    h.createAgent({ name: "rotate-resolver", owner: "root", purpose: "resolve", risk_tier: "low", scopes: ["secrets:read"] })
    const { token } = h.mintToken("rotate-resolver", 300, ["secrets:read"], [ref])
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "rotate-decoy",
    })
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "harbor", name: "rotate-harbor" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    const { remediation } = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file" },
    })

    const rotated = h.rotateRemediation(remediation!.id)

    expect(rotated.status).toBe("rotated")
    expect(rotated.closed_at).not.toBeNull()
    expect(h.resolveSecret(token, ref)).toMatchObject({ allow: true, value: "rotated-secret" })
    expect(h.listCanaries("demo")[0].status).toBe("revoked")
  })

  test("rotates remediation without revoking its canary when requested", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "ROTATED_WITH_ACTIVE_CANARY",
      value: "rotated-secret",
    })
    h.setKeyGuardrail(ref, {
      default: "deny",
      allow_agents: [],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 300,
      require_approval: false,
      on_exposure: "block",
    })
    const { canary } = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "active-canary-decoy",
    })
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "harbor", name: "active-canary-harbor" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    const { remediation } = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file" },
    })

    const rotated = h.rotateRemediation(remediation!.id, false)

    expect(rotated.status).toBe("rotated")
    expect(h.listCanaries("demo")[0].status).toBe("active")
  })

  test("keeps a key blocked until every sibling block remediation is rotated", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({
      org: "demo",
      project: "default",
      env: "dev",
      name: "MULTI_EXPOSED",
      value: "rotated-secret",
    })
    h.setKeyGuardrail(ref, {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 300,
      require_approval: false,
      on_exposure: "block",
    })
    h.createAgent({ name: "multi-resolver", owner: "root", purpose: "resolve", risk_tier: "low", scopes: ["secrets:read"] })
    const { token } = h.mintToken("multi-resolver", 300, ["secrets:read"], [ref])
    const firstCanary = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "first-sibling-decoy",
    }).canary
    const secondCanary = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "second-sibling-decoy",
    }).canary
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "harbor", name: "multi-harbor" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    const first = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: firstCanary.id,
      digest: firstCanary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file" },
    }).remediation!
    const second = h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: secondCanary.id,
      digest: secondCanary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file" },
    }).remediation!

    h.rotateRemediation(first.id)
    expect(h.resolveSecret(token, ref).reason).toBe("exposure_blocked")

    h.rotateRemediation(second.id)
    expect(h.resolveSecret(token, ref)).toMatchObject({ allow: true, value: "rotated-secret" })
  })
})

describe("guardrails and knock", () => {
  test("parseGuardrail accepts on_exposure and defaults to queue", async () => {
    const h = await openTestHaven()
    h.setOrgGuardrail("demo", {
      default: "deny",
      allow_agents: [],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 900,
      require_approval: false,
      on_exposure: "block",
    })
    expect(h.getOrgBySlug("demo")!.guardrail.on_exposure).toBe("block")
    h.setOrgGuardrail("demo", {
      default: "deny",
      allow_agents: [],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 900,
      require_approval: false,
      // on_exposure omitted
    } as any)
    expect(h.getOrgBySlug("demo")!.guardrail.on_exposure).toBe("queue")
  })

  test("default deny auto-denies a known agent", async () => {
    const h = await openTestHaven()
    h.createAgent({ name: "scout", owner: "root", purpose: "probe", risk_tier: "low", scopes: ["secrets:read"] })
    const result = h.knock({
      org: "demo",
      project: "default",
      agent_name: "scout",
      purpose: "read ping",
      need: [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }],
    })
    expect(result.status).toBe("auto_deny")
    expect(result.token).toBeUndefined()
  })

  test("org allow mints a short-lived haven_ token for a known agent", async () => {
    const h = await openTestHaven()
    h.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    h.setOrgGuardrail("demo", {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 120,
      require_approval: false,
      on_exposure: "queue",
    })
    h.createAgent({ name: "pilot", owner: "root", purpose: "read", risk_tier: "low", scopes: ["secrets:read"] })
    const result = h.knock({
      org: "demo",
      project: "default",
      agent_name: "pilot",
      purpose: "read ping",
      need: [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }],
      ttl_seconds: 600,
    })
    expect(result.status).toBe("auto_allow")
    expect(result.token?.startsWith("haven_")).toBe(true)
    expect(result.ttl_seconds).toBeLessThanOrEqual(120)
    const resolved = h.resolveSecret(result.token!, "haven://demo/default/dev/PING")
    expect(resolved.allow).toBe(true)
    expect(resolved.value).toBe("dock")
  })

  test("cross-org knock cannot grant or resolve another organization's secret", async () => {
    const h = await openTestHaven()
    const demoOrg = h.getOrgBySlug("demo")!
    const other = h.createOrg("other", "Other")
    const otherProject = h.createProject(other.id, "default", "default")
    const secret = h.putKey({
      org: "other",
      project: "default",
      env: "dev",
      name: "CROSS_ORG",
      value: "must-stay-in-other",
    })
    h.setOrgGuardrail("other", {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 120,
      require_approval: false,
      on_exposure: "queue",
    })
    const agent = h.createAgent({
      name: "demo-agent",
      owner: "root",
      purpose: "demo only",
      risk_tier: "low",
      scopes: ["secrets:read"],
      org_id: demoOrg.id,
      project_id: h.getProject("demo", "default")!.id,
    })

    expect(() =>
      h.knock({
        org: "other",
        project: "default",
        agent_name: agent.name,
        purpose: "cross tenant attack",
        need: [{ action: "secrets:read", key_ref: secret.ref }],
      }),
    ).toThrow(/agent_scope_mismatch/)
    expect(h.listResourceGrants(agent.id)).toEqual([])
    expect(otherProject.org_id).toBe(other.id)
  })

  test("exposure-blocked needs auto-deny without minting a grant", async () => {
    const h = await openTestHaven({ canaryPepperHex: "cd".repeat(32) })
    const { ref } = h.putKey({ org: "demo", project: "default", env: "dev", name: "BLOCKED_KNOCK", value: "dock" })
    h.setKeyGuardrail(ref, {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 120,
      require_approval: false,
      on_exposure: "block",
    })
    h.createAgent({ name: "blocked-pilot", owner: "root", purpose: "read", risk_tier: "low", scopes: ["secrets:read"] })
    const canary = h.plantCanary({
      orgSlug: "demo",
      projectSlug: "default",
      mode: "sibling",
      keyRef: ref,
      decoy: "blocked-knock-decoy",
    }).canary
    const registered = await h.registerBuoy({ orgSlug: "demo", kind: "harbor", name: "blocked-knock-harbor" })
    const buoy = h.authenticateBuoy(
      new Request("http://x", {
        headers: { authorization: `Bearer ${registered.token}`, "x-haven-buoy-id": registered.buoy.id },
      }),
    )!
    h.ingestSighting(buoy, {
      buoy_id: buoy.id,
      canary_id: canary.id,
      digest: canary.digest,
      observed_at: new Date().toISOString(),
      context: { source: "file" },
    })

    const result = h.knock({
      org: "demo",
      project: "default",
      agent_name: "blocked-pilot",
      purpose: "read blocked key",
      need: [{ action: "secrets:read", key_ref: ref }],
    })

    expect(result.status).toBe("auto_deny")
    expect(result.decision_reason).toBe("exposure_blocked")
    expect(result.token).toBeUndefined()
    expect(h.listResourceGrants().some((grant) => grant.resource === ref)).toBe(false)
  })

  test("first-time agent is queued even when policy would allow", async () => {
    const h = await openTestHaven()
    h.setOrgGuardrail("demo", {
      default: "allow",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 900,
      require_approval: false,
      on_exposure: "queue",
    })
    const result = h.knock({
      org: "demo",
      project: "default",
      agent_name: "stranger",
      purpose: "first contact",
      need: [{ action: "secrets:read", scope: "haven://demo/default/dev/" }],
    })
    expect(result.status).toBe("pending")
    expect(result.token).toBeUndefined()
  })

  test("human approve mints a token; deny is final", async () => {
    const h = await openTestHaven()
    h.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    h.setOrgGuardrail("demo", {
      default: "approve",
      allow_agents: ["*"],
      allow_actions: ["secrets:read"],
      max_ttl_seconds: 900,
      require_approval: false,
      on_exposure: "queue",
    })
    const queued = h.knock({
      org: "demo",
      project: "default",
      agent_name: "newbie",
      purpose: "please",
      need: [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }],
    })
    expect(queued.status).toBe("pending")
    const rootUser = (await h.verifyPassword("root", "correct-horse-battery"))!
    const denied = h.decideKnock(queued.id, { actorId: rootUser.id, decision: "deny" })
    expect(denied.status).toBe("denied")
    expect(() => h.decideKnock(queued.id, { actorId: rootUser.id, decision: "approve" })).toThrow(/already_resolved/)

    const queued2 = h.knock({
      org: "demo",
      project: "default",
      agent_name: "newbie",
      purpose: "again",
      need: [{ action: "secrets:read", key_ref: "haven://demo/default/dev/PING" }],
    })
    const approved = h.decideKnock(queued2.id, { actorId: rootUser.id, decision: "approve" })
    expect(approved.status).toBe("approved")
    expect(approved.token?.startsWith("haven_")).toBe(true)
    const resolved = h.resolveSecret(approved.token!, "haven://demo/default/dev/PING")
    expect(resolved.allow).toBe(true)
    expect(resolved.value).toBe("dock")
  })

  test("resolve is fail-closed without a grant", async () => {
    const h = await openTestHaven()
    h.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "dock" })
    h.createAgent({ name: "pilot", owner: "root", purpose: "read", risk_tier: "low", scopes: ["secrets:read"] })
    const minted = h.mintToken("pilot", 300, ["secrets:read"])
    const resolved = h.resolveSecret(minted.token, "haven://demo/default/dev/PING")
    expect(resolved.allow).toBe(false)
    expect(resolved.reason).toBe("resource_not_granted")
    expect(JSON.stringify(resolved)).not.toContain("dock")
  })
})

describe("human roles", () => {
  test("user cannot read secret values; admin cannot rewrite org guardrails", async () => {
    const h = await openTestHaven()
    const org = h.listOrgs()[0]
    await h.createHuman({ username: "ops", password: "ops-pass-word-12", orgId: org.id, role: "admin" })
    await h.createHuman({ username: "queue", password: "queue-pass-12", orgId: org.id, role: "user" })
    h.putKey({ org: "demo", project: "default", env: "dev", name: "PING", value: "secret-val" })

    const ops = (await h.verifyPassword("ops", "ops-pass-word-12"))!
    const queue = (await h.verifyPassword("queue", "queue-pass-12"))!
    expect(h.canReadKeyValues(ops.id, org.id)).toBe(true)
    expect(h.canReadKeyValues(queue.id, org.id)).toBe(false)
    expect(h.canWriteOrgGuardrail(ops.id, org.id)).toBe(false)
    expect(h.canWriteOrgGuardrail((await h.verifyPassword("root", "correct-horse-battery"))!.id, org.id)).toBe(true)
    expect(h.canApprove(queue.id, org.id)).toBe(true)
  })

  test("root can change password", async () => {
    const h = await openTestHaven()
    const rootUser = (await h.verifyPassword("root", "correct-horse-battery"))!
    await h.changePassword(rootUser.id, "correct-horse-battery", "new-password-ok")
    expect(await h.verifyPassword("root", "correct-horse-battery")).toBeNull()
    expect(await h.verifyPassword("root", "new-password-ok")).not.toBeNull()
  })
})

describe("schema migration", () => {
  test("backfills legacy API keys to the bootstrap org so they remain manageable", async () => {
    const dataDir = mkdtempSync(join(tmpdir(), "haven-legacy-api-key-"))
    dirs.push(dataDir)
    const raw = "haven_ak_legacy_key_material"
    const db = new Database(join(dataDir, "haven.db"), { create: true })
    db.exec(`
      CREATE TABLE orgs (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        guardrail_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE api_keys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        scopes_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        revoked_at TEXT
      );
    `)
    db.query(`INSERT INTO orgs VALUES (?, ?, ?, ?, ?)`).run(
      "org_legacy",
      "demo",
      "Demo",
      JSON.stringify({
        default: "deny",
        allow_agents: [],
        allow_actions: ["secrets:read"],
        max_ttl_seconds: 900,
        require_approval: false,
        on_exposure: "queue",
      }),
      new Date().toISOString(),
    )
    db.query(`INSERT INTO api_keys VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`).run(
      "apk_legacy",
      "legacy",
      createHash("sha256").update(raw).digest("hex"),
      "haven_ak_legacy…",
      JSON.stringify(["activity:read", "activity:write"]),
      "active",
      new Date().toISOString(),
    )
    db.close()

    const h = await openTestHaven({ dataDir })
    expect(h.authenticateApiKey(new Request("http://x", { headers: { authorization: `Bearer ${raw}` } }))).toMatchObject({
      id: "apk_legacy",
      org_id: "org_legacy",
    })
    expect(h.listApiKeys("org_legacy")).toContainEqual(expect.objectContaining({ id: "apk_legacy" }))
    const manual = new Database(h.dbPath)
    manual.query(`UPDATE api_keys SET org_id = NULL WHERE id = ?`).run("apk_legacy")
    manual.close()
    expect(
      h.authenticateApiKey(new Request("http://x", { headers: { authorization: `Bearer ${raw}` } })),
    ).toBeNull()
    const restore = new Database(h.dbPath)
    restore.query(`UPDATE api_keys SET org_id = ? WHERE id = ?`).run("org_legacy", "apk_legacy")
    restore.close()
    expect(h.revokeApiKey("apk_legacy", "org_legacy")).toMatchObject({ id: "apk_legacy", status: "revoked" })
  })
})
