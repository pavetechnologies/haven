import { afterEach, expect, test } from "bun:test"
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
  const dataDir = mkdtempSync(join(tmpdir(), "haven-routes-"))
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
  return createApp(haven)
}

async function login(handle: (req: Request) => Promise<Response>) {
  const res = await handle(
    new Request("http://127.0.0.1/v1/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "root", password: "correct-horse-battery" }),
    }),
  )
  return (res.headers.get("set-cookie") || "").split(";")[0]
}

// Every endpoint the operator UI calls, plus the machine-plane routes.
// Payloads are intentionally invalid so handlers reject at validation:
// this asserts the route is wired, not that the action succeeds.
const ROUTES: Array<[string, string]> = [
  ["GET", "/v1/me"],
  ["POST", "/v1/me/password"],
  ["GET", "/v1/orgs"],
  ["POST", "/v1/orgs"],
  ["GET", "/v1/orgs/demo/projects"],
  ["POST", "/v1/orgs/demo/projects"],
  ["GET", "/v1/orgs/demo/policy"],
  ["PUT", "/v1/orgs/demo/policy"],
  ["GET", "/v1/orgs/demo/policy/history"],
  ["GET", "/v1/orgs/demo/projects/default/policy"],
  ["PUT", "/v1/orgs/demo/projects/default/policy"],
  ["GET", "/v1/orgs/demo/projects/default/policy/history"],
  ["GET", "/v1/keys/bogus/policy"],
  ["PUT", "/v1/keys/bogus/policy"],
  ["GET", "/v1/keys/bogus/policy/history"],
  ["POST", "/v1/policies/preview"],
  ["PUT", "/v1/orgs/demo/guardrails"],
  ["PUT", "/v1/orgs/demo/projects/default/guardrails"],
  ["GET", "/v1/orgs/demo/members"],
  ["POST", "/v1/orgs/demo/members"],
  ["GET", "/v1/permissions"],
  ["GET", "/v1/orgs/demo/users/bogus/access"],
  ["POST", "/v1/orgs/demo/access-assignments"],
  ["POST", "/v1/orgs/demo/access-assignments/bogus/revoke"],
  ["POST", "/v1/authorization/explain"],
  ["GET", "/v1/secrets?org=demo&project=default&env=dev"],
  ["POST", "/v1/secrets"],
  ["POST", "/v1/secrets/reveal"],
  ["POST", "/v1/secrets/delete"],
  ["POST", "/v1/secrets/resolve"],
  ["POST", "/v1/knock"],
  ["GET", "/v1/knocks?org=demo"],
  ["POST", "/v1/knocks/bogus/approve"],
  ["POST", "/v1/knocks/bogus/deny"],
  ["GET", "/v1/access-requests?org=demo"],
  ["GET", "/v1/access-requests/bogus"],
  ["POST", "/v1/access-requests/bogus/approve"],
  ["POST", "/v1/access-requests/bogus/deny"],
  ["POST", "/v1/access-requests/bogus/escalate"],
  ["POST", "/v1/access-requests/bogus/cancel"],
  ["GET", "/v1/buoys?org=demo"],
  ["POST", "/v1/buoys"],
  ["POST", "/v1/buoys/bogus/rotate-credential"],
  ["POST", "/v1/buoys/bogus/revoke"],
  ["GET", "/v1/canaries?org=demo"],
  ["POST", "/v1/canaries"],
  ["POST", "/v1/canaries/bogus/revoke"],
  ["GET", "/v1/remediations?org=demo"],
  ["POST", "/v1/remediations/bogus/rotate"],
  ["POST", "/v1/remediations/bogus/dismiss"],
  ["GET", "/v1/agents?org=demo"],
  ["POST", "/v1/agents"],
  ["POST", "/v1/agents/bogus/revoke"],
  ["GET", "/v1/resources?org=demo"],
  ["POST", "/v1/resources/grant"],
  ["POST", "/v1/resources/revoke"],
  ["POST", "/v1/tokens"],
  ["POST", "/v1/tokens/introspect"],
  ["POST", "/v1/tokens/revoke"],
  ["POST", "/v1/authorize"],
  ["GET", "/v1/api-keys?org=demo"],
  ["POST", "/v1/api-keys"],
  ["POST", "/v1/api-keys/bogus/revoke"],
  ["GET", "/v1/activity"],
  ["POST", "/v1/activity"],
  ["GET", "/v1/watch-packages/current"],
  ["POST", "/v1/sightings"],
  ["GET", "/v1/ledger?org=demo&limit=10"],
  ["GET", "/v1/ledger/verify?org=demo"],
]

test("every declared route is reachable", async () => {
  const handle = await app()
  const cookie = await login(handle)
  const missing: string[] = []

  for (const [method, path] of ROUTES) {
    const res = await handle(
      new Request(`http://127.0.0.1${path}`, {
        method,
        headers: { "content-type": "application/json", cookie },
        body: method === "GET" ? undefined : "{}",
      }),
    )
    const text = await res.text()
    if (res.status === 404 && text.includes("no route")) missing.push(`${method} ${path}`)
  }

  expect(missing).toEqual([])
})

test("POST /v1/secrets/delete removes the key after typed-name confirmation", async () => {
  const handle = await app()
  const cookie = await login(handle)
  const h = { "content-type": "application/json", cookie }

  const put = await handle(
    new Request("http://127.0.0.1/v1/secrets", {
      method: "POST",
      headers: h,
      body: JSON.stringify({ org: "demo", project: "default", env: "dev", name: "DOOMED", value: "v1" }),
    }),
  )
  const { ref } = await put.json()
  const beforeDelete = await handle(
    new Request("http://127.0.0.1/v1/secrets?org=demo&project=default&env=dev", { headers: h }),
  )
  const keyId = (await beforeDelete.json()).secrets.find((key: { ref: string }) => key.ref === ref).id
  const policy = await handle(
    new Request(`http://127.0.0.1/v1/keys/${keyId}/policy`, {
      method: "PUT",
      headers: h,
      body: JSON.stringify({
        expected_version: 0,
        document: {
          defaults: [{ action: "keys.delete", actor_type: "human", outcome: "auto_approve" }],
          minimums: [],
        },
      }),
    }),
  )
  expect(policy.status).toBe(200)

  const mismatch = await handle(
    new Request("http://127.0.0.1/v1/secrets/delete", {
      method: "POST",
      headers: h,
      body: JSON.stringify({ ref, confirm_name: "WRONG" }),
    }),
  )
  expect(mismatch.status).toBe(400)

  const ok = await handle(
    new Request("http://127.0.0.1/v1/secrets/delete", {
      method: "POST",
      headers: h,
      body: JSON.stringify({ ref, confirm_name: "DOOMED" }),
    }),
  )
  expect(ok.status).toBe(200)

  const list = await handle(
    new Request("http://127.0.0.1/v1/secrets?org=demo&project=default&env=dev", { headers: h }),
  )
  const { secrets } = await list.json()
  expect(secrets.some((s: { name: string }) => s.name === "DOOMED")).toBe(false)
})
