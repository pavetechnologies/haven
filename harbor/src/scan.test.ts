import { describe, expect, test } from "bun:test"
import { generateKeyPairSync, sign } from "node:crypto"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { runCycle } from "./index.ts"
import { canaryDigest, scanPaths, verifyWatchPackage } from "./scan.ts"

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value
  if (Array.isArray(value)) return value.map(sortKeysDeep)
  return Object.fromEntries(
    Object.keys(value as object)
      .sort()
      .map((key) => [key, sortKeysDeep((value as Record<string, unknown>)[key])]),
  )
}

describe("Harbor scanning", () => {
  test("finds whitespace- and equals-delimited decoy tokens without returning plaintext", async () => {
    const directory = await mkdtemp(join(tmpdir(), "haven-harbor-"))
    const path = join(directory, "watched.txt")
    const decoy = "decoy-token-do-not-log"
    const pepper = Buffer.from("ab".repeat(32), "hex")

    try {
      await writeFile(path, `ordinary-value\nTOKEN=${decoy}\n`)
      const matches = await scanPaths(
        [path],
        pepper,
        [{ canary_id: "canary-1", digest: canaryDigest(pepper, decoy), revoked: false }],
      )

      expect(matches).toEqual([
        {
          canary_id: "canary-1",
          digest: canaryDigest(pepper, decoy),
          path,
        },
      ])
      expect(JSON.stringify(matches)).not.toContain(decoy)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  test("ignores revoked canaries", async () => {
    const directory = await mkdtemp(join(tmpdir(), "haven-harbor-"))
    const path = join(directory, "watched.txt")
    const pepper = Buffer.from("cd".repeat(32), "hex")

    try {
      await writeFile(path, "revoked-decoy\n")
      expect(
        await scanPaths(
          [path],
          pepper,
          [{ canary_id: "canary-2", digest: canaryDigest(pepper, "revoked-decoy"), revoked: true }],
        ),
      ).toEqual([])
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  test("skips unreadable paths and continues scanning", async () => {
    const directory = await mkdtemp(join(tmpdir(), "haven-harbor-"))
    const missingPath = join(directory, "missing.txt")
    const watchedPath = join(directory, "watched.txt")
    const pepper = Buffer.from("de".repeat(32), "hex")
    const logs: string[] = []

    try {
      await writeFile(watchedPath, "surviving-decoy\n")
      const matches = await scanPaths(
        [missingPath, watchedPath],
        pepper,
        [{ canary_id: "canary-readable", digest: canaryDigest(pepper, "surviving-decoy"), revoked: false }],
        (message) => logs.push(message),
      )

      expect(matches).toHaveLength(1)
      expect(matches[0]?.path).toBe(watchedPath)
      expect(logs).toEqual([`Harbor scan skipped unreadable path: ${missingPath}`])
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })

  test("verifies a canonically signed watch package only with the pinned SPKI", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")
    const pinnedPublicKey = Buffer.from(publicKey.export({ format: "der", type: "spki" }))
    const body = {
      version: 1,
      issued_at: "2026-08-13T00:00:00.000Z",
      audience: "harbor",
      public_key: pinnedPublicKey.toString("hex"),
      public_key_format: "spki-der-hex",
      canaries: [{ canary_id: "canary-1", digest: "ab".repeat(32), revoked: false }],
    }
    const payload = JSON.stringify(sortKeysDeep(body))
    const pkg = { ...body, signature: sign(null, Buffer.from(payload), privateKey).toString("base64") }

    expect(verifyWatchPackage(pkg, pinnedPublicKey)).toBe(true)
    expect(verifyWatchPackage({ ...pkg, version: 2 }, pinnedPublicKey)).toBe(false)
  })

  test("rejects a package signed by its attacker-controlled embedded key", () => {
    const trusted = generateKeyPairSync("ed25519")
    const attacker = generateKeyPairSync("ed25519")
    const body = {
      version: 1,
      issued_at: "2026-08-13T00:00:00.000Z",
      audience: "harbor",
      public_key: Buffer.from(attacker.publicKey.export({ format: "der", type: "spki" })).toString("hex"),
      public_key_format: "spki-der-hex",
      canaries: [],
    }
    const signature = sign(
      null,
      Buffer.from(JSON.stringify(sortKeysDeep(body))),
      attacker.privateKey,
    ).toString("base64")

    expect(
      verifyWatchPackage(
        { ...body, signature },
        Buffer.from(trusted.publicKey.export({ format: "der", type: "spki" })),
      ),
    ).toBe(false)
  })

  test("posts sightings with authenticated buoy identity and logs no plaintext", async () => {
    const directory = await mkdtemp(join(tmpdir(), "haven-harbor-"))
    const path = join(directory, "watched.txt")
    const decoy = "network-cycle-decoy"
    const pepper = Buffer.from("ef".repeat(32), "hex")
    const { publicKey, privateKey } = generateKeyPairSync("ed25519")
    const packagePublicKey = Buffer.from(publicKey.export({ format: "der", type: "spki" }))
    const body = {
      version: 1,
      issued_at: "2026-08-13T00:00:00.000Z",
      audience: "harbor",
      public_key: packagePublicKey.toString("hex"),
      public_key_format: "spki-der-hex",
      canaries: [{ canary_id: "canary-cycle", digest: canaryDigest(pepper, decoy), revoked: false }],
    }
    const signature = sign(
      null,
      Buffer.from(JSON.stringify(sortKeysDeep(body))),
      privateKey,
    ).toString("base64")
    const requests: Array<{ url: string; init?: RequestInit }> = []
    const logs: string[] = []

    try {
      await writeFile(path, `${decoy}\n`)
      const fetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
        requests.push({ url: String(input), init })
        if (requests.length === 1) {
          return Response.json(
            { ...body, signature },
            { headers: { "x-haven-buoy-id": "buoy-harbor" } },
          )
        }
        return Response.json({ ok: true }, { status: 201 })
      }

      expect(
        await runCycle(
          {
            havenUrl: "http://127.0.0.1:19090",
            buoyId: "buoy-harbor",
            token: "haven_buoy_test",
            pepper,
            packagePublicKey,
            paths: [path],
          },
          fetchImpl,
          (message) => logs.push(message),
        ),
      ).toBe(1)
      expect(JSON.parse(String(requests[1]?.init?.body))).toMatchObject({
        buoy_id: "buoy-harbor",
        canary_id: "canary-cycle",
        digest: canaryDigest(pepper, decoy),
        context: { source: "file", path },
      })
      expect(requests[0]?.init?.headers).toMatchObject({ "x-haven-buoy-id": "buoy-harbor" })
      expect(requests[1]?.init?.headers).toMatchObject({ "x-haven-buoy-id": "buoy-harbor" })
      expect(logs).toEqual(["Harbor sighting: canary-cycle"])
      expect(JSON.stringify(logs)).not.toContain(decoy)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  })
})
