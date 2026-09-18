import { describe, expect, test } from "bun:test"
import {
  canaryDigest,
  generatePackageKeyPair,
  signWatchPackage,
  verifyWatchPackage,
} from "./canary_crypto.ts"

describe("canary_crypto", () => {
  test("digest is stable hex hmac", () => {
    const pepper = Buffer.from("a".repeat(32))
    const a = canaryDigest(pepper, "decoy-value")
    const b = canaryDigest(pepper, "decoy-value")
    expect(a).toBe(b)
    expect(a).toMatch(/^[0-9a-f]{64}$/)
    expect(canaryDigest(pepper, "other")).not.toBe(a)
  })

  test("watch package sign/verify", () => {
    const { publicKey, privateKey } = generatePackageKeyPair()
    const body = {
      version: 1,
      issued_at: "2026-08-13T00:00:00.000Z",
      audience: "harbor",
      canaries: [{ canary_id: "c1", digest: "abc", revoked: false }],
    }
    const signature = signWatchPackage(body, privateKey)
    expect(verifyWatchPackage({ ...body, signature }, publicKey)).toBe(true)
    expect(verifyWatchPackage({ ...body, signature, version: 2 }, publicKey)).toBe(false)
  })
})
