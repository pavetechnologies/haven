import { describe, expect, test } from "bun:test"
import { decrypt, encrypt, parseRootKey } from "./crypto.ts"

describe("AES-256-GCM envelope", () => {
  test("round-trips a secret value", () => {
    const key = parseRootKey("ab".repeat(32))
    const blob = encrypt("harbor-secret", key)
    expect(decrypt(blob, key)).toBe("harbor-secret")
  })

  test("rejects placeholder root keys", () => {
    expect(() => parseRootKey("dev-only-change-me")).toThrow(/HAVEN_ROOT_ENCRYPTION_KEY/)
  })
})
