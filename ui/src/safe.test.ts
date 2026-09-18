import { describe, expect, test } from "bun:test"
import { sanitizeLedgerEvent } from "./safe.ts"

describe("sanitizeLedgerEvent", () => {
  test("strips value keys at any depth", () => {
    const out = sanitizeLedgerEvent({
      type: "secret.resolve",
      detail: { secret_name: "X", value: "leak", nested: { value: "also" } },
      value: "nope",
    })
    const text = JSON.stringify(out)
    expect(text).not.toContain("leak")
    expect(text).not.toContain("also")
    expect(text).not.toContain("nope")
    expect(out.type).toBe("secret.resolve")
    expect((out.detail as { secret_name: string }).secret_name).toBe("X")
  })
})
