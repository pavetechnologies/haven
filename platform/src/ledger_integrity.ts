import { createHash } from "node:crypto"

export type LedgerVerification =
  | { valid: true; events: number }
  | {
      valid: false
      events: number
      first_break: {
        line: number
        reason: "invalid_json" | "missing_hash" | "invalid_hash" | "prev_hash_mismatch" | "hash_mismatch"
      }
    }

function canonicalJson(value: unknown): string {
  if (value === undefined) return "null"
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`

  const object = value as Record<string, unknown>
  return `{${Object.keys(object)
    .filter((key) => object[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`
}

export function ledgerEventHash(event: Record<string, unknown>): string {
  const { hash: _hash, ...payload } = event
  return createHash("sha256").update(canonicalJson(payload)).digest("hex")
}

export function verifyLedgerContents(contents: string): LedgerVerification {
  if (!contents) return { valid: true, events: 0 }
  const lines = contents.split("\n")
  if (lines.at(-1) === "") lines.pop()

  let previousHash: string | null = null
  for (let index = 0; index < lines.length; index++) {
    let event: Record<string, unknown>
    try {
      event = JSON.parse(lines[index]) as Record<string, unknown>
    } catch {
      return { valid: false, events: index, first_break: { line: index + 1, reason: "invalid_json" } }
    }

    if (!Object.hasOwn(event, "prev_hash") || !Object.hasOwn(event, "hash")) {
      return { valid: false, events: index, first_break: { line: index + 1, reason: "missing_hash" } }
    }
    if (
      (event.prev_hash !== null && (typeof event.prev_hash !== "string" || !/^[0-9a-f]{64}$/.test(event.prev_hash))) ||
      typeof event.hash !== "string" ||
      !/^[0-9a-f]{64}$/.test(event.hash)
    ) {
      return { valid: false, events: index, first_break: { line: index + 1, reason: "invalid_hash" } }
    }
    if (event.prev_hash !== previousHash) {
      return { valid: false, events: index, first_break: { line: index + 1, reason: "prev_hash_mismatch" } }
    }
    if (event.hash !== ledgerEventHash(event)) {
      return { valid: false, events: index, first_break: { line: index + 1, reason: "hash_mismatch" } }
    }
    previousHash = event.hash
  }

  return { valid: true, events: lines.length }
}
