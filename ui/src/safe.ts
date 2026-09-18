/** Never render secret values even if a payload is malformed. */
export function sanitizeLedgerEvent(input: unknown): Record<string, unknown> {
  return stripValue(input) as Record<string, unknown>
}

function stripValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stripValue)
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (k === "value" || k === "secretValue" || k === "client_secret") continue
      out[k] = stripValue(val)
    }
    return out
  }
  return v
}
