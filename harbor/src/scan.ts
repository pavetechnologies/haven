import { createHmac, createPublicKey, verify } from "node:crypto"
import { readFile } from "node:fs/promises"

export type WatchCanary = {
  canary_id: string
  digest: string
  revoked: boolean
}

export type ScanMatch = {
  canary_id: string
  digest: string
  path: string
}

export type WatchPackage = {
  version: number
  issued_at: string
  audience: string
  public_key: string
  public_key_format: string
  canaries: WatchCanary[]
  signature: string
}

export function canaryDigest(pepper: Buffer, candidate: string): string {
  return createHmac("sha256", pepper).update(candidate, "utf8").digest("hex")
}

function candidates(contents: string): string[] {
  const values = new Set<string>()
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line) continue
    values.add(line)
    for (const token of line.split(/[\s=]+/)) values.add(token)
  }
  return [...values]
}

export async function scanPaths(
  paths: string[],
  pepper: Buffer,
  canaries: WatchCanary[],
  log: (message: string) => void = console.warn,
): Promise<ScanMatch[]> {
  const watchedByDigest = new Map<string, WatchCanary[]>()
  for (const canary of canaries) {
    if (canary.revoked) continue
    const watched = watchedByDigest.get(canary.digest) ?? []
    watched.push(canary)
    watchedByDigest.set(canary.digest, watched)
  }

  const matches: ScanMatch[] = []
  for (const path of paths) {
    let contents: string
    try {
      contents = await readFile(path, "utf8")
    } catch {
      log(`Harbor scan skipped unreadable path: ${path}`)
      continue
    }
    const seen = new Set<string>()
    for (const candidate of candidates(contents)) {
      const digest = canaryDigest(pepper, candidate)
      for (const canary of watchedByDigest.get(digest) ?? []) {
        if (seen.has(canary.canary_id)) continue
        seen.add(canary.canary_id)
        matches.push({ canary_id: canary.canary_id, digest, path })
      }
    }
  }
  return matches
}

function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value
  if (Array.isArray(value)) return value.map(sortKeysDeep)
  const sorted: Record<string, unknown> = {}
  for (const key of Object.keys(value as object).sort()) {
    sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key])
  }
  return sorted
}

export function verifyWatchPackage(pkg: Record<string, unknown>, trustedPublicKey: Buffer): boolean {
  try {
    if (
      pkg.public_key_format !== "spki-der-hex" ||
      typeof pkg.public_key !== "string" ||
      typeof pkg.signature !== "string"
    ) {
      return false
    }
    if (pkg.public_key.toLowerCase() !== trustedPublicKey.toString("hex").toLowerCase()) return false
    const publicKey = createPublicKey({
      key: trustedPublicKey,
      format: "der",
      type: "spki",
    })
    const { signature, ...body } = pkg
    const payload = JSON.stringify(sortKeysDeep(body))
    return verify(null, Buffer.from(payload), publicKey, Buffer.from(signature, "base64"))
  } catch {
    return false
  }
}
