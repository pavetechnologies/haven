import { createHmac, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto"

export function canaryDigest(pepper: Buffer, decoy: string): string {
  return createHmac("sha256", pepper).update(decoy, "utf8").digest("hex")
}

export function generatePackageKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  return { publicKey, privateKey }
}

// Canonical JSON: recursively sort object keys, then JSON.stringify (same bytes for sign and verify).
function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value))
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

export function signWatchPackage(bodyWithoutSig: object, privateKey: KeyObject): string {
  const payload = canonicalJson(bodyWithoutSig)
  return sign(null, Buffer.from(payload), privateKey).toString("base64")
}

export function verifyWatchPackage(
  pkg: { signature: string } & Record<string, unknown>,
  publicKey: KeyObject,
): boolean {
  const { signature, ...body } = pkg
  const payload = canonicalJson(body)
  return verify(null, Buffer.from(payload), publicKey, Buffer.from(signature, "base64"))
}
