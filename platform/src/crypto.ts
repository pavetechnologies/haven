/**
 * AES-256-GCM envelope for secret values.
 * Standard construction: 12-byte IV, ciphertext, 16-byte tag.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"

const IV_LENGTH = 12
const TAG_LENGTH = 16
const KEY_BYTES = 32
const PLACEHOLDERS = new Set(["dev-only-change-me", "dev-admin-change-me"])

export function parseRootKey(value: string): Buffer {
  const hex = value?.trim() ?? ""
  if (!hex || PLACEHOLDERS.has(hex)) {
    throw new Error("Missing or insecure required configuration: HAVEN_ROOT_ENCRYPTION_KEY")
  }
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== KEY_BYTES * 2) {
    throw new Error("Missing or insecure required configuration: HAVEN_ROOT_ENCRYPTION_KEY")
  }
  return Buffer.from(hex, "hex")
}

export function encrypt(plaintext: string, key: Buffer): Buffer {
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, encrypted, tag])
}

export function decrypt(ciphertextBlob: Buffer, key: Buffer): string {
  if (ciphertextBlob.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error("ciphertext_too_short")
  }
  const iv = ciphertextBlob.subarray(0, IV_LENGTH)
  const tag = ciphertextBlob.subarray(-TAG_LENGTH)
  const encrypted = ciphertextBlob.subarray(IV_LENGTH, -TAG_LENGTH)
  const decipher = createDecipheriv("aes-256-gcm", key, iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8")
}
