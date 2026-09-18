import { hostname } from "node:os"
import { createPublicKey } from "node:crypto"
import { scanPaths, verifyWatchPackage, type WatchPackage } from "./scan.ts"

export type HarborConfig = {
  havenUrl: string
  buoyId: string
  token: string
  pepper: Buffer
  packagePublicKey: Buffer
  paths: string[]
}

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>

function requireEnv(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  return value
}

function loadConfig(): HarborConfig & { pollSeconds: number } {
  const pepperHex = requireEnv("HAVEN_CANARY_PEPPER")
  if (!/^[0-9a-f]{64}$/i.test(pepperHex)) {
    throw new Error("HAVEN_CANARY_PEPPER must be 32-byte hex")
  }
  const paths = requireEnv("HARBOR_WATCH_PATHS")
    .split(":")
    .map((path) => path.trim())
    .filter(Boolean)
  const pollSeconds = Number(process.env.HARBOR_POLL_SECONDS || "60")
  if (!Number.isFinite(pollSeconds) || pollSeconds <= 0) {
    throw new Error("HARBOR_POLL_SECONDS must be a positive number")
  }
  const packagePublicKeyHex = requireEnv("HAVEN_PACKAGE_PUBLIC_KEY")
  if (!/^(?:[0-9a-f]{2})+$/i.test(packagePublicKeyHex)) {
    throw new Error("HAVEN_PACKAGE_PUBLIC_KEY must be SPKI DER hex")
  }
  const packagePublicKey = Buffer.from(packagePublicKeyHex, "hex")
  try {
    createPublicKey({ key: packagePublicKey, format: "der", type: "spki" })
  } catch {
    throw new Error("HAVEN_PACKAGE_PUBLIC_KEY must be valid SPKI DER hex")
  }
  return {
    havenUrl: requireEnv("HAVEN_URL").replace(/\/+$/, ""),
    buoyId: requireEnv("HAVEN_BUOY_ID"),
    token: requireEnv("HAVEN_BUOY_TOKEN"),
    pepper: Buffer.from(pepperHex, "hex"),
    packagePublicKey,
    paths,
    pollSeconds,
  }
}

export async function runCycle(
  config: HarborConfig,
  fetchImpl: FetchLike = fetch,
  log: (message: string) => void = console.log,
): Promise<number> {
  const headers = {
    authorization: `Bearer ${config.token}`,
    "x-haven-buoy-id": config.buoyId,
  }
  const packageResponse = await fetchImpl(
    `${config.havenUrl}/v1/watch-packages/current?audience=harbor`,
    { headers },
  )
  if (!packageResponse.ok) {
    throw new Error(`watch package request failed (${packageResponse.status})`)
  }
  const responseBuoyId = packageResponse.headers.get("x-haven-buoy-id")
  if (responseBuoyId && responseBuoyId !== config.buoyId) {
    throw new Error("watch package response buoy identity mismatch")
  }

  const pkg = (await packageResponse.json()) as WatchPackage
  if (!verifyWatchPackage(pkg as unknown as Record<string, unknown>, config.packagePublicKey)) {
    throw new Error("watch package signature verification failed")
  }
  if (!Array.isArray(pkg.canaries)) throw new Error("watch package canaries are invalid")

  const matches = await scanPaths(config.paths, config.pepper, pkg.canaries, log)
  for (const match of matches) {
    const sighting = {
      buoy_id: config.buoyId,
      canary_id: match.canary_id,
      digest: match.digest,
      observed_at: new Date().toISOString(),
      context: { host: hostname(), path: match.path, source: "file" as const },
    }
    const response = await fetchImpl(`${config.havenUrl}/v1/sightings`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify(sighting),
    })
    if (!response.ok) throw new Error(`sighting request failed (${response.status})`)
    log(`Harbor sighting: ${match.canary_id}`)
  }
  return matches.length
}

async function main(): Promise<void> {
  const config = loadConfig()
  for (;;) {
    try {
      await runCycle(config)
    } catch (error) {
      console.error(`Harbor cycle failed: ${error instanceof Error ? error.message : "unknown error"}`)
    }
    await Bun.sleep(config.pollSeconds * 1000)
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(`Harbor failed: ${error instanceof Error ? error.message : "unknown error"}`)
    process.exit(1)
  })
}
