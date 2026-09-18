/**
 * Haven — identity · broker · PEP · ledger · secrets · knock
 */
import { createApp, VERSION } from "./app.ts"
import { createHavenFromEnv } from "./haven.ts"

const PORT = Number(process.env.HAVEN_PORT || 19090)

const haven = await createHavenFromEnv()
const handleRequest = createApp(haven)

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  fetch: handleRequest,
})

console.log(
  JSON.stringify({
    msg: "haven listening",
    port: server.port,
    version: VERSION,
    dataDir: haven.dataDir,
  }),
)
