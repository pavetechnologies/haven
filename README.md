<p align="center">
  <img src="brand/github-header.png" alt="Haven" width="800" />
</p>

<p align="center"><strong>Stop sharing API keys across agents. Give every agent an identity, a short life, and a paper trail.</strong></p>

Haven is an **agent identity and secrets control plane**. Secrets stay encrypted in port. Agents knock for clearance, receive short-lived tokens, and every decision lands in an append-only logbook.

---

## Why Haven

| Problem | Haven’s answer |
|---------|----------------|
| Shared long-lived API keys across bots | Named **agents** + short-lived `haven_…` tokens |
| No audit of who resolved what | Hash-chained **ledger** (org-scoped) |
| Secrets sprawled in env files and chat | Values only in Haven; configs keep `haven://org/project/env/name` **refs** |
| Leak detection after the fact | **Buoys** + **canaries** (Harbor scanner included) |

Haven is original work. Runtime is a single Bun process (API + operator UI). Prefer loopback or a private network — **do not publish `:19090` to the public internet.**

---

## Quick start

### Requirements

- [Bun](https://bun.sh) 1.2+
- Docker optional

### Generate secrets

```bash
export HAVEN_TOKEN_SECRET=$(openssl rand -hex 32)
export HAVEN_ROOT_ENCRYPTION_KEY=$(openssl rand -hex 32)
export HAVEN_CANARY_PEPPER=$(openssl rand -hex 32)   # must differ from root key
export HAVEN_BOOTSTRAP_USER=root
export HAVEN_BOOTSTRAP_PASSWORD='choose-a-long-password'
export HAVEN_BOOTSTRAP_ORG=demo
export HAVEN_DATA_DIR=./platform/data
```

### Run locally

```bash
cd ui && bun install && bun run build && cd ..
cd platform && bun run start
# → http://127.0.0.1:19090
curl -fsS http://127.0.0.1:19090/health
```

### Run with Docker

```bash
cd ui && bun install && bun run build && cd ..
docker build -t haven:local .
docker run --rm -p 19090:19090 \
  -e HAVEN_TOKEN_SECRET -e HAVEN_ROOT_ENCRYPTION_KEY -e HAVEN_CANARY_PEPPER \
  -e HAVEN_BOOTSTRAP_USER -e HAVEN_BOOTSTRAP_PASSWORD -e HAVEN_BOOTSTRAP_ORG \
  -e HAVEN_DATA_DIR=/data -v haven-data:/data \
  haven:local
```

### Smoke

```bash
export BASE=http://127.0.0.1:19090
bash platform/scripts/smoke.sh   # prints HAVEN_SMOKE_OK
```

**Full how-to** (UI tour, agent knock/resolve, buoys, policy): [`docs/HOWTO.md`](docs/HOWTO.md)

---

## Planes

1. **Agent identity** — register / revoke agents  
2. **Token broker** — short-lived `haven_…` tokens  
3. **PEP** — `POST /v1/authorize`  
4. **Ledger** — append-only, hash-chained events  
5. **Secrets** — AES-256-GCM at rest; fail-closed resolve  
6. **Knock** — clearance with org/project guardrails  
7. **Buoys** — canary digests + remediations  

---

## Repository layout

| Path | Role |
|------|------|
| `platform/` | Haven API (Bun) — identity, broker, PEP, ledger, secrets, static UI host |
| `ui/` | Operator SPA (Vite + React) |
| `harbor/` | Local Harbor buoy scanner |
| `brand/` | Logo mark, lockup, favicon |
| `docs/HOWTO.md` | Operator & integrator guide |
| `RUNBOOK.md` | Operations |
| `AGENTS.md` | Contributor / agent contract for this repo |

---

## Operator UI

After login you get:

- **Projects** — berths and keys  
- **Approvals** — clearance inbox  
- **Policy** — action policy workspace  
- **Buoys** — registry, canaries, remediations  
- **Agents** — identities  
- **Logbook** — ledger  
- **Administration** — members, assignments, API keys  

---

## Agent pattern (minimal)

```bash
# 1) Knock (no long-lived provider key on the agent)
curl -fsS -X POST http://127.0.0.1:19090/v1/knock \
  -H 'content-type: application/json' \
  -d '{"org":"demo","project":"default","agent_name":"worker","purpose":"job","need":[{"action":"secrets:read","key_ref":"haven://demo/default/dev/OPENAI_API_KEY"}]}'

# 2) Resolve with the short-lived token from the knock response
curl -fsS -X POST http://127.0.0.1:19090/v1/secrets/resolve \
  -H 'content-type: application/json' \
  -d '{"token":"haven_…","resource":"haven://demo/default/dev/OPENAI_API_KEY"}'
```

Buoy routes also require `X-Haven-Buoy-Id` plus `Authorization: Bearer haven_buoy_…`.

---

## Security notes

- Do not commit `.env`, database files, buoy tokens, or secret values (see `.gitignore`)
- Prefer loopback; treat LAN exposure as trusted-network only
- Resolve and reveal paths are fail closed / audited
- Canary pepper rotation requires coordinated buoy updates

See [`LICENSE-NOTES.md`](LICENSE-NOTES.md) for licensing notes on the crypto construction.

---

## Status & ops

- Live probe discipline: [`STATUS.md`](STATUS.md)  
- Launchd / Harbor ops: [`RUNBOOK.md`](RUNBOOK.md)  
- Tests: `cd platform && bun test`

---

## Contributing

1. Read [`AGENTS.md`](AGENTS.md) and [`docs/HOWTO.md`](docs/HOWTO.md)  
2. Keep credential **values** out of git and PR text — refs only  
3. After platform or UI changes, rebuild UI if needed and run `platform/scripts/smoke.sh`  
---

## License

See [`LICENSE-NOTES.md`](LICENSE-NOTES.md). Haven’s product code and brand are original; AES-256-GCM is a standard construction.
