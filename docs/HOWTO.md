# Haven — How to use

This guide is for operators running Haven and for developers whose agents need secrets. It assumes Haven is reachable on loopback or a private network only — do not expose `:19090` to the public internet.

## Mental model

Haven is a **port**. Secrets stay in the harbor. Agents do not get long-lived API keys. They get an **identity**, they **knock** for clearance, and they receive a **short-lived token** that can resolve a specific secret ref. Every decision is written to a **logbook** (ledger).

| Word | Meaning |
|------|---------|
| **Org** | Tenancy boundary (default bootstrap org is configurable; examples often use `demo`) |
| **Project / berth** | Workspace inside an org that holds keys |
| **Key / berth key** | Named secret: `haven://org/project/env/name` |
| **Agent** | Named non-human identity with scopes |
| **Knock** | Agent request for clearance to act on a need |
| **Guardrail** | Org/project policy for knocks: allow / deny / approve (+ exposure behavior) |
| **Buoy** | Sensor that watches for canary digests (Harbor included; `custom` for other scanners) |
| **Canary** | Planted digest; a sighting means a secret may have leaked to a watched surface |
| **Clearance** | Approvals inbox for knocks and access requests |

## Roles

| Role | Typical powers |
|------|----------------|
| **superadmin** | Bootstrap user; org policy, members, guardrails, reveal/delete with confirm |
| **admin** | Day-to-day secrets, agents, buoys, approvals (per assignment) |
| **user** | Limited; cannot rewrite org guardrails or read secret values without grants |

Enterprise **access assignments** refine what each human can do at org / project / key scope. Explicit deny wins.

---

## 1. Run Haven

### Required environment

| Variable | Purpose |
|----------|---------|
| `HAVEN_TOKEN_SECRET` | 32-byte hex — signs broker tokens |
| `HAVEN_ROOT_ENCRYPTION_KEY` | 32-byte hex — AES-GCM root key for values at rest |
| `HAVEN_CANARY_PEPPER` | 32-byte hex — must **differ** from the root key |
| `HAVEN_BOOTSTRAP_USER` | First human (default `root`) |
| `HAVEN_BOOTSTRAP_PASSWORD` | Bootstrap password (set a long one) |
| `HAVEN_BOOTSTRAP_ORG` | First org slug (default `demo`) |
| `HAVEN_DATA_DIR` | SQLite + ledger directory (default `./data`) |
| `HAVEN_PORT` | Listen port (default `19090`) |
| `HAVEN_UI_DIST` | Optional path to built operator UI |

Generate secrets once:

```bash
export HAVEN_TOKEN_SECRET=$(openssl rand -hex 32)
export HAVEN_ROOT_ENCRYPTION_KEY=$(openssl rand -hex 32)
export HAVEN_CANARY_PEPPER=$(openssl rand -hex 32)
export HAVEN_BOOTSTRAP_USER=root
export HAVEN_BOOTSTRAP_PASSWORD='choose-a-long-password'
export HAVEN_BOOTSTRAP_ORG=demo
export HAVEN_DATA_DIR=./data
```

### Option A — local Bun

```bash
cd ui && bun install && bun run build && cd ..
cd platform
bun run start
# UI + API: http://127.0.0.1:19090
curl -fsS http://127.0.0.1:19090/health
```

### Option B — Docker (repo root)

Build the UI first (`cd ui && bun run build`), then:

```bash
docker build -t haven:local .
docker run --rm -p 19090:19090 \
  -e HAVEN_TOKEN_SECRET \
  -e HAVEN_ROOT_ENCRYPTION_KEY \
  -e HAVEN_CANARY_PEPPER \
  -e HAVEN_BOOTSTRAP_USER \
  -e HAVEN_BOOTSTRAP_PASSWORD \
  -e HAVEN_BOOTSTRAP_ORG \
  -e HAVEN_DATA_DIR=/data \
  -v haven-data:/data \
  haven:local
```

### Smoke test

With env loaded and Haven up:

```bash
export BASE=http://127.0.0.1:19090
bash platform/scripts/smoke.sh
# expects: HAVEN_SMOKE_OK
```

---

## 2. Operator UI walkthrough

Open http://127.0.0.1:19090 and sign in with the bootstrap user.

Sidebar (nautical chrome: **Clearance · Berth · Logbook**):

| Screen | What you do |
|--------|-------------|
| **Projects** | Create berths; open a project to create/list keys (refs only in the list; values stay encrypted) |
| **Approvals** | Clearance inbox — approve / deny / escalate access requests and knocks |
| **Policy** | Action policy at org / project / key scope (defaults + minimums; versioned) |
| **Buoys** | Register Harbor (or other) buoys; plant canaries; watch remediations |
| **Agents** | Register agent identities; revoke when done |
| **Logbook** | Org-scoped ledger events (no secret values) |
| **Administration** | Members, assignments, API keys, org settings |

**Never paste live secret values into git, chat, or docs.** Put values only through the UI or `POST /v1/secrets`.

---

## 3. Day-one operator checklist

1. Health check: `curl -fsS http://127.0.0.1:19090/health`
2. Sign in as bootstrap user; change password under profile if offered
3. Create a **project** (berth) for an app or team
4. Create a **key** (e.g. `OPENAI_API_KEY` in `dev`) — copy the `haven://…` ref, not the value, into agent configs
5. Create an **agent** with scope `secrets:read`
6. Set org **guardrail** to `allow` for dogfood, or `approve` for production-like flow
7. Run smoke or a manual knock → resolve loop (below)
8. (Optional) Register a **Harbor buoy** and plant a sibling canary on a sensitive key

---

## 4. Agent integration (knock → resolve)

Agents never store long-lived provider keys. Flow:

```text
register agent  →  POST /v1/knock  →  short-lived haven_… token  →  POST /v1/secrets/resolve
```

### Knock

```bash
curl -fsS -X POST http://127.0.0.1:19090/v1/knock \
  -H 'content-type: application/json' \
  -d '{
    "org": "demo",
    "project": "default",
    "agent_name": "my-agent",
    "purpose": "draft email",
    "need": [{"action": "secrets:read", "key_ref": "haven://demo/default/dev/OPENAI_API_KEY"}]
  }'
```

Outcomes: `auto_allow` / `auto_deny` / queued for human approval (`approve` guardrail or action policy).

### Resolve (fail closed)

```bash
curl -fsS -X POST http://127.0.0.1:19090/v1/secrets/resolve \
  -H 'content-type: application/json' \
  -d '{"token":"haven_…","resource":"haven://demo/default/dev/OPENAI_API_KEY"}'
```

Without a valid grant, resolve denies. Do not log the `value` field.

Related runtime APIs: `POST /v1/authorize`, `POST /v1/tokens/introspect`, `POST /v1/tokens/revoke`.

---

## 5. Humans and secrets (session API)

```bash
# Session
curl -fsS -c jar -X POST http://127.0.0.1:19090/v1/session \
  -H 'content-type: application/json' \
  -d '{"username":"root","password":"…"}'

# Put secret
curl -fsS -b jar -X POST http://127.0.0.1:19090/v1/secrets \
  -H 'content-type: application/json' \
  -d '{"org":"demo","project":"default","env":"dev","name":"OPENAI_API_KEY","value":"…"}'

# List (masked)
curl -fsS -b jar 'http://127.0.0.1:19090/v1/secrets?org=demo&project=default&env=dev'

# Ledger
curl -fsS -b jar 'http://127.0.0.1:19090/v1/ledger?org=demo&limit=50'
```

Most list routes require `org=…` after enterprise scoping.

Reveal / delete are privileged and audited; delete requires typed name confirmation.

---

## 6. Buoys, canaries, Harbor

1. In UI **Buoys**, register `kind=harbor` → save `buoy id`, `haven_buoy_…` token, canary pepper, package public key (once).
2. Plant a **sibling** canary on a key you care about.
3. Run Harbor with env from `harbor/README.md` (`HAVEN_URL`, `HAVEN_BUOY_ID`, `HAVEN_BUOY_TOKEN`, `HAVEN_CANARY_PEPPER`, `HAVEN_PACKAGE_PUBLIC_KEY`, `HARBOR_WATCH_PATHS`).
4. Buoy HTTP must send **both**:
   - `Authorization: Bearer <haven_buoy_…>`
   - `X-Haven-Buoy-Id: <buoy_id>`
5. On sighting, Haven opens a **remediation** (`block` / `queue` / `observe` per guardrail `on_exposure`). Rotate or dismiss in the UI.


---

## 7. Policy and approvals

- **Guardrails** (org/project): knock default allow/deny/approve + `on_exposure`.
- **Action policy** (org/project/key): richer defaults and minimums for humans and agents; composed key → project → org; fail closed when no default matches.
- **Access requests**: threshold or sequential tiers (`normal` / `elevated` / `breakglass`); SoD rules apply; pending snapshots do not mutate when policy changes mid-flight.

Use **Approvals** for the inbox; use **Policy** to edit documents and preview before activate.

---

## 8. Architecture map (from code graph)

God nodes in this tree: `createHaven()` (store), `createApp()` (HTTP), operator `App.tsx`, action policy + access requests, buoy/canary crypto.

| Path | Role |
|------|------|
| `platform/src/haven.ts` | In-process store: humans, agents, secrets, knocks, buoys, ledger |
| `platform/src/app.ts` | HTTP surface + static UI |
| `platform/src/authorization.ts` / `permissions.ts` / `action_policy.ts` / `access_requests.ts` | Enterprise access control |
| `platform/src/canary_crypto.ts` | Canary digests + watch package signing |
| `ui/` | Operator SPA (Vite + React) |
| `harbor/` | Installable local buoy scanner |
| `brand/` | Locked mark assets |

No import cycles detected in the current graph build (`graphify update .`).

---

## 9. Safety rules

1. Loopback or private LAN only for `:19090`
2. Never commit `.env`, buoy tokens, peppers, or secret values
3. Agent configs store **refs** (`haven://…`), not values
4. Resolve is fail closed without a grant
5. Ledger and watch packages must never contain plaintext secret values
6. Rotate `HAVEN_CANARY_PEPPER` only with a coordinated revoke → replant across all buoys

---

## 10. Where next

- Ops detail: [`RUNBOOK.md`](../RUNBOOK.md)
- Brand assets: [`brand/`](../brand/)
- Contributor notes: [`AGENTS.md`](../AGENTS.md)
