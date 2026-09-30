# Changelog

All notable changes to Haven are documented here.

## 0.4.2 — 2026-09-30

### Added

- **Delete revoked agent keys.** `POST /v1/agents/:id/credentials/:credential_id/delete` removes a revoked key so key lists don't fill up with dead entries. Active keys return `409 credential_active` — revoke first. Each delete writes an `agent.credential.deleted` ledger event (key prefix only), so the audit trail survives. The Agents screen shows a **Delete** button on revoked keys.

## 0.4.1 — 2026-09-29

### Fixed

- **Docker image shipped a stale operator UI.** The root `Dockerfile` copied a prebuilt `ui/dist` from the build context; because `ui/dist` is gitignored, an image could silently bundle an older UI than its platform code (e.g. 0.4.0's agent-key screens missing). The Dockerfile is now multi-stage and builds the UI from source, and `.dockerignore` excludes any local `ui/dist`.

## 0.4.0 — 2026-09-29

### Security

- **Agents must authenticate to knock.** `POST /v1/knock` previously trusted the `agent_name` in the request body, so anyone who knew a registered agent's name could knock as that agent — and receive a secret-resolving token wherever policy auto-approved. Knock now requires a Haven-issued **agent key** (`Authorization: Bearer haven_agk_…` or `x-haven-agent-key`). Requests without a valid, active key are rejected with `401 agent_credential_required` before any state is written.
- **Agents no longer self-register.** Knocking with an unknown name used to create a new agent. Agents now exist only when an operator registers them.
- **Identity cannot be spoofed in the body.** If a knock names an `agent_name` that differs from the key's agent, it is rejected with `403 agent_identity_mismatch`.

### Added

- Agent keys (`haven_agk_…`): 256-bit random, shown once at issue time, stored only as a SHA-256 hash. An agent key grants **knock access only** — it is rejected by `/v1/secrets/resolve`, `/v1/authorize`, `/v1/tokens/introspect`, `/v1/activity`, and every operator route.
- `POST /v1/agents` now returns the agent's first key in a one-time `credential` field.
- `POST /v1/agents/:id/credentials` — issue an additional key (rotation: issue new, then revoke old).
- `GET /v1/agents/:id/credentials` — list keys (prefix, status, created, last used; never the value or hash).
- `POST /v1/agents/:id/credentials/:credential_id/revoke` — revoke a single key.
- Ledger events `agent.credential.issued` and `agent.credential.revoked` (key prefix only).
- Operator UI: the Agents screen shows a new agent's key once, and can issue and revoke keys per agent.
- README "Identity & access" section describing the full human / agent / token model.

### Changed

- Revoking an agent now also revokes all of its agent keys (it already revoked outstanding tokens).
- `scripts/smoke.sh` issues a key for the smoke agent, asserts unauthenticated and revoked-key knocks return `401`, and asserts the key never appears in the ledger.

### Breaking

- Existing knock callers must send an agent key. For each existing agent, issue one with `POST /v1/agents/:id/credentials` (or from the Agents screen) and configure the agent with it. Until then, its knocks return `401`.
- Agents that self-registered through knock before this release have owner `knock` and no key. Review them and revoke any you don't recognize. See `RUNBOOK.md` → "Agent credentials (breaking change)".

### Known limitations

- When a knock is held for human approval, the approved token is returned to the approver, not delivered to the agent. An agent-side pickup path is planned.
- `/v1/knock` is not rate limited.

## 0.3.0

- Initial public release.
