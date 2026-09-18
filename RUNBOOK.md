# Haven runbook

**Host context:** operator host primary (`$HAVEN_ROOT`). Prefer loopback probes.

## Services

| Service | How | Port |
|---------|-----|------|
| Haven API + operator UI | launchd `com.haven.platform` | **19090** |
| Harbor buoy | launchd `com.haven.harbor` | outbound to Haven only |

### Platform (operator host)

```bash
launchctl print gui/$(id -u)/com.haven.platform | head -40
launchctl kickstart -k gui/$(id -u)/com.haven.platform

curl -fsS http://127.0.0.1:19090/health
```

- Working directory: `$HAVEN_ROOT/platform`
- Env: `platform/.env` (mode `600`). Required: `HAVEN_TOKEN_SECRET`, `HAVEN_ROOT_ENCRYPTION_KEY`, `HAVEN_CANARY_PEPPER`, `HAVEN_BOOTSTRAP_USER` (first boot only).
- Generate the canary pepper once with `openssl rand -hex 32`; store it only as `HAVEN_CANARY_PEPPER`. It must be a 32-byte hex value and must not equal `HAVEN_ROOT_ENCRYPTION_KEY`.
- Data: `platform/data/` (directory mode `700`; files `600`) — `haven.db`
- UI: `ui/dist` (rebuild with `bunx vite build` in `ui/` after UI changes)
- Startup must fail closed if required secrets missing or known dev placeholders

### Harbor (operator host)

Create an owner-readable local copy of `harbor/launchd/com.haven.harbor.plist.example`, replace its placeholders with the buoy ID, issued token, package public key returned at registration, the same canary pepper used by Haven, and the paths to scan, then load it:

```bash
chmod 600 ~/Library/LaunchAgents/com.haven.harbor.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.haven.harbor.plist
launchctl print gui/$(id -u)/com.haven.harbor
launchctl kickstart -k gui/$(id -u)/com.haven.harbor
```

Do not commit the local plist, buoy token, or canary pepper. Pepper rotation invalidates digest matching: revoke all existing canaries, update Haven and every buoy with the new pepper, restart them, and replant canaries.

### Smoke

```bash
set -a && source $HAVEN_ROOT/platform/.env && set +a
bash $HAVEN_ROOT/platform/scripts/smoke.sh
```

## Admin API quick start

```bash
set -a && source $HAVEN_ROOT/platform/.env && set +a
curl -fsS http://127.0.0.1:19090/health
curl -fsS -c /tmp/haven.jar -X POST http://127.0.0.1:19090/v1/session \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$HAVEN_BOOTSTRAP_USER\",\"password\":\"$HAVEN_BOOTSTRAP_PASSWORD\"}"
curl -fsS -b /tmp/haven.jar http://127.0.0.1:19090/v1/me
```

Operator UI: http://127.0.0.1:19090/

### Access administration

Use **Administration → Access** to select the active organization and member, review assigned, inherited, and effective permissions, and record scoped grants or denies. Every assignment or revocation requires an operator reason; the server remains authoritative and rejects invalid scopes or protected-root lockout attempts.

The permission catalog is `GET /v1/permissions`. Effective access is `GET /v1/orgs/:org/users/:userId/access`; assignments are created with `POST /v1/orgs/:org/access-assignments` and revoked with `POST /v1/orgs/:org/access-assignments/:assignmentId/revoke`. Scope inheritance runs organization → project → key, and an applicable explicit deny takes precedence over a grant. Use `POST /v1/authorization/explain` to inspect the server decision, matching assignments, and decision ID without retrieving a secret value.

Treat the legacy membership role as a compatibility bootstrap, not the source of truth for scoped authorization. Before removing broad access, inspect the member's effective permissions at the target scope. Root protections reject changes that would leave the protected organization without required administration capability.

### Approval inbox

Use **Approvals** to review pending access requests eligible for the signed-in operator at each request's org/project/key scope. Each row shows its origin, owner, scoped resource, current approval stage, policy explanation, and any separate requester reason. Approval and denial enforce the current tier permission and separation of duties; escalation requires `approvals.escalate` and a reason. Self-approval and repeated sequential approval candidates are omitted. Transitions against expired requests return HTTP `410`.

The corresponding routes are `GET /v1/access-requests?org=<slug>`, `GET /v1/access-requests/:id`, and `POST /v1/access-requests/:id/{approve|deny|escalate|cancel}`. The list is membership-gated and filters every row by scoped `approvals.read` plus the current tier permission or `approvals.escalate`; detail reads require scoped `approvals.read`.

### Policy workspace

Use **Policy** to edit action defaults and minimum constraints at organization, project, or stable key-ID scope. Preview the candidate before activation: Haven composes key → project → organization, warns when a parent minimum neutralizes a weaker child outcome, and denies when no default matches. Policy writes use the displayed `expected_version`; HTTP `409 policy_version_conflict` means another operator activated a version first, so reload before retrying.

Read and write routes are `GET|PUT /v1/orgs/:org/policy`, `GET|PUT /v1/orgs/:org/projects/:project/policy`, and `GET|PUT /v1/keys/:keyId/policy`. Append `/history` to any policy GET route for immutable versions. `POST /v1/policies/preview` evaluates a candidate without activating it. The server gates each scope with its `policies.*.read` or `policies.*.manage` permission.

### Superadmin key controls

Only `superadmin` members can reveal or delete a key value. Reveal is a one-time UI action (`POST /v1/secrets/reveal`) and records `secret.reveal` in the ledger without the value. Delete (`POST /v1/secrets/delete`) requires typing the exact key name, permanently removes the key, and records `secret.delete`; it cannot be restored in v1.

### Ledger integrity

Ledger events are hash-chained with SHA-256 using each event's `prev_hash` and a canonical JSON hash of the existing event fields. An operator with org-scoped `audit.read` can verify the complete ledger file with `GET /v1/ledger/verify?org=<slug>`; `valid: false` reports the first broken line without returning event contents.

Migration is deliberately fail closed. Ledger lines written before hash chaining, including lines missing either hash field, make verification invalid and are not rewritten. A later append starts a new chain segment with `prev_hash: null` when the preceding legacy line has no usable hash, but verification continues to report the original legacy line as the first break. Preserve the old file for audit history or archive it through a separately reviewed operational migration before starting a fresh ledger.

### Database schema migrations

Startup applies table creation, supported `ALTER TABLE ... ADD COLUMN` changes, and data backfills in one SQLite transaction. Any schema or backfill error rolls the database migration back and prevents startup. SQLite supports the DDL used by the current migration transactionally; filesystem side effects such as ledger and package-key files are outside SQLite and are not part of that transaction.

API keys created before organization scoping are backfilled to `HAVEN_BOOTSTRAP_ORG` during this migration. They remain visible and revocable through that organization's API-key administration routes. Active API keys with a null organization are rejected during authentication, so operators should investigate and revoke/reissue any such row if a manual database change bypassed migration.

## Docs map

- Contributor contract → `AGENTS.md`
- Live snapshot → `STATUS.md`
- Brand assets → `brand/`

## Deploying enterprise access control

```bash
cd $HAVEN_ROOT/platform && bun test
cd $HAVEN_ROOT/ui && bun run build
launchctl kickstart -k gui/$(id -u)/com.haven.platform
curl -fsS http://127.0.0.1:19090/health
```


## Incident notes

- Do not publish :19090 to the public internet
- Rotate control-plane secrets by editing `platform/.env` + kickstart LaunchAgent
- Ledger is append-only and hash-chained; verify it with the org-gated ledger integrity route
