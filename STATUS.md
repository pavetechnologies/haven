# Haven status

**Surface:** loopback `http://127.0.0.1:19090` (API + operator UI)  
**Host:** operator host (`$HAVEN_ROOT`)

## Health

| Check | Probe | Notes |
|-------|-------|-------|
| Platform API | `curl -fsS http://127.0.0.1:19090/health` | Restart the platform process after deploy |
| Operator UI | `http://127.0.0.1:19090/` | Served from `ui/dist` via the platform |
| Buoy ingress | `/v1/watch-packages/current`, `/v1/sightings` | Requires a registered buoy token |
| Harbor buoy | launchd `com.haven.harbor` (optional) | Confirm with a package pull or smoke loop |

## Smoke

```bash
set -a && source $HAVEN_ROOT/platform/.env && set +a
bash $HAVEN_ROOT/platform/scripts/smoke.sh
```

## Notes

- Login is username/password. Agents knock (`POST /v1/knock`).
- Scoped grants and denies compose organization → project → key; explicit deny wins.
- Agent secret **value** path: fail closed without a knock grant.
- Do not expose `:19090` to the public internet.
- Ledger events are append-only and SHA-256 hash-chained; org-scoped auditors can probe integrity with `GET /v1/ledger/verify?org=<slug>`.

## Ops

See `RUNBOOK.md`.
