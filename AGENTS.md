# Haven agent notes

## Purpose

Haven is the agent identity + secrets control plane: credential values, identity, broker tokens, PEP, ledger, fail-closed resolve. Original substrate only.

## Ownership

- Maintainer: product owner / prod gates
- Release owner: coordination and platform integration
- Do not treat this tree as a place to paste credential values

## Local Contracts

- Values live encrypted in the Haven process; Platform holds agent identity, short-lived tokens, authorize, ledger.
- Agent secret retrieval stays **fail closed** except via a reviewed resource-scoped grant.
- Record logical refs only in docs/code comments: `haven://<org>/<project>/<env>/<name>`.
- Never commit `.env` values, admin keys, or token secrets.
- Brand: use assets under `brand/` / `ui/public` only.
- Working surface: `README.md`, `RUNBOOK.md`, `STATUS.md`, `platform/`, `ui/`.

## Work Guidance

- Read `RUNBOOK.md` and `STATUS.md` before ops claims.
- Platform changes: focused edit under `platform/`, then `bash platform/scripts/smoke.sh` with env loaded.

## Verification

```bash
curl -fsS http://127.0.0.1:19090/health

set -a && source $HAVEN_ROOT/platform/.env && set +a
bash $HAVEN_ROOT/platform/scripts/smoke.sh
```

## Human docs

- How to use: `docs/HOWTO.md`
- GitHub/readme: `README.md`
