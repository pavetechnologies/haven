# Haven Platform

Single Bun process on **:19090**: identity, broker, PEP, ledger, encrypted keys, knock, operator UI.

```bash
export HAVEN_TOKEN_SECRET=$(openssl rand -hex 32)
export HAVEN_ROOT_ENCRYPTION_KEY=$(openssl rand -hex 32)
export HAVEN_BOOTSTRAP_USER=root
export HAVEN_BOOTSTRAP_PASSWORD='choose-a-long-password'
export HAVEN_BOOTSTRAP_ORG=demo
export HAVEN_DATA_DIR=./data
bun run start
```

Login is username/password (argon2id). Agents `POST /v1/knock`. Refs: `haven://org/project/env/name`.

Activity keys: `haven_ak_…` for `/v1/activity` only.
