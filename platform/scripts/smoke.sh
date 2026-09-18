#!/usr/bin/env bash
# Haven smoke (idempotent). Requires a signed-in bootstrap human.
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:19090}"
USER="${HAVEN_BOOTSTRAP_USER:?set HAVEN_BOOTSTRAP_USER}"
PASS="${HAVEN_BOOTSTRAP_PASSWORD:?set HAVEN_BOOTSTRAP_PASSWORD}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

echo "== health =="
curl -fsS "$BASE/health" | tee /tmp/haven-health.json
python3 -c 'import json; d=json.load(open("/tmp/haven-health.json")); assert d.get("service")=="haven", d'
echo

echo "== session =="
curl -fsS -c "$JAR" -X POST "$BASE/v1/session" -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" >/tmp/haven-session.json

H=(-b "$JAR" -H "Content-Type: application/json")

echo "== put key =="
SMOKE_NAME="SMOKE_$(openssl rand -hex 4)"
SMOKE_VAL="$(openssl rand -hex 12)"
export SMOKE_NAME SMOKE_VAL
curl -fsS -X POST "$BASE/v1/secrets" "${H[@]}" \
  -d "$(python3 -c 'import json,os; print(json.dumps({"org":"demo","project":"default","env":"dev","name":os.environ["SMOKE_NAME"],"value":os.environ["SMOKE_VAL"]}))')" \
  >/tmp/haven-put.json
REF=$(python3 -c 'import json; print(json.load(open("/tmp/haven-put.json"))["ref"])')
export REF
echo "put $REF"

echo "== list masked =="
LIST=$(curl -fsS "$BASE/v1/secrets?org=demo&project=default&env=dev" "${H[@]}")
python3 -c 'import json,os,sys; raw=sys.stdin.read(); assert os.environ["SMOKE_VAL"] not in raw; d=json.loads(raw); assert any(s["name"]==os.environ["SMOKE_NAME"] for s in d["secrets"])' <<<"$LIST"

echo "== known agent + allow guardrail =="
curl -fsS -X PUT "$BASE/v1/orgs/demo/guardrails" "${H[@]}" \
  -d '{"default":"allow","allow_agents":["*"],"allow_actions":["secrets:read"],"max_ttl_seconds":300,"require_approval":false,"on_exposure":"queue"}' \
  >/tmp/haven-guard.json

AGENTS=$(curl -fsS "$BASE/v1/agents?org=demo" "${H[@]}")
AID=$(echo "$AGENTS" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for a in d.get("agents") or []:
    if a.get("name")=="haven-smoke" and a.get("status")=="active":
        print(a["id"]); raise SystemExit
print("")
')
if [[ -z "$AID" ]]; then
  AGENT=$(curl -fsS -X POST "$BASE/v1/agents" "${H[@]}" -d '{
    "org": "demo",
    "name": "haven-smoke",
    "owner": "root",
    "purpose": "smoke knock",
    "risk_tier": "low",
    "scopes": ["secrets:read"]
  }')
  AID=$(echo "$AGENT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
fi
echo "agent $AID"

echo "== knock =="
KNOCK=$(curl -fsS -X POST "$BASE/v1/knock" -H "Content-Type: application/json" \
  -d "{\"org\":\"demo\",\"project\":\"default\",\"agent_name\":\"haven-smoke\",\"purpose\":\"smoke\",\"need\":[{\"action\":\"secrets:read\",\"key_ref\":\"$REF\"}]}")
echo "$KNOCK" | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k:d[k] for k in d if k!="token"}); assert d.get("status")=="auto_allow", d'
TOKEN=$(echo "$KNOCK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

echo "== resolve =="
python3 - "$BASE" "$TOKEN" "$REF" <<'PY'
import json, os, sys, urllib.request
base, token, ref = sys.argv[1], sys.argv[2], sys.argv[3]
expect = os.environ["SMOKE_VAL"]
req = urllib.request.Request(
    base + "/v1/secrets/resolve",
    data=json.dumps({"token": token, "resource": ref}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req) as r:
    body = json.loads(r.read().decode())
assert body.get("allow") is True, body
assert body.get("value") == expect, "value mismatch"
print("resolve ok decision", body.get("decision_id"))
PY

curl -fsS "$BASE/v1/ledger?org=demo&limit=20" "${H[@]}" | python3 -c '
import json, os, sys
raw = sys.stdin.read()
assert os.environ["SMOKE_VAL"] not in raw, "secret value leaked into ledger"
d = json.loads(raw)
types = [e.get("type") for e in d.get("events", [])]
assert "secret.resolve" in types, types
print("ledger clean of secret value; saw secret.resolve")
'

echo "== buoy register =="
BUOY_NAME="haven-smoke-$(openssl rand -hex 4)"
BUOY=$(curl -fsS -X POST "$BASE/v1/buoys" "${H[@]}" \
  -d "{\"org\":\"demo\",\"kind\":\"harbor\",\"name\":\"$BUOY_NAME\"}")
BUOY_ID=$(echo "$BUOY" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["token"].startswith("haven_buoy_"), d; print(d["buoy"]["id"])')
BUOY_TOKEN=$(echo "$BUOY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
echo "buoy $BUOY_ID"

echo "== plant sibling canary =="
CANARY=$(curl -fsS -X POST "$BASE/v1/canaries" "${H[@]}" \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"org":"demo","project":"default","mode":"sibling","key_ref":sys.argv[1]}))' "$REF")")
CANARY_ID=$(echo "$CANARY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["canary"]["id"])')
CANARY_DIGEST=$(echo "$CANARY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["canary"]["digest"])')
echo "canary $CANARY_ID"

echo "== buoy watch package =="
PACKAGE=$(curl -fsS "$BASE/v1/watch-packages/current?audience=harbor" \
  -H "Authorization: Bearer $BUOY_TOKEN" \
  -H "X-Haven-Buoy-Id: $BUOY_ID")
export CANARY_ID CANARY_DIGEST
python3 -c '
import json, os, sys
raw = sys.stdin.read()
assert os.environ["SMOKE_VAL"] not in raw, "secret value leaked into watch package"
d = json.loads(raw)
assert any(
    c.get("canary_id") == os.environ["CANARY_ID"]
    and c.get("digest") == os.environ["CANARY_DIGEST"]
    and c.get("revoked") is False
    for c in d.get("canaries", [])
), d
print("package clean of secret value; saw sibling canary")
' <<<"$PACKAGE"

echo "== buoy sighting + remediation =="
SIGHTING=$(curl -fsS -X POST "$BASE/v1/sightings" \
  -H "Authorization: Bearer $BUOY_TOKEN" \
  -H "X-Haven-Buoy-Id: $BUOY_ID" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c 'import datetime,json,os,sys; print(json.dumps({"buoy_id":sys.argv[1],"canary_id":os.environ["CANARY_ID"],"digest":os.environ["CANARY_DIGEST"],"observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"context":{"source":"smoke"}}))' "$BUOY_ID")")
REMEDIATION_ID=$(echo "$SIGHTING" | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
r = d["remediation"]
assert r["status"] == "open", r
assert r["on_exposure_applied"] == "queue", r
assert r["key_ref"] == os.environ["REF"], r
print(r["id"])
')
export REMEDIATION_ID
curl -fsS "$BASE/v1/remediations?org=demo&status=open" "${H[@]}" | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
assert any(r.get("id") == os.environ["REMEDIATION_ID"] for r in d.get("remediations", [])), d
print("sighting opened queue remediation", os.environ["REMEDIATION_ID"])
'

echo
echo "HAVEN_SMOKE_OK ref=$REF"
