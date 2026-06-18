#!/usr/bin/env bash
#
# demo.sh — end-to-end demonstration of the Feature Management Vault plugin.
#
# Two modes:
#
#   MOCK (default) — fully self-contained: builds a mock FM service + a throwaway
#   dev Vault and exercises the full SDK-key lifecycle with no real credentials.
#
#       ./scripts/demo.sh
#
#   LIVE — points the plugin at a REAL Feature Management service. Triggered by
#   setting FM_BASE_URL (all FM_* vars below are then required). It still runs a
#   throwaway dev Vault locally; only the FM service is real.
#
#       FM_BASE_URL=https://<host>/public/feature-management-service/v0.1 \
#       FM_TOKEN_URL=https://<sso-host>/sso/oauth2/token \
#       FM_CLIENT_ID=... FM_CLIENT_SECRET=... FM_TENANT=abcd1234 \
#       FM_PROJECT=<existing-project> FM_STAGE=<existing-release-stage> \
#       ./scripts/demo.sh
#
#     LIVE mode CREATES, ROTATES and DELETES real SDK keys for the given
#     project/release-stage (which must already exist). Keys the demo creates are
#     cleaned up on exit; pre-existing keys are never touched. The real
#     client_secret is never printed.
#
# Options (env vars):
#   FM_PROJECT / FM_STAGE / FM_TYPE / FM_VERSION   coordinate (defaults below)
#   VAULT_PORT=8210 / MOCK_PORT=8899               preferred ports (auto-bump)
#   KEEP_RUNNING=1     leave the servers running afterward (skips FM cleanup)
#   LIVE_YES=1         skip the live-mode confirmation prompt
#   DEMO_WAIT_SWEEP=1  also demonstrate the deferred-delete sweep (waits ~75s)
set -euo pipefail

PLUGIN_NAME="vault-plugin-secrets-feature-management"
PLUGIN_VERSION="v0.0.1"
MOUNT="feature-management"
SCOPES="feature-management:sdk-keys:read feature-management:sdk-keys:write feature-management:sdk-keys:delete"

# Coordinate (override for LIVE mode to match a real project / release stage).
VERSION="${FM_VERSION:-dt01}"
STAGE="${FM_STAGE:-production}"
PROJECT="${FM_PROJECT:-checkout}"
TYPE="${FM_TYPE:-server}"
COORD="${VERSION}/${STAGE}/${PROJECT}/${TYPE}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolve to the physical path: Vault rejects a plugin whose real (symlink-
# resolved) location differs from the configured -dev-plugin-dir, and on macOS
# $TMPDIR lives under the /var -> /private/var symlink.
WORKDIR="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/fm-vault-demo.XXXXXX")" && pwd -P)"
PLUGIN_DIR="${WORKDIR}/plugins"
MOCK_BIN="${WORKDIR}/mock-fm-server"
MOCK_LOG="${WORKDIR}/mock-fm.log"
VAULT_LOG="${WORKDIR}/vault-dev.log"
BASELINE="${WORKDIR}/baseline.keys"
MOCK_PID="" VAULT_PID="" MODE="mock"

# usage prints the leading comment header (stops at the first non-comment line).
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "${BASH_SOURCE[0]}"; }

# --- pretty output -----------------------------------------------------------
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
run()  { printf '\033[2m$ %s\033[0m\n' "$*"; eval "$*"; }

# --- helpers -----------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "required tool not found: $1" >&2; exit 1; }; }

free_port() { local p="$1"; while lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; do p=$((p + 1)); done; echo "$p"; }

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

wait_http() { # ready once the endpoint accepts a connection (any HTTP code)
  local url="$1"
  for _ in $(seq 1 60); do
    curl -s -o /dev/null --connect-timeout 2 --max-time 4 "$url" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}

public_prefix() { printf '%s' "$1" | cut -d. -f1-2; }

# json_get <key> — extract a top-level string field from JSON on stdin.
json_get() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null
  else
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1
  fi
}

# extract_sdkkeys — print every sdkKey value from an SDKKeyList JSON on stdin.
extract_sdkkeys() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for t in ("web", "mobile", "server"):
    for k in (d.get(t) or []):
        if k.get("sdkKey"):
            print(k["sdkKey"])
' 2>/dev/null
  else
    grep -o '"sdkKey"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -E 's/.*: *"([^"]*)"/\1/'
  fi
}

fm_token() { # echo a client-credentials bearer token (empty on failure)
  curl -s --max-time 15 -X POST "$CFG_TOKEN_URL" \
    -d grant_type=client_credentials \
    -d "client_id=${CFG_CLIENT_ID}" -d "client_secret=${CFG_CLIENT_SECRET}" \
    --data-urlencode "scope=${SCOPES}" 2>/dev/null | json_get access_token
}

fm_list_keys() { # echo every active sdkKey for the coordinate's bucket (one per line)
  local tok body status
  tok="$(fm_token)"; [[ -z "$tok" ]] && return 0
  body="$(mktemp)"
  status="$(curl -s --max-time 15 -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer ${tok}" -H "Dt-Tenant: ${CFG_TENANT}" \
    "${CFG_FM_BASE_URL}/projects/${PROJECT}/release-stages/${STAGE}/sdk-keys" 2>/dev/null || echo 000)"
  [[ "$status" == "200" ]] && extract_sdkkeys <"$body"
  rm -f "$body"
}

fm_count() { # echo the number of active keys in the bucket, or n/a on error
  local tok body status
  tok="$(fm_token)"; [[ -z "$tok" ]] && { echo "n/a (no token)"; return; }
  body="$(mktemp)"
  status="$(curl -s --max-time 15 -o "$body" -w '%{http_code}' \
    -H "Authorization: Bearer ${tok}" -H "Dt-Tenant: ${CFG_TENANT}" \
    "${CFG_FM_BASE_URL}/projects/${PROJECT}/release-stages/${STAGE}/sdk-keys" 2>/dev/null || echo 000)"
  if [[ "$status" == "200" ]]; then extract_sdkkeys <"$body" | grep -c . | tr -d ' '; else echo "n/a (HTTP ${status})"; fi
  rm -f "$body"
}

# live_cleanup — delete ONLY the keys this demo created (current bucket minus the
# baseline snapshot). Pre-existing keys are never touched.
live_cleanup() {
  [[ "$MODE" == "live" ]] || return 0
  [[ -f "$BASELINE" ]] || return 0
  local tok created
  created="$(comm -13 <(sort -u "$BASELINE") <(fm_list_keys | sort -u) 2>/dev/null || true)"
  if [[ -z "$created" ]]; then echo "live cleanup: no demo-created keys remain in FM"; return 0; fi
  tok="$(fm_token)"
  echo "live cleanup: deleting demo-created keys (pre-existing keys left untouched) ..."
  while IFS= read -r k; do
    [[ -z "$k" ]] && continue
    curl -s --max-time 15 -X DELETE \
      -H "Authorization: Bearer ${tok}" -H "Dt-Tenant: ${CFG_TENANT}" \
      "${CFG_FM_BASE_URL}/projects/${PROJECT}/release-stages/${STAGE}/sdk-keys/${k}" >/dev/null 2>&1 \
      && echo "  deleted $(public_prefix "$k")"
  done <<<"$created"
}

# --- cleanup -----------------------------------------------------------------
cleanup() {
  if [[ "${KEEP_RUNNING:-0}" == "1" ]]; then
    bold "KEEP_RUNNING=1 — leaving servers up (FM cleanup skipped):"
    echo "  VAULT_ADDR=${VAULT_ADDR}  VAULT_TOKEN=root   (vault pid ${VAULT_PID})"
    [[ "$MODE" == "mock" ]] && echo "  mock FM:    http://127.0.0.1:${MOCK_PORT}     (mock pid ${MOCK_PID})"
    echo "  workdir:    ${WORKDIR}"
    return
  fi
  live_cleanup || true
  [[ -n "${VAULT_PID}" ]] && kill "${VAULT_PID}" 2>/dev/null || true
  [[ -n "${MOCK_PID}" ]] && kill "${MOCK_PID}" 2>/dev/null || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT INT TERM

# --- mode detection (after the trap so an early exit still cleans up) ---------
if [[ -n "${FM_BASE_URL:-}" ]]; then
  MODE="live"
  missing=()
  [[ -n "${FM_TOKEN_URL:-}" ]]     || missing+=(FM_TOKEN_URL)
  [[ -n "${FM_CLIENT_ID:-}" ]]     || missing+=(FM_CLIENT_ID)
  [[ -n "${FM_CLIENT_SECRET:-}" ]] || missing+=(FM_CLIENT_SECRET)
  [[ -n "${FM_TENANT:-}" ]]        || missing+=(FM_TENANT)
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "LIVE mode requires these env vars: ${missing[*]}" >&2
    echo >&2; usage >&2; exit 1
  fi
fi

# --- prerequisites & ports ---------------------------------------------------
need go; need vault; need curl; need lsof

VAULT_PORT="$(free_port "${VAULT_PORT:-8210}")"
export VAULT_ADDR="http://127.0.0.1:${VAULT_PORT}"
export VAULT_TOKEN="root"

if [[ "$MODE" == "live" ]]; then
  CFG_FM_BASE_URL="$FM_BASE_URL"
  CFG_TOKEN_URL="$FM_TOKEN_URL"
  CFG_CLIENT_ID="$FM_CLIENT_ID"
  CFG_CLIENT_SECRET="$FM_CLIENT_SECRET"
  CFG_TENANT="$FM_TENANT"
else
  MOCK_PORT="$(free_port "${MOCK_PORT:-8899}")"
  CFG_FM_BASE_URL="http://127.0.0.1:${MOCK_PORT}/public/feature-management-service/v0.1"
  CFG_TOKEN_URL="http://127.0.0.1:${MOCK_PORT}/sso/oauth2/token"
  CFG_CLIENT_ID="demo"
  CFG_CLIENT_SECRET="demo-secret"
  CFG_TENANT="tenantxxxx"
fi

# --- live-mode confirmation --------------------------------------------------
if [[ "$MODE" == "live" && "${LIVE_YES:-0}" != "1" ]]; then
  bold "LIVE MODE — this will CREATE, ROTATE and DELETE real SDK keys:"
  echo "  FM service: ${CFG_FM_BASE_URL}"
  echo "  tenant:     ${CFG_TENANT}"
  echo "  coordinate: ${COORD}   (project & release-stage must already exist)"
  echo "  Demo-created keys are cleaned up on exit; pre-existing keys are left untouched."
  printf "Continue? [y/N] "
  read -r ans || ans=""
  case "$ans" in y|Y|yes|YES) ;; *) echo "aborted."; exit 1 ;; esac
fi

bold "mode: ${MODE}   coordinate: ${COORD}"

# --- build -------------------------------------------------------------------
if [[ "$MODE" == "mock" ]]; then step "Build plugin + mock FM server"; else step "Build plugin"; fi
mkdir -p "${PLUGIN_DIR}"
run "go build -o '${PLUGIN_DIR}/${PLUGIN_NAME}' '${REPO_ROOT}/cmd/${PLUGIN_NAME}'"
if [[ "$MODE" == "mock" ]]; then
  run "go build -o '${MOCK_BIN}' '${REPO_ROOT}/scripts/mock-fm-server'"

  step "Start mock FM service on :${MOCK_PORT}"
  "${MOCK_BIN}" -addr "127.0.0.1:${MOCK_PORT}" >"${MOCK_LOG}" 2>&1 &
  MOCK_PID=$!
  wait_http "http://127.0.0.1:${MOCK_PORT}/sso/oauth2/token" || { echo "mock FM never came up:" >&2; cat "${MOCK_LOG}" >&2; exit 1; }
  echo "mock FM up (pid ${MOCK_PID})"
fi

# --- dev Vault ---------------------------------------------------------------
step "Start dev Vault on :${VAULT_PORT} (plugin dir: ${PLUGIN_DIR})"
vault server -dev -dev-root-token-id=root \
  -dev-listen-address="127.0.0.1:${VAULT_PORT}" \
  -dev-plugin-dir="${PLUGIN_DIR}" >"${VAULT_LOG}" 2>&1 &
VAULT_PID=$!
wait_http "${VAULT_ADDR}/v1/sys/health" || { echo "dev Vault never became ready; log:" >&2; tail -30 "${VAULT_LOG}" >&2; exit 1; }
echo "dev Vault up (pid ${VAULT_PID}) at ${VAULT_ADDR}"

step "Register + enable the plugin"
SHA="$(sha256 "${PLUGIN_DIR}/${PLUGIN_NAME}")"
run "vault plugin register -sha256='${SHA}' -version='${PLUGIN_VERSION}' secret '${PLUGIN_NAME}'"
run "vault secrets enable -path='${MOUNT}' -plugin-version='${PLUGIN_VERSION}' '${PLUGIN_NAME}'"
run "vault secrets tune -max-lease-ttl=4560h '${MOUNT}'"

step "Configure the mount (client_secret is never printed)"
echo "  fm_base_url = ${CFG_FM_BASE_URL}"
echo "  token_url   = ${CFG_TOKEN_URL}"
echo "  client_id   = ${CFG_CLIENT_ID}   client_secret = *** (hidden)   dt_tenant = ${CFG_TENANT}"
vault write "${MOUNT}/config" \
  fm_base_url="${CFG_FM_BASE_URL}" \
  token_url="${CFG_TOKEN_URL}" \
  client_id="${CFG_CLIENT_ID}" \
  client_secret="${CFG_CLIENT_SECRET}" \
  dt_tenant="${CFG_TENANT}" >/dev/null
echo "configured."
echo "--- read back (client_secret must NOT appear) ---"
run "vault read ${MOUNT}/config"

step "Create a catch-all policy role 'default'"
run "vault write ${MOUNT}/roles/default ttl=2280h max_ttl=4560h rotation_grace=2h"

# Snapshot the pre-existing FM keys so live cleanup only removes what we create.
fm_list_keys >"${BASELINE}" 2>/dev/null || true
BASE_COUNT=0
[[ -s "${BASELINE}" ]] && BASE_COUNT="$(grep -c . "${BASELINE}")"
[[ "$MODE" == "live" ]] && echo "baseline: ${BASE_COUNT} pre-existing key(s) in this bucket (will be preserved)"

step "Read a coordinate → mints a key in FM and issues a Vault lease"
bold "GET ${MOUNT}/${COORD}"
run "vault read ${MOUNT}/${COORD}"
echo "FM active keys: $(fm_count)  (baseline + 1)"

step "Read again → returns the SAME current key (no new mint)"
run "vault read -field=public_prefix ${MOUNT}/${COORD}; echo"
echo "FM active keys: $(fm_count)  (unchanged — stable)"

step "Rotate → mints a NEW key now; predecessor kept until the grace window (make-before-break)"
run "vault write -f ${MOUNT}/rotate/${COORD}"
echo "FM active keys: $(fm_count)  (baseline + 2 — old + new overlap during grace)"

step "Re-read after rotation → consumer picks up the new key under a fresh lease"
run "vault read -field=public_prefix ${MOUNT}/${COORD}; echo"

if [[ "$MODE" == "mock" ]]; then
  step "Reconcile → new key is current, predecessor is queued; no orphans"
  run "vault write -f ${MOUNT}/reconcile"
else
  step "Reconcile (skipped in LIVE mode)"
  echo "Skipped: reconcile treats any untracked FM key as an orphan, which would"
  echo "flag your pre-existing keys. It is safe to run manually (read-only without"
  echo "delete_orphans=true): vault write ${MOUNT}/reconcile"
fi

step "Revoke the leases → deletes the corresponding keys in FM"
run "vault lease revoke -prefix -sync ${MOUNT}/"
echo "FM active keys: $(fm_count)  (both leased keys deleted; back toward baseline of ${BASE_COUNT})"

if [[ "${DEMO_WAIT_SWEEP:-0}" == "1" ]]; then
  step "Demonstrate the deferred-delete sweep (short grace, waits for the periodic func)"
  run "vault write ${MOUNT}/roles/default ttl=2280h max_ttl=4560h rotation_grace=5s"
  run "vault read -field=public_prefix ${MOUNT}/${COORD}; echo"   # ensure a current key exists
  run "vault write -f ${MOUNT}/rotate/${COORD}"
  echo "FM active keys right after rotate: $(fm_count)"
  echo "waiting ~75s for the grace window + periodic sweep ..."
  sleep 75
  echo "FM active keys after sweep: $(fm_count)  (predecessor should be deleted)"
  run "vault lease revoke -prefix -sync ${MOUNT}/"
fi

step "Done"
bold "The plugin minted, served, rotated, and revoked SDK keys end-to-end (${MODE} mode)."
[[ "$MODE" == "live" ]] && echo "Demo-created keys will be cleaned up on exit; your pre-existing keys are untouched."
echo "Logs: ${VAULT_LOG}$( [[ "$MODE" == "mock" ]] && echo " , ${MOCK_LOG}")"
