#!/usr/bin/env bash
# Register and enable the plugin against a running dev Vault.
#
# Prereqs:
#   - A dev Vault started with the plugin directory, e.g.:
#       vault server -dev -dev-root-token-id=root -dev-plugin-dir="$PWD/vault/plugins"
#   - VAULT_ADDR and VAULT_TOKEN exported (dev defaults: http://127.0.0.1:8200 / root)
#   - The plugin binary already built into PLUGIN_DIR (the `make dev` target does this).
set -euo pipefail

PLUGIN_DIR="${PLUGIN_DIR:-$PWD/vault/plugins}"
PLUGIN_NAME="${PLUGIN_NAME:-vault-plugin-dynatrace-feature-management}"
VERSION="${VERSION:-v0.0.1}"
MOUNT="${MOUNT:-feature-management}"
: "${VAULT_ADDR:=http://127.0.0.1:8200}"
export VAULT_ADDR

BIN="${PLUGIN_DIR}/${PLUGIN_NAME}"
if [[ ! -f "${BIN}" ]]; then
  echo "plugin binary not found: ${BIN} (run 'make dev' to build it)" >&2
  exit 1
fi

# sha256 helper (macOS: shasum, Linux: sha256sum)
if command -v sha256sum >/dev/null 2>&1; then
  SHA=$(sha256sum "${BIN}" | cut -d' ' -f1)
else
  SHA=$(shasum -a 256 "${BIN}" | cut -d' ' -f1)
fi
echo "sha256=${SHA}"

vault plugin register -sha256="${SHA}" -version="${VERSION}" secret "${PLUGIN_NAME}"

# Re-enable cleanly if already mounted.
if vault secrets list -format=json | grep -q "\"${MOUNT}/\""; then
  vault secrets disable "${MOUNT}" || true
fi
# Note: on `secrets enable`, the plugin's semantic version is `-plugin-version`
# (`-version` is the KV-engine version flag).
vault secrets enable -path="${MOUNT}" -plugin-version="${VERSION}" "${PLUGIN_NAME}"


echo "enabled ${PLUGIN_NAME} ${VERSION} at ${MOUNT}/"
