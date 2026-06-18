# Feature Management Vault Plugin

A custom HashiCorp Vault **secrets-engine plugin** that brokers SDK keys from the
Dynatrace Feature Management (FM) Service. It treats each SDK key as a Vault
**dynamic secret**: keys are minted on demand via the FM API, tied to a Vault
**lease**, and deleted when the lease expires or is revoked. Rotation
(create-new → delete-old after a grace window) is supported, and expiry is
enforced entirely by the plugin because the FM Service has no native key TTL.

> Status: initial scaffold. Builds, unit-tests against a mocked FM service, and
> registers/enables against a local Vault. The FM client is wired to the real
> API contract (OpenAPI v0.1.45). See [Known limitations](#known-limitations).

## Architecture

```
operator/terraform ──configure──▶ feature-management/config, /roles/<name>
consumer ──read──▶ feature-management/<version>/<release-stage>/<project>/<type>
                      │
                      ├─ lazily mints via FM createSdkKey (if absent)
                      └─ returns the key under a Vault lease
lease expiry/revoke ──▶ FM deleteSdkKey
rotate path ──▶ createSdkKey (new) + tombstone old (deleted after rotation_grace)
```

| Component | File |
|---|---|
| Backend wiring, client cache, locks | `backend.go` |
| Coordinate parsing/validation | `coordinate.go` |
| `config` path | `path_config.go` |
| `roles/<name>` (policy templates) | `path_roles.go` |
| Coordinate read + secret type (Renew/Revoke) | `path_coordinate.go` |
| `rotate/...` path | `path_rotate.go` |
| Deferred-delete queue + periodic sweep | `rotation.go` |
| Create crash-safety (WAL) + orphan reaper | `wal.go` |
| `reconcile` path | `path_reconcile.go` |
| FM API client (internal) | `internal/fmclient/` |
| Plugin entrypoint | `cmd/vault-plugin-secrets-feature-management/` |

## Plugin paths

| Path | Verb | Purpose |
|---|---|---|
| `config` | write/read/delete | FM base URL, OAuth client (`client_id`/`client_secret`/`token_url`), `dt_tenant`. |
| `roles/<name>` | write/read/delete | Policy template: `ttl`, `max_ttl`, `rotation_grace`, optional `project_key`/`release_stage_key`/`type` constraints. |
| `roles` | list | List roles. |
| `<version>/<release-stage>/<project>/<type>` | read | Read (lazily mint) the current key for a coordinate; issues a lease. |
| `rotate/<version>/<release-stage>/<project>/<type>` | write | Force a rotation (new key now; old deleted after `rotation_grace`). |
| `reconcile` | write | Clear stale current keys and report/optionally delete orphaned FM keys. |

`<version>` is the SDK-key **format** version (the `dtNN` token, e.g. `dt01`), not
an API or plugin version. Every coordinate element is a path segment so Vault
policies can regex-scope a consumer to, e.g., its own project + release stage.

## Build & test

```sh
make build     # -> bin/vault-plugin-secrets-feature-management
make test      # unit tests (mocked FM client)
make vet
```

Requires Go 1.25.7+, Vault SDK v0.25.x. Targets Vault 2.0.

## Local end-to-end

**Quick start — one command** (self-contained: builds everything, starts a throwaway
dev Vault on a free port + a mock FM service, walks the full lifecycle, tears down):

```sh
./scripts/demo.sh
# DEMO_WAIT_SWEEP=1 ./scripts/demo.sh   # also demonstrates the deferred-delete sweep (~75s)
# KEEP_RUNNING=1   ./scripts/demo.sh   # leave the servers up afterward to poke at
```

**Against a real FM service (live mode)** — set `FM_BASE_URL` (and the other
`FM_*` vars) to point the plugin at a real Feature Management service. It still
runs a throwaway local dev Vault; only the FM service is real. The demo
**creates, rotates, and deletes real SDK keys** for the given project/release
stage (which must already exist), snapshots a baseline first, and on exit deletes
only the keys it created — pre-existing keys are never touched, and the real
`client_secret` is never printed.

```sh
FM_BASE_URL=https://<host>/public/feature-management-service/v0.1 \
FM_TOKEN_URL=https://<sso-host>/sso/oauth2/token \
FM_CLIENT_ID=... FM_CLIENT_SECRET=... FM_TENANT=abcd1234 \
FM_PROJECT=<existing-project> FM_STAGE=<existing-release-stage> \
./scripts/demo.sh            # add LIVE_YES=1 to skip the confirmation prompt
```

The steps below are the same flow done by hand (mock mode).

1. Start a dev Vault pointed at a plugin directory:

   ```sh
   vault server -dev -dev-root-token-id=root -dev-plugin-dir="$PWD/vault/plugins"
   ```

   In another shell:

   ```sh
   export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root
   ```

2. Build, register, and enable the plugin:

   ```sh
   make dev       # builds into vault/plugins, registers, enables, tunes max-lease-ttl
   ```

   Registration uses a semantic `-version` (e.g. `v0.0.1`); on `secrets enable`
   the plugin version flag is `-plugin-version`. SDK keys are long-lived, so the
   mount's max lease TTL is tuned above the 768h system default
   (`vault secrets tune -max-lease-ttl=4560h feature-management/`).

3. Start the mock FM service (no real credentials needed):

   ```sh
   make mock-server   # listens on 127.0.0.1:8899
   ```

4. Configure and use:

   ```sh
   vault write feature-management/config \
     fm_base_url=http://127.0.0.1:8899/public/feature-management-service/v0.1 \
     token_url=http://127.0.0.1:8899/sso/oauth2/token \
     client_id=mock client_secret=mock dt_tenant=tenantxxx

   vault write feature-management/roles/default ttl=2280h max_ttl=4560h rotation_grace=2h

   vault read  feature-management/dt01/production/checkout/server      # mint + lease
   vault write feature-management/rotate/dt01/production/checkout/server  # rotate
   vault lease revoke -prefix feature-management/                       # revoke -> deleteSdkKey
   ```

## Authentication to the FM Service

The plugin authenticates with OAuth 2.0 **client-credentials** against the
Dynatrace SSO token endpoint, requesting scopes
`feature-management:sdk-keys:{read,write,delete}`. The bearer token is cached and
refreshed. The plugin is the only component that holds the privileged FM
credential; consumers only ever see minted SDK keys. The full SDK key secret is
never logged — only the public prefix (`{token}.{platform}_{geo}_{publicRandom}`).

## Known limitations

- **Shared key per coordinate.** A coordinate has one current key; every read
  returns it under a new lease. Revoking any one lease deletes the key in FM, so
  the design assumes effectively one logical consumer per coordinate (consistent
  with the scoping doc's service-scoped policies). Downstream SDKs must handle
  key revocation and re-initialize — tracked as separate work.
- **Coordinate→role resolution** uses most-specific match with an ambiguity
  error; confirm the intended semantics with the team.
- **`<version>` vs minted token**: the plugin records the minted key and warns if
  its `dtNN` token differs from the requested version.
- Out of scope here: SSE rotation notifications, downstream SDK changes, FM
  service-account IAM provisioning, integration tests against a real FM instance,
  and metrics/alerting wiring.
- **LICENSE**: add the license your team requires (not chosen here).
