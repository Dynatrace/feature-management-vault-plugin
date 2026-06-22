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

| Component                                    | File                                           |
|----------------------------------------------|------------------------------------------------|
| Backend wiring, client cache, locks          | `backend.go`                                   |
| Coordinate parsing/validation                | `coordinate.go`                                |
| `config` path                                | `path_config.go`                               |
| `roles/<name>` (policy templates)            | `path_roles.go`                                |
| Coordinate read + secret type (Renew/Revoke) | `path_coordinate.go`                           |
| `rotate/...` path                            | `path_rotate.go`                               |
| Deferred-delete queue + periodic sweep       | `rotation.go`                                  |
| Create crash-safety (WAL) + orphan reaper    | `wal.go`                                       |
| `reconcile` path                             | `path_reconcile.go`                            |
| FM API client (internal)                     | `internal/fmclient/`                           |
| Plugin entrypoint                            | `cmd/vault-plugin-secrets-feature-management/` |

## Plugin paths

| Path                                                | Verb              | Purpose                                                                                                             |
|-----------------------------------------------------|-------------------|---------------------------------------------------------------------------------------------------------------------|
| `config`                                            | write/read/delete | FM base URL, OAuth client (`client_id`/`client_secret`/`token_url`), `dt_tenant`.                                   |
| `roles/<name>`                                      | write/read/delete | Policy template: `ttl`, `max_ttl`, `rotation_grace`, optional `project_key`/`release_stage_key`/`type` constraints. |
| `roles`                                             | list              | List roles.                                                                                                         |
| `<version>/<release-stage>/<project>/<type>`        | read              | Read (lazily mint) the current key for a coordinate; issues a lease.                                                |
| `rotate/<version>/<release-stage>/<project>/<type>` | write             | Force a rotation (new key now; old deleted after `rotation_grace`).                                                 |
| `reconcile`                                         | write             | Clear stale current keys and report/optionally delete orphaned FM keys.                                             |

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

## CI & releases

CI (`.github/workflows/ci.yml`) runs on every push/PR: gofmt check, `go vet`,
`go test -race`, and a GoReleaser snapshot build (the full release pipeline
without publishing, so packaging breaks are caught early). Run the same checks
locally with `make ci`.

Releases are automated with [release-please](https://github.com/googleapis/release-please)
+ [GoReleaser](https://goreleaser.com) (`.github/workflows/release.yml`), driven by
[Conventional Commits](https://www.conventionalcommits.org/):

- `fix:` → patch, `feat:` → minor, `feat!:` / `BREAKING CHANGE:` → major (0.x bumps while pre-1.0).
- release-please maintains a "release PR" that updates `CHANGELOG.md` and the
  version in `.release-please-manifest.json`. Merging it tags `vX.Y.Z` and creates
  the GitHub release.
- On that release, GoReleaser (`.goreleaser.yaml`) cross-compiles
  `linux/{amd64,arm64}` and `darwin/{amd64,arm64}` and uploads `…_<os>_<arch>.zip`
  archives plus a `…_SHA256SUMS` file to the release (it keeps the
  release-please-generated notes; it does not create its own release). The build
  injects the tag into `main.version` via ldflags.

`make release-build` runs the same GoReleaser pipeline locally as a snapshot
(into `dist/`, no publish); `make release-check` validates `.goreleaser.yaml`.

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

## Memory locking (mlock)

On startup the plugin calls `mlock.LockMemory()` (`cmd/vault-plugin-secrets-feature-management/main.go`)
to keep secret material — the privileged FM credential and minted SDK keys — out
of swap. This is **best-effort**: if locking isn't permitted the plugin logs a
warning (`failed to lock memory; secrets may be paged to swap`) and continues, so
it still runs without the capability.

On Linux, `mlock(2)` requires the `CAP_IPC_LOCK` capability. When the Vault
server runs with mlock **enabled** (the default — i.e. `disable_mlock` is not set
to `true`), grant the capability to the plugin binary in Vault's
`plugin_directory`:

```sh
sudo setcap cap_ipc_lock=+ep /etc/vault/plugins/vault-plugin-secrets-feature-management
```

Notes:

- **Re-apply after every deploy.** The capability is stored on the file, so it
  must be re-set each time the binary is replaced (new release, rebuild, or
  re-extracting a release archive into the plugin directory).
- **It does not change the registration checksum.** `setcap` writes the
  `security.capability` extended attribute, not the file's bytes, so the binary's
  `sha256` is unchanged — `vault plugin register -sha256=…` works the same before
  or after `setcap`.
- **Containers:** grant `IPC_LOCK` to the container instead (Docker
  `--cap-add IPC_LOCK`, Kubernetes `securityContext.capabilities.add: ["IPC_LOCK"]`)
  and ensure the `memlock` ulimit is high enough.
- **`disable_mlock = true`:** if the Vault server disables mlock (e.g. on hosts
  with swap turned off, where `setcap` is impractical), the plugin's locking
  failure is expected and harmless — but you're then relying on the host having no
  swap to keep secrets off disk.

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
