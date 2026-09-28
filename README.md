# Feature Management Vault Plugin

A custom HashiCorp Vault **secrets-engine plugin** that brokers SDK keys from the
Dynatrace Feature Management (FM) Service. It does exactly two things: read the
SDK key for a coordinate, and provision one if the FM Service holds none. The
second is rare, since FM creates a key of each type with every release stage.
Keys are **static** - there is no lease, no expiry, no rotation, and **the plugin
never deletes anything in the FM Service**. Its whole job is to connect a
workload's mount path to an SDK key, non-destructively.

> See [Known limitations](#known-limitations).

## Architecture

```
operator/terraform --configure--> feature-management/config, /roles/<name>
consumer --read--> feature-management/<version>/<release-stage>/<project>/<type>
                      |
                      +- local record?      -> return it, no FM call
                      +- else list in FM    -> adopt the existing key if there is one
                      +- else createSdkKey  -> then re-list and adopt the winner
                      +- returns the key verbatim, with no lease

reconciliation loop (every ~6h, jittered)
                      +- re-points each record at the newest key FM holds
```

Provisioning is **read-through**: the FM Service, not the mount's local storage, is
the source of truth for whether a coordinate already has a key. That is what keeps
many independent Vault instances pointed at the same coordinate from each minting
their own key. The per-coordinate lock in `backend.go` only serializes reads inside
one instance; it is not a fleet-wide guard.

The **reconciliation loop** runs a pass every `reconcile_interval` per instance
(default 6 hours), jittered by a third either way so a fleet never runs in
lockstep; the default therefore fires somewhere in 4h-8h. Set `reconcile_interval=0` on the mount config to turn the loop off;
the minimum otherwise is 5m. A pass re-lists the FM
Service for every record the mount holds and re-points each one at the newest key,
which is how an out-of-band rotation reaches consumers without anyone running a
command. `vault write <mount>/reconcile` runs a pass on demand.

The plugin holds no `feature-management:sdk-keys:delete` scope and has no code
path that calls the FM delete endpoint.

| Component                             | File                                           |
| ------------------------------------- | ---------------------------------------------- |
| Backend wiring, client cache, locks   | `backend.go`                                   |
| Coordinate parsing/validation         | `coordinate.go`                                |
| `config` path                         | `path_config.go`                               |
| `roles/<name>` (coordinate allowlist) | `path_roles.go`                                |
| Coordinate read + provision           | `path_coordinate.go`                           |
| `reconcile` path                      | `path_reconcile.go`                            |
| FM API client (internal)              | `internal/fmclient/`                           |
| Plugin entrypoint                     | `cmd/vault-plugin-dynatrace-feature-management/` |

## Plugin paths

| Path                                         | Verb              | Purpose                                                                                                                                                                                                                                                             |
| -------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `config`                                     | write/read/delete | FM base URL, `token_url`, `dt_tenant`, `reconcile_interval`, and the OAuth client credentials, either inline (`client_id`/`client_secret`) or, preferably, sourced from a Vault KV path (`client_credentials_path` + AppRole). See [OAuth client credentials](#oauth-client-credentials). |
| `roles/<name>`                               | write/read/delete | Allowlists which coordinates the mount may serve, via optional `project_key`/`release_stage_key`/`type` constraints. An unconstrained role is a catch-all.                                                                                                          |
| `roles`                                      | list              | List roles.                                                                                                                                                                                                                                                         |
| `<version>/<release-stage>/<project>/<type>` | read              | Read the key for a coordinate, provisioning one if the plugin has not already done so. Returns `sdk_key` and `public_prefix` with no lease.                                                                                                                         |
| `reconcile`                                  | write             | Clear current-key records whose key FM no longer has, so the next read provisions a replacement. Deletes nothing in FM.                                                                                                                                             |

`<version>` is the SDK-key **format** version (the `dtNN` token, e.g. `dt01`), not
an API or plugin version. Every coordinate element is a path segment so Vault
policies can regex-scope a consumer to, e.g., its own project + release stage.

## Build & test

```sh
make build     # -> bin/vault-plugin-dynatrace-feature-management
make test      # unit tests (mocked FM client)
make vet
```

Requires Go 1.25.7+, Vault SDK v0.25.x. Targets Vault 2.0.

## CI & releases

CI (`.github/workflows/ci.yml`) runs on every push/PR: gofmt check, `go vet`,
`go test -race`, and a multi-platform Docker build (`linux/amd64,linux/arm64`)
without publishing — so image build breaks are caught on PRs. Run the same code
checks locally with `make ci`.

Releases are fully automated via
[release-please](https://github.com/googleapis/release-please)
(`.github/workflows/release.yml`), driven by
[Conventional Commits](https://www.conventionalcommits.org/):

- `fix:` → patch, `feat:` → minor, `feat!:` / `BREAKING CHANGE:` → major.
- release-please maintains a "release PR" that updates `CHANGELOG.md` and
  `.release-please-manifest.json`. Merging it tags `vX.Y.Z` and creates the
  GitHub release.
- On that release, the `publish` job builds a multi-platform image
  (`linux/amd64,linux/arm64`) and pushes it to GHCR:

  ```
  ghcr.io/dynatrace/feature-management-vault-plugin:<tag>
  ghcr.io/dynatrace/feature-management-vault-plugin:latest
  ```

  The image contains the plugin binary, its sha256sum, and a busybox `cp`
  binary for init-container use.

### Provenance & attestations

Every released image ships with two attestation layers:

- **BuildKit** (`provenance: mode=max`, `sbom: true`): SLSA provenance and a
  CycloneDX SBOM embedded in the image manifest as OCI referrers.
- **GitHub artifact attestation** (Sigstore-signed): verifiable independently
  with:

  ```sh
  gh attestation verify oci://ghcr.io/dynatrace/feature-management-vault-plugin:<tag> \
    --owner Dynatrace
  ```

## Local end-to-end

**Quick start — one command** (self-contained: builds everything, starts a throwaway
dev Vault on a free port + a mock FM service, walks the full lifecycle, tears down):

```sh
./scripts/demo.sh
# KEEP_RUNNING=1 ./scripts/demo.sh   # leave the servers up afterward to poke at
```

**Against a real FM service (live mode)**: set `FM_BASE_URL` (and the other
`FM_*` vars) to point the plugin at a real Feature Management service. It still
runs a throwaway local dev Vault; only the FM service is real. The demo
**creates real SDK keys** for the given project/release stage (which must already
exist) and snapshots a baseline first. The plugin never deletes; the demo script
itself removes only the keys it created, on exit. Pre-existing keys are never
touched, and the real `client_secret` is never printed.

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
   make dev       # builds into vault/plugins, registers, enables
   ```

   Registration uses a semantic `-version` (e.g. `v0.0.1`); on `secrets enable`
   the plugin version flag is `-plugin-version`.

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

   vault write -f feature-management/roles/default   # catch-all allowlist

   vault read feature-management/dt01/production/checkout/server   # provision + read
   vault read feature-management/dt01/production/checkout/server   # same key, no lease
   ```

## Authentication to the FM Service

The plugin authenticates with OAuth 2.0 **client-credentials** against the
Dynatrace SSO token endpoint, requesting scopes
`feature-management:sdk-keys:{read,write}`. It deliberately does **not** request
`feature-management:sdk-keys:delete`, so a bug here cannot destroy a key even if
the mount is pointed at a production project. The bearer token is cached and
refreshed. The plugin is the only component that holds the privileged FM
credential; consumers only ever see minted SDK keys. The full SDK key secret is
never logged — only the public prefix (`{token}.{platform}_{geo}_{publicRandom}`).

### OAuth client credentials

The OAuth client credentials the plugin authenticates with can be supplied in one
of two ways. **Sourced credentials are preferred** for anything beyond local
experiments — the OAuth secret then never lives in this mount's config and its
access is governed entirely by an AppRole policy.

- **Sourced (preferred):** `client_credentials_path` points at a KV secret in the
  same Vault holding the `client_id`/`client_secret`. The plugin logs in with the
  configured AppRole (`auth_role_id`/`auth_secret_id`) and reads that secret at
  client-build time, so the OAuth secret is never stored on the mount and can be
  rotated in one place. The short-lived AppRole token is revoked immediately after
  the read.

  ```sh
  vault write feature-management/config \
    fm_base_url=https://<host>/platform/feature-management/v0.1 \
    token_url=https://<sso-host>/sso/oauth2/token \
    dt_tenant=tenantxxx \
    client_credentials_path=secret/data/dynatrace/fm \
    auth_role_id=<role-id> auth_secret_id=<secret-id>
  ```

  Optional fields: `client_id_field`/`client_secret_field` (KV field names,
  default `client_id`/`client_secret`), `kv_version` (`1` or `2`, default `2` —
  for KV v2 include `/data/` in the path), `auth_mount` (default `approle`), and
  `vault_addr` (defaults to the plugin's `VAULT_ADDR`; TLS via the standard
  `VAULT_CACERT`/`VAULT_CAPATH`/`VAULT_SKIP_VERIFY` env vars).

- **Inline:** `client_id`/`client_secret` are stored directly on the mount.
  Simplest for local/mock runs, but the secret then lives in the mount config.

  ```sh
  vault write feature-management/config \
    fm_base_url=… token_url=… dt_tenant=tenantxxx \
    client_id=<id> client_secret=<secret>
  ```

**Switching between the two is a plain config write and never errors.** The mode
is chosen from what the request supplies, and the other mode's fields are cleared
so no stale secret lingers:

- Writing `client_credentials_path` selects sourced mode and **takes precedence** —
  if the same request also carries `client_id`/`client_secret`, those are ignored,
  cleared, and a warning is returned.
- Writing `client_id`/`client_secret` *without* a path selects inline mode and
  clears all sourced fields (`client_credentials_path`, the `auth_*` fields, etc.).

`client_secret` and `auth_secret_id` are write-only and never returned on read;
`config` read reports `credentials_source` as `inline` or `vault_kv`.

## Memory locking (mlock)

On startup the plugin calls `mlock.LockMemory()` (`cmd/vault-plugin-dynatrace-feature-management/main.go`)
to keep secret material — the privileged FM credential and minted SDK keys — out
of swap. This is **best-effort**: if locking isn't permitted the plugin logs a
warning (`failed to lock memory; secrets may be paged to swap`) and continues, so
it still runs without the capability.

On Linux, `mlock(2)` requires the `CAP_IPC_LOCK` capability. When the Vault
server runs with mlock **enabled** (the default — i.e. `disable_mlock` is not set
to `true`), grant the capability to the plugin binary in Vault's
`plugin_directory`:

```sh
sudo setcap cap_ipc_lock=+ep /etc/vault/plugins/vault-plugin-dynatrace-feature-management
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

- **Rotation is an FM-side operator task, and it is "make-before-break".** Create a
  replacement key in the FM service; each instance re-points onto it on its next
  pass of the reconciliation loop, so allow up to 8 hours for the whole fleet. Delete the old key once you
  are satisfied. The plugin never deletes it for you. **Keep in mind the system provides no assurances
  that keys are ONLY used by the plugin - after 8 hours, no vault instance will be using the older key (assuming default configuration) but that doesn't guarantee no workload was manually configured to use it.**
- **Shared key per coordinate.** A coordinate has one key and every consumer
  reading that coordinate gets the same value, across every instance.
- **The plugin serves keys it did not create.** Adoption cannot distinguish a key
  the plugin minted from one a team created by hand, because the FM Service has no
  owner or name field on SDK keys. Adopting is deliberate: it is what prevents a
  parallel key being minted alongside one already in use.
- **Creation is a fallback.** The FM Service provisions a key of each type with
  every release stage, so a coordinate normally already has one to adopt and the
  create path does not run. If instances ever do race on a genuinely empty
  coordinate they can each create one, since FM has no uniqueness constraint. To
  narrow that, an instance that finds FM empty waits a random moment and looks
  again before creating, and the reconciliation loop then settles everyone on one
  key. Any extras stay in FM unreaped.
- **Coordinate to role resolution** uses most-specific match with an ambiguity
  error; confirm the intended semantics with the team.
- **`<version>` vs provisioned token**: the plugin records the key it got and
  warns if its `dtNN` token differs from the requested version.
- Out of scope here: downstream SDK changes, FM service-account IAM
  provisioning, integration tests against a real FM instance, and
  metrics/alerting wiring.
- **LICENSE**: add the license your team requires (not chosen here).
