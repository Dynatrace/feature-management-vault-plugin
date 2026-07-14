package featuremanagement

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

const secretTypeSDKKey = "fm_sdk_key"

// Storage key prefixes.
const (
	storageConfig          = "config"
	storageRolePrefix      = "role/"
	storageCurrentPrefix   = "current/"
	storageTombstonePrefix = "tombstone/"
)

// walKindCreate marks an in-flight createSdkKey so a crash between create and
// store can be reconciled (the orphaned-key reaper).
const walKindCreate = "fm_create_sdkkey"

// walRollbackMinAge must exceed the worst-case createSdkKey latency so a merely
// slow create isn't reaped mid-flight.
const walRollbackMinAge = 10 * time.Minute

// backend is the Feature Management secrets engine.
type backend struct {
	*framework.Backend

	// clientLock guards the cached FM client identity (not the token value).
	clientLock sync.RWMutex
	client     fmclient.FMClient

	// clientFactory builds an FM client from config; overridable in tests.
	clientFactory func(fmclient.Config) (fmclient.FMClient, error)

	// resolveCreds reads the OAuth client credentials from a separate Vault KV
	// path when the mount is configured for sourced credentials; overridable in
	// tests.
	resolveCreds func(ctx context.Context, cfg *fmConfig) (clientID, clientSecret string, err error)

	// coordLocks serializes read-modify-write on a coordinate's current-key
	// record, preventing a double-mint race.
	coordLocks []*locksutil.LockEntry

	// metrics are the OpenTelemetry instruments for the SDK-key lifecycle.
	metrics *metrics
}

// Factory builds the backend for the Vault plugin runtime.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{
		coordLocks: locksutil.CreateLocks(),
		clientFactory: func(cfg fmclient.Config) (fmclient.FMClient, error) {
			return fmclient.New(cfg)
		},
		resolveCreds: resolveAppRoleCredentials,
		metrics:      newDefaultMetrics(),
	}

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				storageConfig,
				"role/*",
				"current/*",
				"tombstone/*",
			},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRoles(),
			b.pathRolesList(),
			b.pathCoordinateRead(),
			b.pathRotate(),
			b.pathReconcile(),
		},
		Secrets: []*framework.Secret{
			b.sdkKeySecret(),
		},
		PeriodicFunc:      b.periodicFunc,
		WALRollback:       b.walRollback,
		WALRollbackMinAge: walRollbackMinAge,
		Invalidate:        b.invalidate,
		Clean:             b.clean,
	}
	return b
}

// getClient returns the cached FM client, lazily building it from stored config.
func (b *backend) getClient(ctx context.Context, s logical.Storage) (fmclient.FMClient, error) {
	b.clientLock.RLock()
	c := b.client
	b.clientLock.RUnlock()
	if c != nil {
		return c, nil
	}

	b.clientLock.Lock()
	defer b.clientLock.Unlock()
	if b.client != nil { // lost the race; reuse
		return b.client, nil
	}

	cfg, err := b.readConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("backend is not configured; write %q first", storageConfig)
	}
	clientCfg := cfg.toClientConfig()
	if cfg.usesSourcedCredentials() {
		id, secret, err := b.resolveCreds(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("resolve client credentials from %q: %w", cfg.ClientCredentialsPath, err)
		}
		clientCfg.ClientID = id
		clientCfg.ClientSecret = secret
	}
	client, err := b.clientFactory(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("build FM client: %w", err)
	}
	b.client = client
	return client, nil
}

// resetClient drops the cached client so the next call rebuilds it (with fresh
// config and a fresh token).
func (b *backend) resetClient() {
	b.clientLock.Lock()
	b.client = nil
	b.clientLock.Unlock()
}

// invalidate is called when storage changes (on every node, including replicas).
func (b *backend) invalidate(_ context.Context, key string) {
	if key == storageConfig {
		b.resetClient()
	}
}

// clean is called on backend unload.
func (b *backend) clean(_ context.Context) {
	b.resetClient()
}

// lockCoordinate returns the striped lock for a coordinate.
func (b *backend) lockCoordinate(coord coordinate) *locksutil.LockEntry {
	return locksutil.LockForKey(b.coordLocks, coord.String())
}

// isStandby reports whether this node must not perform storage writes (a
// performance standby or DR secondary). Background sweeps gate on this.
func (b *backend) isStandby() bool {
	repl := b.System().ReplicationState()
	return repl.HasState(consts.ReplicationPerformanceStandby) ||
		repl.HasState(consts.ReplicationDRSecondary)
}

const backendHelp = `
The Feature Management secrets engine brokers SDK keys from the Dynatrace
Feature Management Service, treating each key as a dynamic secret tied to a
Vault lease. Configure the mount with the FM service URL and OAuth client
credentials at "config", define policy templates at "roles/<name>", then read a
key at "<version>/<release-stage>/<project>/<type>". Keys are deleted when their
lease expires or is revoked; rotation (create-new then delete-old after a grace
window) is available at "rotate/<version>/<release-stage>/<project>/<type>".
`
