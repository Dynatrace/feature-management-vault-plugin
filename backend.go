package featuremanagement

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

const (
	// defaultReconcileInterval is the loop cadence when the mount does not set one.
	defaultReconcileInterval = 6 * time.Hour

	// minReconcileInterval floors the configured interval, in seconds, to spare FM pointless load.
	minReconcileInterval = 300

	// reconcileDisabled is the stored sentinel for a loop turned off; on the wire that is 0.
	reconcileDisabled = -1
)

// reconcileInterval is the mount's configured loop cadence, or the default when unset.
func (c *fmConfig) reconcileInterval() time.Duration {
	if c == nil || c.ReconcileIntervalSeconds <= 0 {
		return defaultReconcileInterval
	}
	return time.Duration(c.ReconcileIntervalSeconds) * time.Second
}

// reconcileEnabled reports whether the reconciliation loop should run on this mount.
func (c *fmConfig) reconcileEnabled() bool {
	return c == nil || c.ReconcileIntervalSeconds != reconcileDisabled
}

// nextReconcileAt spreads passes over interval +/- a third so instances never run in lockstep.
func nextReconcileAt(interval time.Duration) time.Time {
	spread := interval / 3
	return time.Now().Add(interval - spread + time.Duration(rand.Int63n(int64(2*spread))))
}

// Storage key prefixes.
const (
	storageConfig        = "config"
	storageRolePrefix    = "role/"
	storageCurrentPrefix = "current/"
)

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

	// reconcileMu guards nextReconcile, the schedule for the reconciliation loop.
	reconcileMu   sync.Mutex
	nextReconcile time.Time

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
		resolveCreds:  resolveSourcedCredentials,
		nextReconcile: nextReconcileAt(defaultReconcileInterval),
		metrics:       newDefaultMetrics(),
	}

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				storageConfig,
				"role/*",
				"current/*",
			},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRoles(),
			b.pathRolesList(),
			b.pathCoordinateRead(),
			b.pathReconcile(),
		},
		PeriodicFunc: b.periodicFunc,
		Invalidate:   b.invalidate,
		Clean:        b.clean,
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
		b.rearmReconcile()
	}
}

// rearmReconcile makes the next tick run a pass, so a changed reconcile_interval takes effect.
func (b *backend) rearmReconcile() {
	b.reconcileMu.Lock()
	b.nextReconcile = time.Time{}
	b.reconcileMu.Unlock()
}

// clean is called on backend unload.
func (b *backend) clean(_ context.Context) {
	b.resetClient()
}

// lockCoordinate returns the striped lock for a coordinate.
func (b *backend) lockCoordinate(coord coordinate) *locksutil.LockEntry {
	return locksutil.LockForKey(b.coordLocks, coord.String())
}

// isStandby reports whether this node must not write storage (perf standby or DR secondary).
func (b *backend) isStandby() bool {
	repl := b.System().ReplicationState()
	return repl.HasState(consts.ReplicationPerformanceStandby) ||
		repl.HasState(consts.ReplicationDRSecondary)
}

const backendHelp = `
The Feature Management secrets engine brokers SDK keys from the Dynatrace
Feature Management Service. Configure the mount with the FM service URL and
OAuth client credentials at "config", define which coordinates the mount may
serve at "roles/<name>", then read a key at
"<version>/<release-stage>/<project>/<type>". A read adopts the key FM already
holds, or provisions one if FM has none. A reconciliation loop re-points records
at the newest key FM holds. The engine never deletes keys.
`
