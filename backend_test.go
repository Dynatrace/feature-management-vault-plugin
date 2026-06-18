package featuremanagement

import (
	"context"
	"errors"
	"testing"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient/fmclienttest"
)

func testBackend(t *testing.T) (*backend, *fmclienttest.Fake, logical.Storage) {
	t.Helper()
	fake := fmclienttest.New()
	b := newBackend()
	b.clientFactory = func(_ fmclient.Config) (fmclient.FMClient, error) { return fake, nil }

	cfg := &logical.BackendConfig{
		Logger:      hclog.NewNullLogger(),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	}
	require.NoError(t, b.Setup(context.Background(), cfg))
	return b, fake, cfg.StorageView
}

func writeConfig(t *testing.T, b *backend, s logical.Storage) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   s,
		Data: map[string]interface{}{
			"fm_base_url":   "http://fm.example/public/feature-management-service/v0.1",
			"token_url":     "http://sso.example/token",
			"client_id":     "id",
			"client_secret": "secret",
			"dt_tenant":     "tenant1234",
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "config write error: %v", resp)
}

func writeDefaultRole(t *testing.T, b *backend, s logical.Storage) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/default",
		Storage:   s,
		Data: map[string]interface{}{
			"ttl":            "2280h",
			"max_ttl":        "4560h",
			"rotation_grace": "2h",
		},
	})
	require.NoError(t, err)
	if resp != nil {
		require.False(t, resp.IsError(), "role write error: %v", resp)
	}
}

func readCoordinate(t *testing.T, b *backend, s logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.False(t, resp.IsError(), "read error: %v", resp)
	return resp
}

const testCoordPath = "dt01/production/checkout/server"

func testCoord(t *testing.T) coordinate {
	t.Helper()
	c, err := parseCoordinate("dt01", "production", "checkout", "server")
	require.NoError(t, err)
	return c
}

func TestConfig_WriteRedactRead(t *testing.T) {
	b, _, s := testBackend(t)
	writeConfig(t, b, s)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "id", resp.Data["client_id"])
	require.Equal(t, "tenant1234", resp.Data["dt_tenant"])
	_, hasSecret := resp.Data["client_secret"]
	require.False(t, hasSecret, "client_secret must never be returned")
}

func TestConfig_LoopbackWarning(t *testing.T) {
	b, _, s := testBackend(t)
	// Loopback URLs (as in the demo) should write but warn.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"fm_base_url": "http://127.0.0.1:8899/public/feature-management-service/v0.1",
			"token_url":   "http://localhost:8899/sso/oauth2/token",
			"client_id":   "id", "client_secret": "secret", "dt_tenant": "tenant1234",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Warnings, "loopback config should produce a warning")
	require.Contains(t, resp.Warnings[0], "loopback")

	// A real-looking host should not warn.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"fm_base_url": "https://fm.example.com/public/feature-management-service/v0.1",
			"token_url":   "https://sso.example.com/sso/oauth2/token",
		},
	})
	require.NoError(t, err)
	if resp != nil {
		require.Empty(t, resp.Warnings)
	}
}

func TestCoordinate_MintFailureSurfacesConfigHint(t *testing.T) {
	b, fake, s := testBackend(t)
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)
	fake.CreateErr = errors.New("dial tcp 127.0.0.1:8899: connect: connection refused")

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: testCoordPath, Storage: s,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "verify the FM service URL/credentials")
	require.Contains(t, err.Error(), "connection refused")
}

func TestConfig_InvalidTenant(t *testing.T) {
	b, _, s := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"fm_base_url": "http://x/y", "token_url": "http://x/t",
			"client_id": "id", "client_secret": "secret", "dt_tenant": "bad!",
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestRole_ResolveMostSpecific(t *testing.T) {
	b, _, s := testBackend(t)
	ctx := context.Background()

	// Catch-all and a project-specific role.
	_, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.CreateOperation, Path: "roles/default", Storage: s,
		Data: map[string]interface{}{"ttl": "100h", "rotation_grace": "1h"}})
	require.NoError(t, err)
	_, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.CreateOperation, Path: "roles/checkout", Storage: s,
		Data: map[string]interface{}{"project_key": "checkout", "ttl": "200h", "rotation_grace": "1h"}})
	require.NoError(t, err)

	role, err := b.resolveRole(ctx, s, testCoord(t))
	require.NoError(t, err)
	require.Equal(t, "checkout", role.Name)
	require.Equal(t, 200*time.Hour, role.TTL)

	// A coordinate not matching the specific role falls back to the catch-all.
	other, _ := parseCoordinate("dt01", "production", "billing", "server")
	role, err = b.resolveRole(ctx, s, other)
	require.NoError(t, err)
	require.Equal(t, "default", role.Name)
}

func TestCoordinate_ReadMintsAndIsStable(t *testing.T) {
	b, fake, s := testBackend(t)
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	resp := readCoordinate(t, b, s, testCoordPath)
	require.NotNil(t, resp.Secret)
	key1 := resp.Data["sdk_key"].(string)
	require.NotEmpty(t, key1)
	require.Equal(t, 2280*time.Hour, resp.Secret.TTL)
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))

	// A second read returns the same current key (no new mint).
	resp2 := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, key1, resp2.Data["sdk_key"].(string))
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))

	// Internal data carries what revoke needs.
	require.Equal(t, key1, resp.Secret.InternalData["full_sdk_key"])
	require.Equal(t, testCoordPath, resp.Secret.InternalData["coordinate"])
}

func TestCoordinate_NoMatchingRole(t *testing.T) {
	b, _, s := testBackend(t)
	writeConfig(t, b, s)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: testCoordPath, Storage: s,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestRotate_MakeBeforeBreak(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	first := readCoordinate(t, b, s, testCoordPath)
	keyA := first.Data["sdk_key"].(string)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "rotate/" + testCoordPath, Storage: s,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	keyB := resp.Data["sdk_key"].(string)
	require.NotEqual(t, keyA, keyB)

	// Both keys still active (make-before-break); predecessor tombstoned for later.
	require.Equal(t, 2, fake.ActiveCount("checkout", "production"))

	ck, err := b.readCurrentKey(ctx, s, testCoord(t))
	require.NoError(t, err)
	require.Equal(t, keyB, ck.FullSDKKey)

	tombs, err := b.listTombstones(ctx, s)
	require.NoError(t, err)
	require.Len(t, tombs, 1)
	require.Equal(t, keyA, tombs[0].FullSDKKey)
	require.True(t, tombs[0].DeleteAfter.After(time.Now()), "predecessor must survive the grace window")
}

func TestPeriodicFunc_DeletesDueAndKeepsFuture(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	coord := testCoord(t)

	due, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)
	future, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)
	require.Equal(t, 2, fake.ActiveCount("checkout", "production"))

	require.NoError(t, b.enqueueTombstone(ctx, s, coord, due.SdkKey, time.Now().Add(-time.Minute)))
	require.NoError(t, b.enqueueTombstone(ctx, s, coord, future.SdkKey, time.Now().Add(time.Hour)))

	require.NoError(t, b.periodicFunc(ctx, &logical.Request{Storage: s}))

	// Only the due key was deleted; the future one remains queued.
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
	tombs, err := b.listTombstones(ctx, s)
	require.NoError(t, err)
	require.Len(t, tombs, 1)
	require.Equal(t, future.SdkKey, tombs[0].FullSDKKey)
}

func TestRevoke_DeletesAndClearsCurrent(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	read := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Storage: s, Secret: read.Secret,
	})
	require.NoError(t, err)
	require.Equal(t, 0, fake.ActiveCount("checkout", "production"))

	ck, err := b.readCurrentKey(ctx, s, testCoord(t))
	require.NoError(t, err)
	require.Nil(t, ck, "current key should be cleared after revoke")
}

func TestRevoke_FailureEnqueuesTombstoneAndErrors(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	read := readCoordinate(t, b, s, testCoordPath)
	fake.DeleteErr = errors.New("FM unavailable")

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Storage: s, Secret: read.Secret,
	})
	require.Error(t, err, "revoke must surface the delete failure so Vault retries")

	tombs, terr := b.listTombstones(ctx, s)
	require.NoError(t, terr)
	require.Len(t, tombs, 1, "a failed revoke must enqueue a tombstone (orphan retry)")
	require.Equal(t, read.Data["sdk_key"], tombs[0].FullSDKKey)
}

func TestWALRollback_ReapsOrphanKeepsTracked(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	// Tracked key via a normal read.
	read := readCoordinate(t, b, s, testCoordPath)
	tracked := read.Data["sdk_key"].(string)

	// Simulate an orphan from a crashed create: a key in FM the plugin doesn't track.
	orphan, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)
	require.Equal(t, 2, fake.ActiveCount("checkout", "production"))

	err = b.walRollback(ctx, &logical.Request{Storage: s}, walKindCreate, map[string]interface{}{
		"coordinate":    testCoordPath,
		"project":       "checkout",
		"release_stage": "production",
		"type":          "server",
	})
	require.NoError(t, err)

	// Orphan reaped, tracked key preserved.
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
	list, err := fake.ListSdkKeys(ctx, "checkout", "production")
	require.NoError(t, err)
	require.Len(t, list.Server, 1)
	require.Equal(t, tracked, list.Server[0].SdkKey)
	require.NotEqual(t, orphan.SdkKey, list.Server[0].SdkKey)
}
