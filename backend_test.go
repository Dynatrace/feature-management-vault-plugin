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
	// Fail loudly if a test reaches the real AppRole resolver (which would dial
	// Vault); tests that exercise sourced credentials override this explicitly.
	b.resolveCreds = func(context.Context, *fmConfig) (string, string, error) {
		return "", "", errors.New("resolveCreds not stubbed for this test")
	}

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

func writeSourcedConfig(t *testing.T, b *backend, s logical.Storage, extra map[string]interface{}) *logical.Response {
	t.Helper()
	data := map[string]interface{}{
		"fm_base_url":             "https://fm.example.com/public/feature-management-service/v0.1",
		"token_url":               "https://sso.example.com/sso/oauth2/token",
		"dt_tenant":               "tenant1234",
		"client_credentials_path": "secret/data/dynatrace/fm",
		"auth_role_id":            "role-123",
		"auth_secret_id":          "secret-456",
	}
	for k, v := range extra {
		data[k] = v
	}
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s, Data: data,
	})
	require.NoError(t, err)
	return resp
}

func TestConfig_SourcedCredentials_WriteReadRedacts(t *testing.T) {
	b, _, s := testBackend(t)
	resp := writeSourcedConfig(t, b, s, nil)
	require.False(t, resp.IsError(), "sourced config write error: %v", resp)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "vault_kv", resp.Data["credentials_source"])
	require.Equal(t, "secret/data/dynatrace/fm", resp.Data["client_credentials_path"])
	require.Equal(t, "role-123", resp.Data["auth_role_id"])
	require.Equal(t, "approle", resp.Data["auth_mount"])
	require.Equal(t, 2, resp.Data["kv_version"])
	require.Equal(t, "client_id", resp.Data["client_id_field"])

	// Neither the OAuth secret nor the AppRole secret_id is ever returned, and
	// no inline client_id leaks in sourced mode.
	for _, k := range []string{"client_secret", "auth_secret_id", "client_id"} {
		_, ok := resp.Data[k]
		require.False(t, ok, "%s must never be returned", k)
	}
}

func TestConfig_SourcedCredentials_RejectsInlineClientFields(t *testing.T) {
	b, _, s := testBackend(t)
	resp := writeSourcedConfig(t, b, s, map[string]interface{}{"client_id": "id", "client_secret": "secret"})
	require.True(t, resp.IsError(), "combining client_id with client_credentials_path must error")
	require.Contains(t, resp.Error().Error(), "must not be set")
}

func TestConfig_SourcedCredentials_RequiresAppRoleFields(t *testing.T) {
	b, _, s := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"fm_base_url":             "https://fm.example.com/x",
			"token_url":               "https://sso.example.com/t",
			"dt_tenant":               "tenant1234",
			"client_credentials_path": "secret/data/dynatrace/fm",
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "auth_role_id")
	require.Contains(t, resp.Error().Error(), "auth_secret_id")
}

func TestConfig_SourcedCredentials_RejectsBadKVVersion(t *testing.T) {
	b, _, s := testBackend(t)
	resp := writeSourcedConfig(t, b, s, map[string]interface{}{"kv_version": 3})
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "kv_version")
}

func TestGetClient_SourcedCredentialsFlowIntoClient(t *testing.T) {
	b, fake, s := testBackend(t)

	var gotCfg fmclient.Config
	b.clientFactory = func(c fmclient.Config) (fmclient.FMClient, error) {
		gotCfg = c
		return fake, nil
	}
	var resolveCalls int
	b.resolveCreds = func(_ context.Context, cfg *fmConfig) (string, string, error) {
		resolveCalls++
		require.Equal(t, "secret/data/dynatrace/fm", cfg.ClientCredentialsPath)
		require.Equal(t, "role-123", cfg.AuthRoleID)
		require.Equal(t, "secret-456", cfg.AuthSecretID)
		return "resolved-id", "resolved-secret", nil
	}

	require.False(t, writeSourcedConfig(t, b, s, nil).IsError())

	_, err := b.getClient(context.Background(), s)
	require.NoError(t, err)
	require.Equal(t, 1, resolveCalls)
	require.Equal(t, "resolved-id", gotCfg.ClientID)
	require.Equal(t, "resolved-secret", gotCfg.ClientSecret)

	// Cached: a second getClient does not re-resolve.
	_, err = b.getClient(context.Background(), s)
	require.NoError(t, err)
	require.Equal(t, 1, resolveCalls)
}

func TestGetClient_SourcedCredentialsResolveError(t *testing.T) {
	b, _, s := testBackend(t)
	b.resolveCreds = func(context.Context, *fmConfig) (string, string, error) {
		return "", "", errors.New("approle login: permission denied")
	}
	require.False(t, writeSourcedConfig(t, b, s, nil).IsError())

	_, err := b.getClient(context.Background(), s)
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolve client credentials")
	require.Contains(t, err.Error(), "permission denied")
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
