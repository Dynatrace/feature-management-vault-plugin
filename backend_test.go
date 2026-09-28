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
	b, s := testBackendWith(t, fake)
	return b, fake, s
}

// testBackendWith builds a backend over a caller-supplied fake, so several can share one FM service.
func testBackendWith(t *testing.T, fake *fmclienttest.Fake) (*backend, logical.Storage) {
	t.Helper()
	// the pre-create pause is timing, not behaviour; TestProvision_* cover it explicitly
	prev := createJitter
	createJitter = 0
	t.Cleanup(func() { createJitter = prev })

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
	return b, cfg.StorageView
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

func TestCoordinate_ProvisionFailureSurfacesConfigHint(t *testing.T) {
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

func TestConfig_SourcedCredentials_InlineFieldsLoseToPath(t *testing.T) {
	b, _, s := testBackend(t)
	// Supplying both sources in one request must not error: client_credentials_path
	// takes precedence, the inline creds are cleared, and a warning is returned.
	resp := writeSourcedConfig(t, b, s, map[string]interface{}{"client_id": "id", "client_secret": "secret"})
	require.False(t, resp.IsError(), "combining client_id with client_credentials_path must not error: %v", resp)
	require.NotEmpty(t, resp.Warnings, "expected a warning about the ignored inline credentials")
	require.Contains(t, resp.Warnings[0], "client_credentials_path")

	cfg, err := b.readConfig(context.Background(), s)
	require.NoError(t, err)
	require.True(t, cfg.usesSourcedCredentials())
	require.Empty(t, cfg.ClientID, "inline client_id must be cleared")
	require.Empty(t, cfg.ClientSecret, "inline client_secret must be cleared")
}

// writeInlineConfig writes a minimal inline-credentials config, merging extra.
func writeInlineConfig(t *testing.T, b *backend, s logical.Storage, extra map[string]interface{}) *logical.Response {
	t.Helper()
	data := map[string]interface{}{
		"fm_base_url":   "https://fm.example.com/public/feature-management-service/v0.1",
		"token_url":     "https://sso.example.com/sso/oauth2/token",
		"dt_tenant":     "tenant1234",
		"client_id":     "inline-id",
		"client_secret": "inline-secret",
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

func TestConfig_SwitchSourcedToInline(t *testing.T) {
	b, _, s := testBackend(t)

	// Start sourced (AppRole + KV path).
	require.False(t, writeSourcedConfig(t, b, s, nil).IsError())

	// Switch to inline by providing only client_id/client_secret. This must not
	// error even though the stored config still carried the sourced fields.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"client_id": "inline-id", "client_secret": "inline-secret"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "switching sourced->inline must not error: %v", resp)

	cfg, err := b.readConfig(context.Background(), s)
	require.NoError(t, err)
	require.False(t, cfg.usesSourcedCredentials(), "mount must no longer be in sourced mode")
	require.Equal(t, "inline-id", cfg.ClientID)
	require.Equal(t, "inline-secret", cfg.ClientSecret)
	// Every sourced field must be wiped so no stale AppRole secret_id lingers.
	require.Empty(t, cfg.ClientCredentialsPath)
	require.Empty(t, cfg.AuthRoleID)
	require.Empty(t, cfg.AuthSecretID)
	require.Empty(t, cfg.VaultAddr)
	require.Zero(t, cfg.KVVersion)

	// Read reports inline mode.
	readResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, "inline", readResp.Data["credentials_source"])
}

func TestConfig_SwitchInlineToSourced(t *testing.T) {
	b, _, s := testBackend(t)

	// Start inline.
	require.False(t, writeInlineConfig(t, b, s, nil).IsError())

	// Switch to sourced by providing the KV path + AppRole fields.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{
			"client_credentials_path": "secret/data/dynatrace/fm",
			"auth_role_id":            "role-123",
			"auth_secret_id":          "secret-456",
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "switching inline->sourced must not error: %v", resp)

	cfg, err := b.readConfig(context.Background(), s)
	require.NoError(t, err)
	require.True(t, cfg.usesSourcedCredentials(), "mount must be in sourced mode")
	// Inline credentials must be dropped.
	require.Empty(t, cfg.ClientID)
	require.Empty(t, cfg.ClientSecret)
	require.Equal(t, "secret/data/dynatrace/fm", cfg.ClientCredentialsPath)
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

func TestRole_Allowlist(t *testing.T) {
	b, _, s := testBackend(t)
	ctx := context.Background()
	for name, data := range map[string]map[string]interface{}{
		"byproject": {"project_key": "checkout"},
		"bystage":   {"release_stage_key": "production"},
		"bytype":    {"type": "web"},
	} {
		_, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation, Path: "roles/" + name, Storage: s, Data: data,
		})
		require.NoError(t, err)
	}

	for _, tc := range []struct {
		name    string
		stage   string
		project string
		typ     string
		allowed bool
	}{
		{"two roles permit it, which must union rather than conflict", "production", "checkout", "server", true},
		{"one role permits it", "development", "checkout", "server", true},
		{"only the type role permits it", "development", "billing", "web", true},
		{"no role permits it", "development", "billing", "server", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coord, err := parseCoordinate("dt01", tc.stage, tc.project, tc.typ)
			require.NoError(t, err)
			if tc.allowed {
				require.NoError(t, b.coordinateAllowed(ctx, s, coord))
			} else {
				require.Error(t, b.coordinateAllowed(ctx, s, coord))
			}
		})
	}
}

func TestRole_CatchAllPermitsEverything(t *testing.T) {
	b, _, s := testBackend(t)
	ctx := context.Background()
	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/default", Storage: s,
	})
	require.NoError(t, err)

	for _, coord := range []coordinate{testCoord(t)} {
		require.NoError(t, b.coordinateAllowed(ctx, s, coord))
	}
	other, err := parseCoordinate("dt02", "development", "billing", "mobile")
	require.NoError(t, err)
	require.NoError(t, b.coordinateAllowed(ctx, s, other))
}

func TestCoordinate_ReadProvisionsAndIsStable(t *testing.T) {
	b, fake, s := testBackend(t)
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	resp := readCoordinate(t, b, s, testCoordPath)
	key1 := resp.Data["sdk_key"].(string)
	require.NotEmpty(t, key1)
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))

	// The key is static: no lease, so nothing expires it and nothing revokes it.
	require.Nil(t, resp.Secret)

	// A second read returns the stored key rather than provisioning another.
	resp2 := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, key1, resp2.Data["sdk_key"].(string))
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
	require.Len(t, fake.Created, 1)
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

func TestReconcile_ClearsStaleRecordWithoutDeleting(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	first := readCoordinate(t, b, s, testCoordPath)
	keyA := first.Data["sdk_key"].(string)

	// Simulate the key being removed in FM out of band.
	fake.Drop("checkout", "production", keyA)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Len(t, resp.Data["cleared_stale_current"], 1)

	ck, err := b.readCurrentKey(ctx, s, testCoord(t))
	require.NoError(t, err)
	require.Nil(t, ck, "stale current record should be cleared")

	// The next read provisions a replacement rather than handing back the dead key.
	second := readCoordinate(t, b, s, testCoordPath)
	require.NotEqual(t, keyA, second.Data["sdk_key"].(string))
}

func TestReconcile_KeepsLiveRecord(t *testing.T) {
	b, _, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	first := readCoordinate(t, b, s, testCoordPath)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.NoError(t, err)
	require.Empty(t, resp.Data["cleared_stale_current"])

	second := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, first.Data["sdk_key"], second.Data["sdk_key"])
}

func TestReconcile_ClearsRecordWhenProjectIsGone(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	readCoordinate(t, b, s, testCoordPath)

	// FM 404s the whole bucket once the project or release stage is deleted.
	fake.ListErr = fmclient.ErrNotFound

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Len(t, resp.Data["cleared_stale_current"], 1)

	ck, err := b.readCurrentKey(ctx, s, testCoord(t))
	require.NoError(t, err)
	require.Nil(t, ck, "a 404 bucket means the record is stale")
}

func TestReconcile_PropagatesOtherListErrors(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	readCoordinate(t, b, s, testCoordPath)
	fake.ListErr = errors.New("FM unavailable")

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.Error(t, err, "a transient list failure must not be read as a stale record")

	ck, rerr := b.readCurrentKey(ctx, s, testCoord(t))
	require.NoError(t, rerr)
	require.NotNil(t, ck, "the record must survive a transient FM failure")
}

func TestCoordinate_AdoptsExistingKeyInsteadOfCreating(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	// a key the plugin did not create, e.g. one the team made by hand
	existing, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)

	resp := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, existing.SdkKey, resp.Data["sdk_key"], "must adopt the existing key")
	require.Len(t, fake.Created, 1, "no second key may be created")
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
}

func TestCoordinate_SeparateInstancesConvergeOnOneKey(t *testing.T) {
	fake := fmclienttest.New()
	b1, s1 := testBackendWith(t, fake)
	b2, s2 := testBackendWith(t, fake)
	for _, inst := range []struct {
		b *backend
		s logical.Storage
	}{{b1, s1}, {b2, s2}} {
		writeConfig(t, inst.b, inst.s)
		writeDefaultRole(t, inst.b, inst.s)
	}

	k1 := readCoordinate(t, b1, s1, testCoordPath).Data["sdk_key"]
	k2 := readCoordinate(t, b2, s2, testCoordPath).Data["sdk_key"]

	require.Equal(t, k1, k2, "the second instance must adopt the first instance's key")
	require.Len(t, fake.Created, 1, "one key per coordinate no matter how many instances")
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
}

func TestCoordinate_DoesNotAdoptAnotherKeyType(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	web, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeWeb)
	require.NoError(t, err)

	resp := readCoordinate(t, b, s, testCoordPath) // a server coordinate
	require.NotEqual(t, web.SdkKey, resp.Data["sdk_key"])
	require.Equal(t, 2, fake.ActiveCount("checkout", "production"))
}

func TestCoordinate_StorageLossReadoptsRatherThanRecreating(t *testing.T) {
	fake := fmclienttest.New()
	b1, s1 := testBackendWith(t, fake)
	writeConfig(t, b1, s1)
	writeDefaultRole(t, b1, s1)
	first := readCoordinate(t, b1, s1, testCoordPath).Data["sdk_key"]

	// a rebuilt Vault cluster: same FM service, empty local storage
	b2, s2 := testBackendWith(t, fake)
	writeConfig(t, b2, s2)
	writeDefaultRole(t, b2, s2)

	require.Equal(t, first, readCoordinate(t, b2, s2, testCoordPath).Data["sdk_key"])
	require.Len(t, fake.Created, 1, "storage loss must not orphan the old key")
}

func TestCoordinate_AdoptsTheNewestOfSeveralKeys(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	var newest string
	for i := 0; i < 4; i++ {
		d, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
		require.NoError(t, err)
		newest = d.SdkKey
	}

	resp := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, newest, resp.Data["sdk_key"], "the newest key must win, not an arbitrary one")
	require.Equal(t, 4, fake.ActiveCount("checkout", "production"), "adoption creates nothing")
}

// Manual rotation the intended way: create the replacement, later delete the old key, reconcile.
func TestCoordinate_ManualRotationViaCreateThenDelete(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	old := readCoordinate(t, b, s, testCoordPath).Data["sdk_key"].(string)

	// 1. operator mints the replacement; both keys now live
	replacement, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)
	require.Equal(t, old, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"],
		"an instance holding a record keeps serving it")

	// a cold instance joining during the overlap must pick the survivor, not the doomed key
	cold, coldStore := testBackendWith(t, fake)
	writeConfig(t, cold, coldStore)
	writeDefaultRole(t, cold, coldStore)
	require.Equal(t, replacement.SdkKey, readCoordinate(t, cold, coldStore, testCoordPath).Data["sdk_key"],
		"newest-wins is what makes a joining instance skip the key about to be deleted")

	// 2. operator deletes the old key
	fake.Drop("checkout", "production", old)

	// the original instance is now serving a key that no longer exists
	require.Equal(t, old, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"],
		"reads are served from the record, so a deleted key is still handed out")

	// 3. reconcile clears the now-absent record
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, replacement.SdkKey, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"])
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
}

func TestReconcile_RepointsToTheNewestKeyWithoutDeleting(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	old := readCoordinate(t, b, s, testCoordPath).Data["sdk_key"].(string)
	replacement, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)
	require.NotEqual(t, old, replacement.SdkKey)

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.NoError(t, err)
	require.Empty(t, resp.Data["cleared_stale_current"])
	require.Len(t, resp.Data["updated_to_newest"], 1)

	require.Equal(t, replacement.SdkKey, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"])
	require.Equal(t, 2, fake.ActiveCount("checkout", "production"),
		"make-before-break: the old key is still valid for the operator to delete later")
}

func TestReconciliationLoop_RunsOncePerInterval(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)
	readCoordinate(t, b, s, testCoordPath)

	replacement, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)

	// newBackend schedules the first pass ahead, so this tick must do nothing
	require.NoError(t, b.periodicFunc(ctx, &logical.Request{Storage: s}))
	require.NotEqual(t, replacement.SdkKey, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"])

	b.nextReconcile = time.Time{}
	require.NoError(t, b.periodicFunc(ctx, &logical.Request{Storage: s}))
	require.Equal(t, replacement.SdkKey, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"],
		"the loop is what moves a running instance onto a rotated key")
	require.True(t, b.nextReconcile.After(time.Now()), "the loop must reschedule itself")
}

func TestReconciliationLoop_IdleMountNeedsNoConfig(t *testing.T) {
	b, _, s := testBackend(t)
	b.nextReconcile = time.Time{}
	// no config and no records, so a pass must not try to build an FM client
	require.NoError(t, b.periodicFunc(context.Background(), &logical.Request{Storage: s}))
}

func TestNextReconcileAt_IsJittered(t *testing.T) {
	seen := map[time.Time]bool{}
	for i := 0; i < 20; i++ {
		at := nextReconcileAt(defaultReconcileInterval)
		// the default 6h interval must land in 4h-8h
		require.True(t, at.After(time.Now().Add(defaultReconcileInterval*2/3-time.Minute)))
		require.True(t, at.Before(time.Now().Add(defaultReconcileInterval*4/3+time.Minute)))
		seen[at] = true
	}
	require.Greater(t, len(seen), 1, "instances must not run in lockstep")
}

func TestReconcileInterval_ConfigurableWithDefaultAndFloor(t *testing.T) {
	b, _, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)

	read := func() int64 {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation, Path: "config", Storage: s,
		})
		require.NoError(t, err)
		return resp.Data["reconcile_interval"].(int64)
	}
	require.EqualValues(t, defaultReconcileInterval.Seconds(), read(), "unset means the default")

	set := func(v interface{}) *logical.Response {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.UpdateOperation, Path: "config", Storage: s,
			Data: map[string]interface{}{"reconcile_interval": v},
		})
		require.NoError(t, err)
		return resp
	}

	require.False(t, set("30m").IsError())
	require.EqualValues(t, 1800, read())

	require.True(t, set("10s").IsError(), "a floor stops hundreds of instances polling FM")
	require.EqualValues(t, 1800, read(), "a rejected write must not change the stored value")

	require.False(t, set(0).IsError(), "0 turns the loop off")
	require.EqualValues(t, 0, read(), "read echoes the write convention")
}

func TestReconciliationLoop_DisabledByConfig(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)
	readCoordinate(t, b, s, testCoordPath)

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "config", Storage: s,
		Data: map[string]interface{}{"reconcile_interval": 0},
	})
	require.NoError(t, err)

	replacement, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)

	b.nextReconcile = time.Time{}
	require.NoError(t, b.periodicFunc(ctx, &logical.Request{Storage: s}))
	require.NotEqual(t, replacement.SdkKey, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"],
		"a disabled loop must not re-point")

	// the path still works when the loop is off
	_, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
	})
	require.NoError(t, err)
	require.Equal(t, replacement.SdkKey, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"])
}

// An instance that loses a cold-start race must adopt rather than create its own key.
func TestProvision_RecheckAdoptsAKeyThatAppearsDuringTheJitter(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	createJitter = 20 * time.Millisecond
	t.Cleanup(func() { createJitter = 0 })

	// another instance wins the race between our first list and our re-check
	var racer string
	lists := 0
	fake.BeforeList = func() {
		lists++
		if lists == 1 {
			d, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
			require.NoError(t, err)
			racer = d.SdkKey
		}
	}

	resp := readCoordinate(t, b, s, testCoordPath)
	require.Equal(t, racer, resp.Data["sdk_key"], "must adopt the racer's key")
	require.Len(t, fake.Created, 1, "the loser must not create a second key")
	require.Equal(t, 1, fake.ActiveCount("checkout", "production"))
}

func TestProvision_CreatesWhenTheRecheckIsStillEmpty(t *testing.T) {
	b, fake, s := testBackend(t)
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)

	createJitter = 20 * time.Millisecond
	t.Cleanup(func() { createJitter = 0 })

	resp := readCoordinate(t, b, s, testCoordPath)
	require.NotEmpty(t, resp.Data["sdk_key"])
	require.Len(t, fake.Created, 1, "an uncontended coordinate still gets exactly one key")
}
