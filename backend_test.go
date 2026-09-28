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

func TestCoordinate_NoMatchingRole(t *testing.T) {
	b, _, s := testBackend(t)
	writeConfig(t, b, s)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: testCoordPath, Storage: s,
	})
	require.NoError(t, err)
	require.True(t, resp.IsError())
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

func TestReconciliationLoop_RunsOncePerInterval(t *testing.T) {
	b, fake, s := testBackend(t)
	ctx := context.Background()
	writeConfig(t, b, s)
	writeDefaultRole(t, b, s)
	readCoordinate(t, b, s, testCoordPath)

	replacement, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)

	// with a pass scheduled ahead, this tick must do nothing
	b.nextReconcile = time.Now().Add(time.Hour)
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

	require.True(t, b.nextReconcile.IsZero(),
		"a config write must re-arm the loop so a changed interval takes effect promptly")
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

func TestCoordinate_ReadAdoptsOrProvisions(t *testing.T) {
	web, server := fmclient.SdkKeyTypeWeb, fmclient.SdkKeyTypeServer
	for _, tc := range []struct {
		name       string
		seed       []fmclient.SdkKeyType
		wantCreate bool
	}{
		{"FM is empty, so one is created", nil, true},
		{"FM holds a key, so it is adopted", []fmclient.SdkKeyType{server}, false},
		{"FM holds several, so the newest is adopted", []fmclient.SdkKeyType{server, server, server}, false},
		{"FM holds only another type, so one is created", []fmclient.SdkKeyType{web}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, fake, s := testBackend(t)
			ctx := context.Background()
			writeConfig(t, b, s)
			writeDefaultRole(t, b, s)

			var newestServer string
			for _, typ := range tc.seed {
				d, err := fake.CreateSdkKey(ctx, "checkout", "production", typ)
				require.NoError(t, err)
				if typ == server {
					newestServer = d.SdkKey
				}
			}
			seeded := len(fake.Created)

			resp := readCoordinate(t, b, s, testCoordPath)
			got := resp.Data["sdk_key"].(string)
			require.Nil(t, resp.Secret, "the key is static, so no lease is issued")

			if tc.wantCreate {
				require.Len(t, fake.Created, seeded+1)
				require.NotEqual(t, newestServer, got)
			} else {
				require.Len(t, fake.Created, seeded, "adoption must create nothing")
				require.Equal(t, newestServer, got)
			}

			afterFirst := len(fake.Created)
			require.Equal(t, got, readCoordinate(t, b, s, testCoordPath).Data["sdk_key"],
				"a second read is served from the record")
			require.Len(t, fake.Created, afterFirst, "and never touches FM")
		})
	}
}

// Separate Vault instances share no storage, so FM is the only thing stopping each from minting
// its own key. This also covers a rebuilt instance that lost its storage.
func TestCoordinate_SeparateInstancesShareOneKey(t *testing.T) {
	fake := fmclienttest.New()
	first, firstStore := testBackendWith(t, fake)
	writeConfig(t, first, firstStore)
	writeDefaultRole(t, first, firstStore)
	key := readCoordinate(t, first, firstStore, testCoordPath).Data["sdk_key"]

	second, secondStore := testBackendWith(t, fake)
	writeConfig(t, second, secondStore)
	writeDefaultRole(t, second, secondStore)

	require.Equal(t, key, readCoordinate(t, second, secondStore, testCoordPath).Data["sdk_key"])
	require.Len(t, fake.Created, 1, "one key per coordinate no matter how many instances")
}

func TestReconcile_Outcomes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		arrange     func(t *testing.T, ctx context.Context, fake *fmclienttest.Fake, current string) string
		wantCleared int
		wantUpdated int
		wantActive  int
	}{
		{
			name:       "the record is already the newest key, so nothing changes",
			arrange:    func(_ *testing.T, _ context.Context, _ *fmclienttest.Fake, current string) string { return current },
			wantActive: 1,
		},
		{
			name: "a newer key exists, so the record moves onto it and the old key survives",
			arrange: func(t *testing.T, ctx context.Context, fake *fmclienttest.Fake, _ string) string {
				d, err := fake.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
				require.NoError(t, err)
				return d.SdkKey
			},
			wantUpdated: 1,
			wantActive:  2,
		},
		{
			name: "FM no longer has the key, so the record is cleared",
			arrange: func(_ *testing.T, _ context.Context, fake *fmclienttest.Fake, current string) string {
				fake.Drop("checkout", "production", current)
				return ""
			},
			wantCleared: 1,
		},
		{
			name: "FM 404s the project, so the record is cleared",
			arrange: func(_ *testing.T, _ context.Context, fake *fmclienttest.Fake, _ string) string {
				fake.ListErr = fmclient.ErrNotFound
				return ""
			},
			wantCleared: 1,
			wantActive:  1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, fake, s := testBackend(t)
			ctx := context.Background()
			writeConfig(t, b, s)
			writeDefaultRole(t, b, s)
			current := readCoordinate(t, b, s, testCoordPath).Data["sdk_key"].(string)

			want := tc.arrange(t, ctx, fake, current)

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation, Path: "reconcile", Storage: s,
			})
			require.NoError(t, err)
			require.False(t, resp.IsError())
			require.Len(t, resp.Data["cleared_stale_current"], tc.wantCleared)
			require.Len(t, resp.Data["updated_to_newest"], tc.wantUpdated)
			require.Equal(t, tc.wantActive, fake.ActiveCount("checkout", "production"),
				"reconcile never deletes in FM")

			ck, err := b.readCurrentKey(ctx, s, testCoord(t))
			require.NoError(t, err)
			if want == "" {
				require.Nil(t, ck, "a stale record must be cleared so the next read provisions")
			} else {
				require.NotNil(t, ck)
				require.Equal(t, want, ck.FullSDKKey)
			}
		})
	}
}

// The convergence rule must be total and must not depend on optional response fields, or separate
// instances could pick different winners from the same list.
func TestPickKey_IsDeterministic(t *testing.T) {
	at := func(sec int) *fmclient.ModificationInfo {
		return &fmclient.ModificationInfo{CreatedTime: time.Unix(int64(sec), 0).UTC()}
	}
	key := func(prefix string) string { return "dt01.server_us_" + prefix + ".abc_def" }

	list := &fmclient.SDKKeyList{Server: []fmclient.SDKKeyDetails{
		{SdkKey: key("bbbbbbbbbb"), ModificationInfo: at(100)},
		{SdkKey: key("cccccccccc"), ModificationInfo: at(300)},
		{SdkKey: key("aaaaaaaaaa"), ModificationInfo: at(200)},
	}}
	got := pickKey(list, fmclient.SdkKeyTypeServer)
	require.NotNil(t, got)
	require.Equal(t, key("cccccccccc"), got.SdkKey, "newest wins regardless of list order")

	// equal timestamps fall back to the public prefix rather than list order
	tied := &fmclient.SDKKeyList{Server: []fmclient.SDKKeyDetails{
		{SdkKey: key("zzzzzzzzzz"), ModificationInfo: at(100)},
		{SdkKey: key("aaaaaaaaaa"), ModificationInfo: at(100)},
	}}
	require.Equal(t, key("aaaaaaaaaa"), pickKey(tied, fmclient.SdkKeyTypeServer).SdkKey)

	// FM may omit modificationInfo; the ordering must still be total
	missing := &fmclient.SDKKeyList{Server: []fmclient.SDKKeyDetails{
		{SdkKey: key("aaaaaaaaaa")},
		{SdkKey: key("bbbbbbbbbb"), ModificationInfo: at(100)},
	}}
	require.Equal(t, key("bbbbbbbbbb"), pickKey(missing, fmclient.SdkKeyTypeServer).SdkKey,
		"a key with a known time beats one with none")

	require.Nil(t, pickKey(&fmclient.SDKKeyList{}, fmclient.SdkKeyTypeServer))
	require.Nil(t, pickKey(nil, fmclient.SdkKeyTypeServer))
}
