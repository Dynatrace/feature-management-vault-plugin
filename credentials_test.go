package featuremanagement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeVault emulates the subset of the Vault API the AppRole resolver uses:
// an AppRole login, a KV read, and revoke-self. It records requests so tests
// can assert on the flow.
type fakeVault struct {
	roleID        string
	secretID      string
	token         string
	kvPath        string // API path (without the /v1 prefix), e.g. "secret/data/dynatrace/fm"
	kvPayload     map[string]interface{}
	loginStatus   int    // override the login response status; 0 => 200
	wantNamespace string // assert X-Vault-Namespace header when set
	revokedCalls  int32
}

func (f *fakeVault) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		if f.loginStatus != 0 {
			http.Error(w, `{"errors":["permission denied"]}`, f.loginStatus)
			return
		}
		if f.wantNamespace != "" {
			require.Equal(t, f.wantNamespace, r.Header.Get("X-Vault-Namespace"))
		}
		var body struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, f.roleID, body.RoleID)
		require.Equal(t, f.secretID, body.SecretID)
		writeJSON(w, map[string]interface{}{
			"auth": map[string]interface{}{"client_token": f.token},
		})
	})
	mux.HandleFunc("/v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&f.revokedCalls, 1)
		require.Equal(t, f.token, r.Header.Get("X-Vault-Token"))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/"+f.kvPath, func(w http.ResponseWriter, r *http.Request) {
		if f.wantNamespace != "" {
			require.Equal(t, f.wantNamespace, r.Header.Get("X-Vault-Namespace"))
		}
		require.Equal(t, f.token, r.Header.Get("X-Vault-Token"))
		writeJSON(w, map[string]interface{}{"data": f.kvPayload})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestResolveAppRoleCredentials_KVv2(t *testing.T) {
	fv := &fakeVault{
		roleID:   "role-123",
		secretID: "secret-456",
		token:    "s.login-token",
		kvPath:   "secret/data/dynatrace/fm",
		// KV v2 nests fields under "data".
		kvPayload: map[string]interface{}{
			"data": map[string]interface{}{
				"client_id":     "resolved-id",
				"client_secret": "resolved-secret",
			},
			"metadata": map[string]interface{}{"version": 1},
		},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/data/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL,
	}
	id, secret, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "resolved-id", id)
	require.Equal(t, "resolved-secret", secret)
	require.EqualValues(t, 1, atomic.LoadInt32(&fv.revokedCalls), "login token should be revoked")
}

func TestResolveAppRoleCredentials_KVv1(t *testing.T) {
	fv := &fakeVault{
		roleID:   "role-123",
		secretID: "secret-456",
		token:    "s.login-token",
		kvPath:   "secret/dynatrace/fm",
		// KV v1 stores fields at the top level.
		kvPayload: map[string]interface{}{
			"client_id":     "v1-id",
			"client_secret": "v1-secret",
		},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		KVVersion:             1,
		VaultAddr:             srv.URL,
	}
	id, secret, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "v1-id", id)
	require.Equal(t, "v1-secret", secret)
}

func TestResolveAppRoleCredentials_CustomFieldNames(t *testing.T) {
	fv := &fakeVault{
		roleID:   "role-123",
		secretID: "secret-456",
		token:    "s.login-token",
		kvPath:   "secret/data/dynatrace/fm",
		kvPayload: map[string]interface{}{
			"data": map[string]interface{}{
				"oauth_id":  "custom-id",
				"oauth_key": "custom-secret",
			},
		},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/data/dynatrace/fm",
		ClientIDField:         "oauth_id",
		ClientSecretField:     "oauth_key",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL,
	}
	id, secret, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "custom-id", id)
	require.Equal(t, "custom-secret", secret)
}

func TestResolveAppRoleCredentials_LoginFailure(t *testing.T) {
	fv := &fakeVault{
		roleID:      "role-123",
		secretID:    "secret-456",
		kvPath:      "secret/data/dynatrace/fm",
		loginStatus: http.StatusForbidden,
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/data/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL,
	}
	_, _, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "approle login")
}

func TestResolveAppRoleCredentials_MissingField(t *testing.T) {
	fv := &fakeVault{
		roleID:   "role-123",
		secretID: "secret-456",
		token:    "s.login-token",
		kvPath:   "secret/data/dynatrace/fm",
		kvPayload: map[string]interface{}{
			"data": map[string]interface{}{"client_id": "only-id"},
		},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/data/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL,
	}
	_, _, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "client_secret")
}

func TestResolveAppRoleCredentials_WrongKVVersionForPayload(t *testing.T) {
	// KV v1 payload (flat) read with kv_version defaulting to 2 => no data envelope.
	fv := &fakeVault{
		roleID:    "role-123",
		secretID:  "secret-456",
		token:     "s.login-token",
		kvPath:    "secret/dynatrace/fm",
		kvPayload: map[string]interface{}{"client_id": "id", "client_secret": "secret"},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL, // kv_version unset => defaults to 2
	}
	_, _, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "kv_version")
}

func TestResolveAppRoleCredentials_Namespace(t *testing.T) {
	fv := &fakeVault{
		roleID:        "role-123",
		secretID:      "secret-456",
		token:         "s.login-token",
		kvPath:        "secret/data/dynatrace/fm",
		wantNamespace: "admin/teamA",
		kvPayload: map[string]interface{}{
			"data": map[string]interface{}{
				"client_id":     "ns-id",
				"client_secret": "ns-secret",
			},
		},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/data/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL,
		VaultNamespace:        "admin/teamA",
	}
	id, secret, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "ns-id", id)
	require.Equal(t, "ns-secret", secret)
}

func TestResolveAppRoleCredentials_TLSSkipVerify(t *testing.T) {
	// Serve over plain HTTP but with skip_verify set — the flag must not prevent
	// the connection (here it just confirms the flag is wired through without
	// causing a build-time panic or config error).
	fv := &fakeVault{
		roleID:   "role-123",
		secretID: "secret-456",
		token:    "s.login-token",
		kvPath:   "secret/data/dynatrace/fm",
		kvPayload: map[string]interface{}{
			"data": map[string]interface{}{
				"client_id":     "tls-id",
				"client_secret": "tls-secret",
			},
		},
	}
	srv := fv.server(t)

	cfg := &fmConfig{
		ClientCredentialsPath: "secret/data/dynatrace/fm",
		AuthRoleID:            "role-123",
		AuthSecretID:          "secret-456",
		VaultAddr:             srv.URL,
		VaultTLSSkipVerify:    true,
	}
	id, secret, err := resolveAppRoleCredentials(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "tls-id", id)
	require.Equal(t, "tls-secret", secret)
}

func TestStringField(t *testing.T) {
	data := map[string]interface{}{"ok": "value", "num": 42, "empty": ""}

	v, err := stringField(data, "ok")
	require.NoError(t, err)
	require.Equal(t, "value", v)

	_, err = stringField(data, "missing")
	require.ErrorContains(t, err, "not found")

	_, err = stringField(data, "num")
	require.ErrorContains(t, err, "not a string")

	_, err = stringField(data, "empty")
	require.ErrorContains(t, err, "empty")
}
