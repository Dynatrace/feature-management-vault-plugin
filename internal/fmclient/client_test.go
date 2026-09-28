package fmclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient/fmclienttest"
)

const testAPIBase = "/public/feature-management-service/v0.1"

// newTestServerAndClient spins up an httptest server backed by a fake and a
// client pointed at it.
func newTestServerAndClient(t *testing.T) (*httptest.Server, *fmclient.Client, *seenHeaders) {
	t.Helper()
	store := fmclienttest.New()
	seen := &seenHeaders{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		seen.grantType = r.Form.Get("grant_type")
		seen.scope = r.Form.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("POST "+testAPIBase+"/projects/{p}/release-stages/{s}/sdk-keys", func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		var body fmclient.SdkKeyCreate
		_ = json.NewDecoder(r.Body).Decode(&body)
		d, err := store.CreateSdkKey(r.Context(), r.PathValue("p"), r.PathValue("s"), body.Type)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("GET "+testAPIBase+"/projects/{p}/release-stages/{s}/sdk-keys", func(w http.ResponseWriter, r *http.Request) {
		seen.record(r)
		l, _ := store.ListSdkKeys(r.Context(), r.PathValue("p"), r.PathValue("s"))
		_ = json.NewEncoder(w).Encode(l)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := fmclient.New(fmclient.Config{
		BaseURL:      srv.URL + testAPIBase,
		TokenURL:     srv.URL + "/token",
		ClientID:     "id",
		ClientSecret: "secret",
		Tenant:       "tenant1234",
	})
	require.NoError(t, err)
	return srv, c, seen
}

type seenHeaders struct {
	auth      string
	tenant    string
	grantType string
	scope     string
}

func (s *seenHeaders) record(r *http.Request) {
	s.auth = r.Header.Get("Authorization")
	s.tenant = r.Header.Get("Dt-Tenant")
}

func writeEnvelope(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(fmclient.ErrorEnvelope{Code: status, Message: msg})
}

func TestClient_CreateAndList(t *testing.T) {
	ctx := context.Background()
	_, c, seen := newTestServerAndClient(t)

	details, err := c.CreateSdkKey(ctx, "checkout", "production", fmclient.SdkKeyTypeServer)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(details.SdkKey, "dt01.server_"), "got %q", details.SdkKey)
	require.Equal(t, fmclient.SdkKeyTypeServer, details.Type)

	// Auth + tenant headers and OAuth grant type were sent.
	require.Equal(t, "Bearer tok", seen.auth)
	require.Equal(t, "tenant1234", seen.tenant)
	require.Equal(t, "client_credentials", seen.grantType)
	require.Contains(t, seen.scope, "feature-management:sdk-keys:write")

	list, err := c.ListSdkKeys(ctx, "checkout", "production")
	require.NoError(t, err)
	require.Len(t, list.Server, 1)
	require.Equal(t, details.SdkKey, list.Server[0].SdkKey)
}

func TestClient_APIError(t *testing.T) {
	_, c, _ := newTestServerAndClient(t)
	// Invalid type triggers the fake's create error -> 400 with envelope.
	_, err := c.CreateSdkKey(context.Background(), "checkout", "production", fmclient.SdkKeyType("bogus"))
	require.Error(t, err)
	var apiErr *fmclient.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	require.NotNil(t, apiErr.Envelope)
}

func TestPublicPrefix(t *testing.T) {
	full := "dt01.server_us_ab3xy9kp2q.03ee0ef7cd4244bfb8b71fea8f783f53_d4f8a9c12a"
	require.Equal(t, "dt01.server_us_ab3xy9kp2q", fmclient.PublicPrefix(full))
	require.Equal(t, "<redacted-sdk-key>", fmclient.PublicPrefix("nope"))
}
