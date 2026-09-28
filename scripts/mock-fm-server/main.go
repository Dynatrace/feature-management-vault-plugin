// Command mock-fm-server is a tiny stand-in for the Feature Management Service
// and the Dynatrace SSO token endpoint, for local end-to-end testing of the
// plugin without real credentials. It is NOT for production use.
//
// Example:
//
//	go run ./scripts/mock-fm-server -addr 127.0.0.1:8899
//
// Then configure the plugin:
//
//	vault write feature-management/config \
//	  fm_base_url=http://127.0.0.1:8899/public/feature-management-service/v0.1 \
//	  token_url=http://127.0.0.1:8899/sso/oauth2/token \
//	  client_id=mock client_secret=mock dt_tenant=tenantxxx
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient/fmclienttest"
)

const apiBase = "/public/feature-management-service/v0.1"

const (
	scopeRead  = "feature-management:sdk-keys:read"
	scopeWrite = "feature-management:sdk-keys:write"
)

// grantableScopes are the only scopes this mock issues; SSO rejects the rest.
var grantableScopes = map[string]bool{scopeRead: true, scopeWrite: true}

func main() {
	addr := flag.String("addr", "127.0.0.1:8899", "listen address")
	flag.Parse()

	store := fmclienttest.New()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /sso/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		granted := strings.Fields(r.FormValue("scope"))
		for _, sc := range granted {
			if !grantableScopes[sc] {
				writeErr(w, http.StatusBadRequest, "invalid_scope: "+sc)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": mockToken(granted),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        strings.Join(granted, " "),
		})
	})

	mux.HandleFunc("POST "+apiBase+"/projects/{project}/release-stages/{stage}/sdk-keys",
		func(w http.ResponseWriter, r *http.Request) {
			if !authOK(w, r, scopeWrite) {
				return
			}
			var body fmclient.SdkKeyCreate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, http.StatusBadRequest, "invalid body")
				return
			}
			details, err := store.CreateSdkKey(r.Context(), r.PathValue("project"), r.PathValue("stage"), body.Type)
			if err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, details)
		})

	mux.HandleFunc("GET "+apiBase+"/projects/{project}/release-stages/{stage}/sdk-keys",
		func(w http.ResponseWriter, r *http.Request) {
			if !authOK(w, r, scopeRead) {
				return
			}
			list, err := store.ListSdkKeys(r.Context(), r.PathValue("project"), r.PathValue("stage"))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, list)
		})

	log.Printf("mock FM service listening on http://%s (base %s)", *addr, apiBase)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// mockToken encodes the granted scopes in the token so the API routes can check them.
func mockToken(scopes []string) string { return "mock-access-token." + strings.Join(scopes, ",") }

// tokenScopes reads the scopes back out of an Authorization header.
func tokenScopes(authHeader string) []string {
	_, scopes, _ := strings.Cut(strings.TrimPrefix(authHeader, "Bearer "), ".")
	return strings.Split(scopes, ",")
}

// authOK enforces the headers and the scope the real API requires.
func authOK(w http.ResponseWriter, r *http.Request, required string) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return false
	}
	if r.Header.Get("Dt-Tenant") == "" {
		writeErr(w, http.StatusBadRequest, "missing Dt-Tenant header")
		return false
	}
	if !slices.Contains(tokenScopes(auth), required) {
		writeScopeErr(w, required)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, fmclient.ErrorEnvelope{Code: status, Message: msg})
}

// writeScopeErr mirrors the real 403, which names the missing scopes in the envelope.
func writeScopeErr(w http.ResponseWriter, scope string) {
	writeJSON(w, http.StatusForbidden, fmclient.ErrorEnvelope{
		Code:    http.StatusForbidden,
		Message: "insufficient scope",
		Details: &fmclient.ErrorDetails{MissingScopes: []string{scope}},
	})
}
