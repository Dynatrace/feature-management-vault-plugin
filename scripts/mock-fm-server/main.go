// Command mock-fm-server is a tiny stand-in for the Feature Management Service,
// the Dynatrace IDM API, and the Dynatrace SSO token endpoint, for local
// end-to-end testing of the plugin without real credentials. It is NOT for
// production use.
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
//	  idm_base_url=http://127.0.0.1:8899/idm \
//	  client_template_id=mock-template \
//	  client_id_prefix=dt0s00000001. \
//	  client_id=mock client_secret=mock dt_tenant=tenantxxx
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient/fmclienttest"
)

const apiBase = "/public/feature-management-service/v0.1"

func main() {
	addr := flag.String("addr", "127.0.0.1:8899", "listen address")
	flag.Parse()

	store := fmclienttest.New()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /sso/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// IDM: create working client from template.
	mux.HandleFunc("POST /idm/v1/oauth2-client-template/{templateId}/client",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				writeErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			var body struct {
				ClientID string `json:"clientId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeErr(w, http.StatusBadRequest, "invalid body")
				return
			}
			writeJSON(w, http.StatusCreated, map[string]string{
				"clientId":     body.ClientID,
				"clientSecret": "mock-working-client-secret",
			})
		})

	// IDM: delete working client.
	mux.HandleFunc("DELETE /idm/v1/oauth2-client/{clientId}/owner",
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				writeErr(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

	mux.HandleFunc("POST "+apiBase+"/projects/{project}/release-stages/{stage}/sdk-keys",
		func(w http.ResponseWriter, r *http.Request) {
			if !authOK(w, r) {
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
			if !authOK(w, r) {
				return
			}
			list, err := store.ListSdkKeys(r.Context(), r.PathValue("project"), r.PathValue("stage"))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, list)
		})

	mux.HandleFunc("DELETE "+apiBase+"/projects/{project}/release-stages/{stage}/sdk-keys/{sdkkey}",
		func(w http.ResponseWriter, r *http.Request) {
			if !authOK(w, r) {
				return
			}
			err := store.DeleteSdkKey(r.Context(), r.PathValue("project"), r.PathValue("stage"), r.PathValue("sdkkey"))
			if fmclient.IsNotFound(err) {
				writeErr(w, http.StatusNotFound, "not found")
				return
			}
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

	log.Printf("mock FM service listening on http://%s (base %s)", *addr, apiBase)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// authOK enforces the same headers the real API requires.
func authOK(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") == "" {
		writeErr(w, http.StatusUnauthorized, "missing bearer token")
		return false
	}
	if r.Header.Get("Dt-Tenant") == "" {
		writeErr(w, http.StatusBadRequest, "missing Dt-Tenant header")
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
