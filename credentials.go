package featuremanagement

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

// Defaults for the sourced-credentials (Vault KV) configuration fields.
const (
	// defaultAuthMount is the conventional mount path of the AppRole auth method.
	defaultAuthMount = "approle"
	// defaultKVVersion is the KV secrets-engine version assumed for
	// client_credentials_path when unset (KV v2 is the modern default).
	defaultKVVersion = 2
	// defaultClientIDField / defaultClientSecretField are the KV field names the
	// OAuth client id/secret are read from when not overridden.
	defaultClientIDField     = "client_id"
	defaultClientSecretField = "client_secret"
)

// resolveAppRoleCredentials logs in to Vault with the configured AppRole and
// reads the OAuth client_id/client_secret from the KV secret at
// cfg.ClientCredentialsPath. It is the production implementation behind
// backend.resolveCreds; tests stub that field so this never dials Vault.
//
// The Vault address and TLS settings come from the plugin's environment
// (VAULT_ADDR / VAULT_CACERT / VAULT_CAPATH / VAULT_SKIP_VERIFY), overridable
// per-mount via cfg.VaultAddr. The short-lived token minted by the login is
// revoked before returning so it does not linger in Vault.
func resolveAppRoleCredentials(ctx context.Context, cfg *fmConfig) (clientID, clientSecret string, err error) {
	client, err := newVaultAPIClient(cfg)
	if err != nil {
		return "", "", err
	}

	token, err := appRoleLogin(ctx, client, cfg)
	if err != nil {
		return "", "", err
	}
	client.SetToken(token)
	// Best-effort cleanup: the resolved credentials are all we need, so the
	// login token should not outlive this call.
	defer func() {
		_, _ = client.Logical().WriteWithContext(ctx, "auth/token/revoke-self", nil)
	}()

	data, err := readCredentialSecret(ctx, client, cfg)
	if err != nil {
		return "", "", err
	}

	idField := cfg.clientIDFieldOrDefault()
	secretField := cfg.clientSecretFieldOrDefault()
	clientID, err = stringField(data, idField)
	if err != nil {
		return "", "", err
	}
	clientSecret, err = stringField(data, secretField)
	if err != nil {
		return "", "", err
	}
	return clientID, clientSecret, nil
}

// newVaultAPIClient builds a Vault API client for the sourced-credentials
// Vault installation. The base config comes from the plugin environment
// (VAULT_ADDR, VAULT_CACERT, VAULT_SKIP_VERIFY); per-mount overrides in cfg
// take precedence, enabling connections to a remote Vault with its own TLS CA
// or enterprise namespace.
func newVaultAPIClient(cfg *fmConfig) (*api.Client, error) {
	apiCfg := api.DefaultConfig()
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("build vault api config: %w", apiCfg.Error)
	}
	if cfg.VaultAddr != "" {
		apiCfg.Address = cfg.VaultAddr
	}

	// Apply per-mount TLS overrides so a remote Vault with a privately-signed
	// certificate works without touching the plugin process's environment.
	tlsCfg := &api.TLSConfig{}
	if cfg.VaultCACert != "" {
		tlsCfg.CACertBytes = []byte(cfg.VaultCACert)
	}
	if cfg.VaultTLSSkipVerify {
		tlsCfg.Insecure = true
	}
	if err := apiCfg.ConfigureTLS(tlsCfg); err != nil {
		return nil, fmt.Errorf("configure vault tls: %w", err)
	}

	client, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}
	// Ensure no ambient token (e.g. VAULT_TOKEN) is used; the AppRole login
	// governs access to the credentials path.
	client.SetToken("")
	if cfg.VaultNamespace != "" {
		client.SetNamespace(cfg.VaultNamespace)
	}
	return client, nil
}

// appRoleLogin performs a role_id/secret_id login against the configured
// AppRole mount and returns the resulting client token.
func appRoleLogin(ctx context.Context, client *api.Client, cfg *fmConfig) (string, error) {
	mount := strings.Trim(cfg.authMountOrDefault(), "/")
	loginPath := fmt.Sprintf("auth/%s/login", mount)
	secret, err := client.Logical().WriteWithContext(ctx, loginPath, map[string]interface{}{
		"role_id":   cfg.AuthRoleID,
		"secret_id": cfg.AuthSecretID,
	})
	if err != nil {
		return "", fmt.Errorf("approle login at %q: %w", loginPath, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("approle login at %q returned no client token", loginPath)
	}
	return secret.Auth.ClientToken, nil
}

// readCredentialSecret reads cfg.ClientCredentialsPath and returns the field map
// holding the credentials, unwrapping the KV v2 "data" envelope when applicable.
func readCredentialSecret(ctx context.Context, client *api.Client, cfg *fmConfig) (map[string]interface{}, error) {
	secret, err := client.Logical().ReadWithContext(ctx, cfg.ClientCredentialsPath)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", cfg.ClientCredentialsPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret found at %q", cfg.ClientCredentialsPath)
	}

	if cfg.kvVersionOrDefault() == 2 {
		// KV v2 nests the user-supplied fields under a top-level "data" key
		// (alongside "metadata"). A missing envelope usually means kv_version
		// is wrong for the path.
		inner, ok := secret.Data["data"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("secret at %q has no KV v2 data payload; check kv_version", cfg.ClientCredentialsPath)
		}
		return inner, nil
	}
	return secret.Data, nil
}

// stringField extracts a non-empty string field from a KV secret's data map.
func stringField(data map[string]interface{}, field string) (string, error) {
	raw, ok := data[field]
	if !ok {
		return "", fmt.Errorf("field %q not found in sourced credentials secret", field)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("field %q in sourced credentials secret is not a string", field)
	}
	if s == "" {
		return "", fmt.Errorf("field %q in sourced credentials secret is empty", field)
	}
	return s, nil
}
