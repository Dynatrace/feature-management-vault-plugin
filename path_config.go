package featuremanagement

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// tenantPattern matches the FM API Dt-Tenant header (8-10 alphanumerics).
var tenantPattern = regexp.MustCompile(`^[a-zA-Z0-9]{8,10}$`)

// fmConfig is the stored mount configuration. A single mount serves one tenant.
//
// The OAuth client credentials come from one of two sources, and a mount can be
// swapped between them at any time by writing the fields of the desired source:
//   - inline: ClientID and ClientSecret are stored directly on the mount; or
//   - sourced: ClientCredentialsPath points at a KV secret in the same Vault,
//     and the plugin reads ClientID/ClientSecret from it at client-build time
//     after logging in via AppRole. In sourced mode the OAuth secret never lives
//     in this config — access is governed entirely by the AppRole's policy.
//
// The two sources never coexist in storage: a write that sets
// ClientCredentialsPath selects sourced mode (and takes precedence over inline
// fields in the same request), while a write that sets ClientID/ClientSecret
// without a path selects inline mode. The losing source's fields are cleared.
type fmConfig struct {
	FMBaseURL          string   `json:"fm_base_url"`
	TokenURL           string   `json:"token_url"`
	ClientID           string   `json:"client_id"`
	ClientSecret       string   `json:"client_secret"`
	Tenant             string   `json:"dt_tenant"`
	Scopes             []string `json:"scopes,omitempty"`
	HTTPTimeoutSeconds int      `json:"http_timeout_seconds,omitempty"`

	// Sourced-credentials fields (empty in inline mode).
	ClientCredentialsPath string `json:"client_credentials_path,omitempty"`
	ClientIDField         string `json:"client_id_field,omitempty"`
	ClientSecretField     string `json:"client_secret_field,omitempty"`
	KVVersion             int    `json:"kv_version,omitempty"`
	VaultAddr             string `json:"vault_addr,omitempty"`
	AuthMount             string `json:"auth_mount,omitempty"`
	AuthRoleID            string `json:"auth_role_id,omitempty"`
	AuthSecretID          string `json:"auth_secret_id,omitempty"`
}

// usesSourcedCredentials reports whether the OAuth client credentials are read
// from a separate Vault KV path rather than stored inline.
func (c *fmConfig) usesSourcedCredentials() bool {
	return c.ClientCredentialsPath != ""
}

// clearSourcedCredentials drops every sourced-mode (Vault KV / AppRole) field so
// the mount reverts cleanly to inline credentials. Clearing ClientCredentialsPath
// makes usesSourcedCredentials report false; the remaining fields are wiped to
// avoid leaving stale, confusing values (notably the AppRole secret_id) behind.
func (c *fmConfig) clearSourcedCredentials() {
	c.ClientCredentialsPath = ""
	c.ClientIDField = ""
	c.ClientSecretField = ""
	c.KVVersion = 0
	c.VaultAddr = ""
	c.AuthMount = ""
	c.AuthRoleID = ""
	c.AuthSecretID = ""
}

func (c *fmConfig) kvVersionOrDefault() int {
	if c.KVVersion == 0 {
		return defaultKVVersion
	}
	return c.KVVersion
}

func (c *fmConfig) authMountOrDefault() string {
	if c.AuthMount == "" {
		return defaultAuthMount
	}
	return c.AuthMount
}

func (c *fmConfig) clientIDFieldOrDefault() string {
	if c.ClientIDField == "" {
		return defaultClientIDField
	}
	return c.ClientIDField
}

func (c *fmConfig) clientSecretFieldOrDefault() string {
	if c.ClientSecretField == "" {
		return defaultClientSecretField
	}
	return c.ClientSecretField
}

func (c *fmConfig) toClientConfig() fmclient.Config {
	return fmclient.Config{
		BaseURL:      c.FMBaseURL,
		TokenURL:     c.TokenURL,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Tenant:       c.Tenant,
		Scopes:       c.Scopes,
		HTTPTimeout:  time.Duration(c.HTTPTimeoutSeconds) * time.Second,
	}
}

func (c *fmConfig) scopesOrDefault() []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return fmclient.DefaultScopes
}

func (b *backend) readConfig(ctx context.Context, s logical.Storage) (*fmConfig, error) {
	return getJSON[fmConfig](ctx, s, storageConfig)
}

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "feature-management",
			OperationSuffix: "config",
		},
		Fields: map[string]*framework.FieldSchema{
			"fm_base_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the Feature Management Service, including the API path prefix (e.g. https://host/public/feature-management-service/v0.1).",
				Required:    true,
			},
			"token_url": {
				Type:        framework.TypeString,
				Description: "Dynatrace SSO OAuth2 client-credentials token endpoint.",
				Required:    true,
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "OAuth client ID the plugin authenticates with. Required unless client_credentials_path is set.",
			},
			"client_secret": {
				Type:         framework.TypeString,
				Description:  "OAuth client secret. Write-only; never returned on read. Required unless client_credentials_path is set.",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			"client_credentials_path": {
				Type: framework.TypeString,
				Description: "Vault path of a KV secret holding the OAuth client_id/client_secret, read at " +
					"client-build time instead of storing them inline. For KV v2 use the raw API path including " +
					"/data/ (e.g. secret/data/dynatrace/fm); for KV v1 omit it (e.g. secret/dynatrace/fm). Setting " +
					"this selects sourced mode and requires the AppRole auth_* fields; it takes precedence over and " +
					"clears any client_id/client_secret. Clear it (and set client_id/client_secret) to switch back " +
					"to inline mode.",
			},
			"client_id_field": {
				Type:        framework.TypeString,
				Description: "Field name within the sourced KV secret holding the client id.",
				Default:     defaultClientIDField,
			},
			"client_secret_field": {
				Type:        framework.TypeString,
				Description: "Field name within the sourced KV secret holding the client secret.",
				Default:     defaultClientSecretField,
			},
			"kv_version": {
				Type:        framework.TypeInt,
				Description: "KV secrets-engine version of client_credentials_path (1 or 2).",
				Default:     defaultKVVersion,
			},
			"vault_addr": {
				Type: framework.TypeString,
				Description: "Vault API address the plugin calls to read client_credentials_path. Defaults to the " +
					"VAULT_ADDR in the plugin's environment. TLS is configured via the standard VAULT_CACERT / " +
					"VAULT_CAPATH / VAULT_SKIP_VERIFY environment variables.",
			},
			"auth_mount": {
				Type:        framework.TypeString,
				Description: "Mount path of the AppRole auth method used to read client_credentials_path.",
				Default:     defaultAuthMount,
			},
			"auth_role_id": {
				Type:        framework.TypeString,
				Description: "AppRole role_id used to authenticate to Vault when reading client_credentials_path.",
			},
			"auth_secret_id": {
				Type:         framework.TypeString,
				Description:  "AppRole secret_id. Write-only; never returned on read.",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			"dt_tenant": {
				Type:        framework.TypeString,
				Description: "Dynatrace tenant id sent as the required Dt-Tenant header (8-10 alphanumerics).",
				Required:    true,
			},
			"scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "OAuth scopes to request. Defaults to the three feature-management:sdk-keys scopes.",
			},
			"http_timeout_seconds": {
				Type:        framework.TypeInt,
				Description: "HTTP timeout for FM API calls, in seconds.",
				Default:     30,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.configExistenceCheck,
		HelpSynopsis:    "Configure the FM service connection and OAuth client.",
		HelpDescription: "Stores the FM service base URL, the OAuth client credentials and token endpoint, and the tenant id. Writing this path resets the cached FM client.",
	}
}

func (b *backend) configExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &fmConfig{}
	}

	if v, ok := d.GetOk("fm_base_url"); ok {
		cfg.FMBaseURL = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("token_url"); ok {
		cfg.TokenURL = strings.TrimSpace(v.(string))
	}
	_, gotID := d.GetOk("client_id")
	_, gotSecret := d.GetOk("client_secret")
	if v, ok := d.GetOk("client_id"); ok {
		cfg.ClientID = v.(string)
	}
	if v, ok := d.GetOk("client_secret"); ok {
		cfg.ClientSecret = v.(string)
	}
	if v, ok := d.GetOk("dt_tenant"); ok {
		cfg.Tenant = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("scopes"); ok {
		cfg.Scopes = v.([]string)
	}
	if v, ok := d.GetOk("http_timeout_seconds"); ok {
		cfg.HTTPTimeoutSeconds = v.(int)
	}
	_, gotCredsPath := d.GetOk("client_credentials_path")
	if v, ok := d.GetOk("client_credentials_path"); ok {
		cfg.ClientCredentialsPath = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("client_id_field"); ok {
		cfg.ClientIDField = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("client_secret_field"); ok {
		cfg.ClientSecretField = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("kv_version"); ok {
		cfg.KVVersion = v.(int)
	}
	if v, ok := d.GetOk("vault_addr"); ok {
		cfg.VaultAddr = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("auth_mount"); ok {
		cfg.AuthMount = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("auth_role_id"); ok {
		cfg.AuthRoleID = strings.TrimSpace(v.(string))
	}
	if v, ok := d.GetOk("auth_secret_id"); ok {
		cfg.AuthSecretID = v.(string)
	}

	// Resolve the credentials mode from what this request supplies, so a mount can
	// be freely swapped between inline and sourced credentials without erroring
	// and without the previous mode's fields lingering in storage. A request that
	// supplies client_credentials_path selects sourced mode and takes precedence;
	// otherwise supplying client_id/client_secret selects inline mode. Either way
	// the losing mode's fields are wiped so no stale secret is left behind.
	var credSwapWarning string
	gotInlineCreds := gotID || gotSecret
	switch {
	case gotCredsPath:
		// Sourced mode: drop any inline credentials so no stale OAuth secret
		// lingers. If the same request also carried inline creds, they lose to the
		// KV path; warn rather than error so a swap never fails.
		if gotInlineCreds {
			credSwapWarning = "client_id/client_secret were ignored and cleared because client_credentials_path " +
				"selects sourced credentials"
		}
		cfg.ClientID = ""
		cfg.ClientSecret = ""
	case gotInlineCreds:
		// Inline mode: drop the sourced configuration so the mount stops resolving
		// credentials from Vault KV.
		cfg.clearSourcedCredentials()
	}

	var missing []string
	if cfg.FMBaseURL == "" {
		missing = append(missing, "fm_base_url")
	}
	if cfg.TokenURL == "" {
		missing = append(missing, "token_url")
	}
	if cfg.Tenant == "" {
		missing = append(missing, "dt_tenant")
	}
	if cfg.usesSourcedCredentials() {
		if cfg.AuthRoleID == "" {
			missing = append(missing, "auth_role_id")
		}
		if cfg.AuthSecretID == "" {
			missing = append(missing, "auth_secret_id")
		}
		if ver := cfg.kvVersionOrDefault(); ver != 1 && ver != 2 {
			return logical.ErrorResponse("invalid kv_version %d: must be 1 or 2", ver), nil
		}
	} else {
		if cfg.ClientID == "" {
			missing = append(missing, "client_id")
		}
		if cfg.ClientSecret == "" {
			missing = append(missing, "client_secret")
		}
	}
	if len(missing) > 0 {
		return logical.ErrorResponse("missing required config fields: %s", strings.Join(missing, ", ")), nil
	}
	if !tenantPattern.MatchString(cfg.Tenant) {
		return logical.ErrorResponse("invalid dt_tenant %q: must be 8-10 alphanumeric characters", cfg.Tenant), nil
	}

	if err := putJSON(ctx, req.Storage, storageConfig, cfg); err != nil {
		return nil, err
	}

	// Invalidate isn't guaranteed to fire on the writing node in all topologies,
	// so drop the cached client here too.
	b.resetClient()

	// Flag the common foot-gun of a deployed mount still pointing at a local
	// test/mock FM service (e.g. config copied from the demo), plus any
	// credentials-mode swap that discarded conflicting fields.
	var resp *logical.Response
	addWarning := func(msg string) {
		if resp == nil {
			resp = &logical.Response{}
		}
		resp.AddWarning(msg)
	}
	if loopback := loopbackURLs(cfg.FMBaseURL, cfg.TokenURL); len(loopback) > 0 {
		addWarning("config points at a loopback address (" + strings.Join(loopback, ", ") +
			"); this only reaches a local/mock FM service and will fail on a deployed Vault")
	}
	if credSwapWarning != "" {
		addWarning(credSwapWarning)
	}
	return resp, nil
}

// loopbackURLs returns the labelled URLs among the given config URLs whose host
// is a loopback address (localhost / 127.0.0.0/8 / ::1).
func loopbackURLs(fmBaseURL, tokenURL string) []string {
	var out []string
	for _, u := range []struct{ label, raw string }{
		{"fm_base_url", fmBaseURL},
		{"token_url", tokenURL},
	} {
		if isLoopbackURL(u.raw) {
			out = append(out, u.label)
		}
	}
	return out
}

func isLoopbackURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	data := map[string]interface{}{
		"fm_base_url":          cfg.FMBaseURL,
		"token_url":            cfg.TokenURL,
		"dt_tenant":            cfg.Tenant,
		"scopes":               cfg.scopesOrDefault(),
		"http_timeout_seconds": cfg.HTTPTimeoutSeconds,
		// client_secret and auth_secret_id are intentionally never returned.
	}
	if cfg.usesSourcedCredentials() {
		data["credentials_source"] = "vault_kv"
		data["client_credentials_path"] = cfg.ClientCredentialsPath
		data["client_id_field"] = cfg.clientIDFieldOrDefault()
		data["client_secret_field"] = cfg.clientSecretFieldOrDefault()
		data["kv_version"] = cfg.kvVersionOrDefault()
		data["vault_addr"] = cfg.VaultAddr
		data["auth_mount"] = cfg.authMountOrDefault()
		data["auth_role_id"] = cfg.AuthRoleID
	} else {
		data["credentials_source"] = "inline"
		data["client_id"] = cfg.ClientID
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, storageConfig); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}
