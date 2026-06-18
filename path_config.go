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
type fmConfig struct {
	FMBaseURL          string   `json:"fm_base_url"`
	TokenURL           string   `json:"token_url"`
	ClientID           string   `json:"client_id"`
	ClientSecret       string   `json:"client_secret"`
	Tenant             string   `json:"dt_tenant"`
	Scopes             []string `json:"scopes,omitempty"`
	HTTPTimeoutSeconds int      `json:"http_timeout_seconds,omitempty"`
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
				Description: "OAuth client ID the plugin authenticates with.",
				Required:    true,
			},
			"client_secret": {
				Type:         framework.TypeString,
				Description:  "OAuth client secret. Write-only; never returned on read.",
				Required:     true,
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

	var missing []string
	if cfg.FMBaseURL == "" {
		missing = append(missing, "fm_base_url")
	}
	if cfg.TokenURL == "" {
		missing = append(missing, "token_url")
	}
	if cfg.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if cfg.Tenant == "" {
		missing = append(missing, "dt_tenant")
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
	// test/mock FM service (e.g. config copied from the demo).
	var resp *logical.Response
	if loopback := loopbackURLs(cfg.FMBaseURL, cfg.TokenURL); len(loopback) > 0 {
		resp = &logical.Response{}
		resp.AddWarning("config points at a loopback address (" + strings.Join(loopback, ", ") +
			"); this only reaches a local/mock FM service and will fail on a deployed Vault")
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
	return &logical.Response{
		Data: map[string]interface{}{
			"fm_base_url":          cfg.FMBaseURL,
			"token_url":            cfg.TokenURL,
			"client_id":            cfg.ClientID,
			"dt_tenant":            cfg.Tenant,
			"scopes":               cfg.scopesOrDefault(),
			"http_timeout_seconds": cfg.HTTPTimeoutSeconds,
			// client_secret is intentionally never returned.
		},
	}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, storageConfig); err != nil {
		return nil, err
	}
	b.resetClient()
	return nil, nil
}
