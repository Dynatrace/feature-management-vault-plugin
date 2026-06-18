package fmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FMClient is the subset of the Feature Management Service API the Vault plugin
// uses. Keeping it as an interface lets the backend swap in a fake for tests and
// lets the HTTP implementation be extracted into a shared SDK later.
type FMClient interface {
	// CreateSdkKey mints a new SDK key for the given project/release-stage/type.
	CreateSdkKey(ctx context.Context, project, releaseStage string, keyType SdkKeyType) (*SDKKeyDetails, error)
	// ListSdkKeys returns the active keys for a release stage, grouped by type.
	ListSdkKeys(ctx context.Context, project, releaseStage string) (*SDKKeyList, error)
	// DeleteSdkKey deletes an SDK key. A 404 is reported as ErrNotFound so the
	// caller can treat an already-gone key as success.
	DeleteSdkKey(ctx context.Context, project, releaseStage, sdkKey string) error
}

// DefaultScopes are the OAuth scopes requested for SDK-key management.
var DefaultScopes = []string{
	"feature-management:sdk-keys:read",
	"feature-management:sdk-keys:write",
	"feature-management:sdk-keys:delete",
}

const defaultHTTPTimeout = 30 * time.Second

// Config configures an HTTP-backed FMClient.
type Config struct {
	// BaseURL is the FM service base, including the API path prefix, e.g.
	// https://host/public/feature-management-service/v0.1
	BaseURL string
	// TokenURL is the Dynatrace SSO OAuth2 client-credentials token endpoint.
	TokenURL     string
	ClientID     string
	ClientSecret string
	// Tenant is sent as the required `Dt-Tenant` header on every request.
	Tenant string
	// Scopes overrides DefaultScopes when non-empty.
	Scopes      []string
	HTTPTimeout time.Duration
}

// Client is the HTTP implementation of FMClient.
type Client struct {
	cfg    Config
	http   *http.Client
	tokens *tokenCache
}

var _ FMClient = (*Client)(nil)

// New builds an HTTP-backed FMClient from cfg.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("fmclient: base URL is required")
	}
	if cfg.TokenURL == "" {
		return nil, fmt.Errorf("fmclient: token URL is required")
	}
	if cfg.Tenant == "" {
		return nil, fmt.Errorf("fmclient: tenant is required")
	}
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	hc := &http.Client{Timeout: timeout}
	return &Client{
		cfg:  cfg,
		http: hc,
		tokens: &tokenCache{
			httpClient:   hc,
			tokenURL:     cfg.TokenURL,
			clientID:     cfg.ClientID,
			clientSecret: cfg.ClientSecret,
			scopes:       scopes,
		},
	}, nil
}

func (c *Client) sdkKeysURL(project, releaseStage string) string {
	return fmt.Sprintf("%s/projects/%s/release-stages/%s/sdk-keys",
		strings.TrimRight(c.cfg.BaseURL, "/"),
		url.PathEscape(project), url.PathEscape(releaseStage))
}

// CreateSdkKey implements FMClient.
func (c *Client) CreateSdkKey(ctx context.Context, project, releaseStage string, keyType SdkKeyType) (*SDKKeyDetails, error) {
	body, err := json.Marshal(SdkKeyCreate{Type: keyType})
	if err != nil {
		return nil, err
	}
	var out SDKKeyDetails
	if err := c.do(ctx, http.MethodPost, c.sdkKeysURL(project, releaseStage), body, http.StatusCreated, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListSdkKeys implements FMClient.
func (c *Client) ListSdkKeys(ctx context.Context, project, releaseStage string) (*SDKKeyList, error) {
	var out SDKKeyList
	if err := c.do(ctx, http.MethodGet, c.sdkKeysURL(project, releaseStage), nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSdkKey implements FMClient.
func (c *Client) DeleteSdkKey(ctx context.Context, project, releaseStage, sdkKey string) error {
	u := c.sdkKeysURL(project, releaseStage) + "/" + url.PathEscape(sdkKey)
	return c.do(ctx, http.MethodDelete, u, nil, http.StatusNoContent, nil)
}

// do performs an authenticated request and decodes a successful response into
// out (if non-nil). It retries once on a 401 after refreshing the token.
func (c *Client) do(ctx context.Context, method, urlStr string, body []byte, wantStatus int, out interface{}) error {
	const maxAttempts = 2
	for attempt := 0; attempt < maxAttempts; attempt++ {
		token, err := c.tokens.bearer(ctx)
		if err != nil {
			return fmt.Errorf("fmclient: obtain token: %w", err)
		}

		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, urlStr, rdr)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Dt-Tenant", c.cfg.Tenant)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("fmclient: %s %s: %w", method, redactURL(urlStr), err)
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized && attempt < maxAttempts-1 {
			c.tokens.invalidate()
			continue
		}
		if resp.StatusCode != wantStatus {
			return parseAPIError(resp.StatusCode, respBody)
		}
		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("fmclient: decode response: %w", err)
			}
		}
		return nil
	}
	return fmt.Errorf("fmclient: unauthorized after token refresh")
}

// redactURL strips the (secret) sdk-key path segment so URLs are safe to log.
func redactURL(u string) string {
	const marker = "/sdk-keys/"
	if i := strings.Index(u, marker); i >= 0 {
		return u[:i+len(marker)] + "<redacted>"
	}
	return u
}
