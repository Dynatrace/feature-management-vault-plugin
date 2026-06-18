package fmclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tokenRefreshSkew is how long before expiry a cached token is considered stale,
// so a token never dies mid-request.
const tokenRefreshSkew = 60 * time.Second

// fallbackTokenTTL is used if the token endpoint omits expires_in.
const fallbackTokenTTL = 5 * time.Minute

// tokenResponse is the OAuth2 token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// tokenCache caches a client-credentials bearer token and refreshes it shortly
// before expiry. It has its own mutex so an in-flight OAuth round trip never
// blocks unrelated SDK-key calls beyond the token fetch itself.
type tokenCache struct {
	httpClient   *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string

	mu       sync.Mutex
	token    string
	expireAt time.Time
}

// bearer returns a valid bearer token, refreshing if necessary.
func (tc *tokenCache) bearer(ctx context.Context) (string, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.token != "" && time.Now().Before(tc.expireAt.Add(-tokenRefreshSkew)) {
		return tc.token, nil
	}
	tok, ttl, err := tc.fetch(ctx)
	if err != nil {
		return "", err
	}
	tc.token = tok
	tc.expireAt = time.Now().Add(ttl)
	return tc.token, nil
}

// invalidate clears the cached token, forcing a refresh on the next call. Used
// after a 401, which can happen if the token was revoked server-side early.
func (tc *tokenCache) invalidate() {
	tc.mu.Lock()
	tc.token = ""
	tc.expireAt = time.Time{}
	tc.mu.Unlock()
}

func (tc *tokenCache) fetch(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", tc.clientID)
	form.Set("client_secret", tc.clientSecret)
	if len(tc.scopes) > 0 {
		form.Set("scope", strings.Join(tc.scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tc.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("fmclient: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := tc.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("fmclient: token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		// Note: do not include client_secret; only the status and a truncated body.
		return "", 0, fmt.Errorf("fmclient: token endpoint status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("fmclient: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("fmclient: token endpoint returned empty access_token")
	}

	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = fallbackTokenTTL
	}
	return tr.AccessToken, ttl, nil
}
