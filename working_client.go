package featuremanagement

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

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageWorkingClient              = "working_client"
	defaultWorkingClientRotationHours = 23
)

type workingClientRecord struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	CreatedAt    time.Time `json:"created_at"`
}

func (c *fmConfig) workingClientRotationHoursOrDefault() int {
	if c.WorkingClientRotationHours <= 0 {
		return defaultWorkingClientRotationHours
	}
	return c.WorkingClientRotationHours
}

func (c *fmConfig) workingClientRotationPeriod() time.Duration {
	return time.Duration(c.workingClientRotationHoursOrDefault()) * time.Hour
}

// defaultResolveWorkingCreds reads the cached working client from storage,
// creating a new one via the IDM API if it is missing or past its rotation period.
// Make-before-break: the new client is stored before the old one is deleted.
func (b *backend) defaultResolveWorkingCreds(
	ctx context.Context,
	s logical.Storage,
	cfg *fmConfig,
	superID, superSecret string,
) (string, string, error) {
	wc, err := getJSON[workingClientRecord](ctx, s, storageWorkingClient)
	if err != nil {
		return "", "", fmt.Errorf("read working client: %w", err)
	}
	if wc != nil && time.Since(wc.CreatedAt) < cfg.workingClientRotationPeriod() {
		return wc.ClientID, wc.ClientSecret, nil
	}

	token, err := idmGetToken(ctx, cfg.TokenURL, superID, superSecret)
	if err != nil {
		return "", "", fmt.Errorf("obtain IDM token: %w", err)
	}

	suffix, err := uuid.GenerateUUID()
	if err != nil {
		return "", "", err
	}
	newClientID := cfg.ClientIDPrefix + suffix[:8]

	newClient, err := idmCreateClient(ctx, cfg.IDMBaseURL, cfg.ClientTemplateID, newClientID, token)
	if err != nil {
		return "", "", fmt.Errorf("create working client: %w", err)
	}

	newRecord := &workingClientRecord{
		ClientID:     newClient.ClientID,
		ClientSecret: newClient.ClientSecret,
		CreatedAt:    time.Now().UTC(),
	}
	if err := putJSON(ctx, s, storageWorkingClient, newRecord); err != nil {
		return "", "", fmt.Errorf("store working client: %w", err)
	}

	// Delete the previous working client after storing the new one (make-before-break).
	if wc != nil && wc.ClientID != "" {
		if delErr := idmDeleteClient(ctx, cfg.IDMBaseURL, wc.ClientID, token); delErr != nil {
			b.Logger().Warn("failed to delete expired working client (IDM leak risk)",
				"client_id", wc.ClientID, "error", delErr)
		}
	}

	return newRecord.ClientID, newRecord.ClientSecret, nil
}

// rotateWorkingClientIfDue is called from periodicFunc to proactively rotate
// the working client when its rotation window has elapsed.
func (b *backend) rotateWorkingClientIfDue(ctx context.Context, s logical.Storage) {
	wc, err := getJSON[workingClientRecord](ctx, s, storageWorkingClient)
	if err != nil || wc == nil {
		return
	}
	cfg, err := b.readConfig(ctx, s)
	if err != nil || cfg == nil {
		return
	}
	if time.Since(wc.CreatedAt) < cfg.workingClientRotationPeriod() {
		return
	}
	b.resetClient()
	if _, err := b.getClient(ctx, s); err != nil {
		b.Logger().Warn("proactive working client rotation failed", "error", err)
	}
}

type idmClientDetails struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}

// idmGetToken obtains a bearer token from the SSO token endpoint using the
// super-client's client_credentials grant.
func idmGetToken(ctx context.Context, tokenURL, clientID, clientSecret string) (string, error) {
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %s: HTTP %d: %s", tokenURL, resp.StatusCode, raw)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}
	return tok.AccessToken, nil
}

// idmCreateClient calls createClientFromClientTemplate on the IDM API.
func idmCreateClient(ctx context.Context, idmBaseURL, templateID, clientID, bearerToken string) (*idmClientDetails, error) {
	endpoint := fmt.Sprintf("%s/v1/oauth2-client-template/%s/client", idmBaseURL, templateID)
	payload, _ := json.Marshal(map[string]string{"clientId": clientID})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IDM create client (template %s): HTTP %d: %s", templateID, resp.StatusCode, raw)
	}
	var details idmClientDetails
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil, fmt.Errorf("decode IDM create response: %w", err)
	}
	return &details, nil
}

// idmDeleteClient calls deleteOAuth2Client on the IDM API; 404 is treated as success.
func idmDeleteClient(ctx context.Context, idmBaseURL, clientID, bearerToken string) error {
	endpoint := fmt.Sprintf("%s/v1/oauth2-client/%s/owner", idmBaseURL, clientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("IDM delete client %s: HTTP %d: %s", clientID, resp.StatusCode, raw)
}
