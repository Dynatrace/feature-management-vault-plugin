package fmclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrNotFound is returned when the FM API responds 404. Callers deleting a key
// should treat not-found as success (the key is already gone — e.g. FM rotated
// it out-of-band), making deletes idempotent.
var ErrNotFound = errors.New("fmclient: resource not found")

// IsNotFound reports whether err represents a 404 from the FM API.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// ErrorEnvelope mirrors the FM API `ErrorEnvelope` schema.
type ErrorEnvelope struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Details *ErrorDetails `json:"details,omitempty"`
}

// ErrorDetails mirrors the FM API `ErrorDetails` schema.
type ErrorDetails struct {
	TraceID              string                `json:"traceId,omitempty"`
	ConstraintViolations []ConstraintViolation `json:"constraintViolations,omitempty"`
	MissingScopes        []string              `json:"missingScopes,omitempty"`
}

// ConstraintViolation mirrors the FM API `ConstraintViolation` schema.
type ConstraintViolation struct {
	Path    string `json:"path,omitempty"`
	Message string `json:"message,omitempty"`
}

// APIError represents a non-2xx response from the FM API.
type APIError struct {
	StatusCode int
	Envelope   *ErrorEnvelope
	Body       string
}

func (e *APIError) Error() string {
	if e.Envelope != nil && e.Envelope.Message != "" {
		msg := fmt.Sprintf("fmclient: FM API error: status=%d code=%d message=%q",
			e.StatusCode, e.Envelope.Code, e.Envelope.Message)
		if e.Envelope.Details != nil && len(e.Envelope.Details.MissingScopes) > 0 {
			msg += fmt.Sprintf(" missing_scopes=%v", e.Envelope.Details.MissingScopes)
		}
		return msg
	}
	return fmt.Sprintf("fmclient: FM API error: status=%d body=%q", e.StatusCode, truncate(e.Body, 256))
}

// parseAPIError builds an error from a non-2xx response.
func parseAPIError(status int, body []byte) error {
	if status == http.StatusNotFound {
		return ErrNotFound
	}
	apiErr := &APIError{StatusCode: status, Body: string(body)}
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && (env.Message != "" || env.Code != 0) {
		apiErr.Envelope = &env
	}
	return apiErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
