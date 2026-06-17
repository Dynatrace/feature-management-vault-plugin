// Package fmclient is a small client for the Dynatrace Feature Management
// Service SDK-keys API. It is intentionally narrow (create/list/delete SDK
// keys) so it can be mocked in tests and later extracted into a standalone,
// reusable Go SDK module.
//
// Contract source: Feature Management API OpenAPI v0.1.45
// (/public/feature-management-service/v0.1).
package fmclient

import (
	"strings"
	"time"
)

// SdkKeyType is the type of an SDK key. Mirrors the FM API `SdkKeyType` enum.
type SdkKeyType string

const (
	SdkKeyTypeWeb    SdkKeyType = "web"
	SdkKeyTypeServer SdkKeyType = "server"
	SdkKeyTypeMobile SdkKeyType = "mobile"
)

// Valid reports whether t is one of the known SDK key types.
func (t SdkKeyType) Valid() bool {
	switch t {
	case SdkKeyTypeWeb, SdkKeyTypeServer, SdkKeyTypeMobile:
		return true
	default:
		return false
	}
}

// SdkKeyCreate is the request body for createSdkKey.
type SdkKeyCreate struct {
	Type SdkKeyType `json:"type"`
}

// ModificationInfo mirrors the FM API `ModificationInfo` schema.
type ModificationInfo struct {
	CreatedBy        string    `json:"createdBy"`
	CreatedTime      time.Time `json:"createdTime"`
	LastModifiedBy   string    `json:"lastModifiedBy"`
	LastModifiedTime time.Time `json:"lastModifiedTime"`
}

// SDKKeyDetails mirrors the FM API `SDKKeyDetails` schema.
type SDKKeyDetails struct {
	// SdkKey is the full SDK key. Its third dot-delimited segment is secret;
	// use PublicPrefix for anything that may be logged.
	SdkKey           string            `json:"sdkKey"`
	Type             SdkKeyType        `json:"type"`
	ModificationInfo *ModificationInfo `json:"modificationInfo,omitempty"`
	// Version is the optimistic-locking version (FM `OptimisticLockingVersion`).
	Version int `json:"version,omitempty"`
}

// SDKKeyList mirrors the FM API `SDKKeyList` schema: active keys grouped by type.
type SDKKeyList struct {
	Web    []SDKKeyDetails `json:"web"`
	Mobile []SDKKeyDetails `json:"mobile"`
	Server []SDKKeyDetails `json:"server"`
}

// OfType returns the list entries for the given key type.
func (l SDKKeyList) OfType(t SdkKeyType) []SDKKeyDetails {
	switch t {
	case SdkKeyTypeWeb:
		return l.Web
	case SdkKeyTypeMobile:
		return l.Mobile
	case SdkKeyTypeServer:
		return l.Server
	default:
		return nil
	}
}

// PublicPrefix returns the log-safe portion of an SDK key: the first two
// dot-delimited segments (`{token}.{platform}_{geo}_{publicRandom}`). The third
// segment (`{secret}_{sha1}`) is private and must never appear in logs,
// telemetry, or support bundles. If the key is malformed, a redaction
// placeholder is returned so a secret can never leak through this function.
func PublicPrefix(sdkKey string) string {
	parts := strings.SplitN(sdkKey, ".", 3)
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
		return "<redacted-sdk-key>"
	}
	return parts[0] + "." + parts[1]
}
