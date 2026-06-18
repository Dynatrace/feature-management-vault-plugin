package featuremanagement

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// coordinateFields is the shared field schema for the coordinate read and
// rotate paths.
var coordinateFields = map[string]*framework.FieldSchema{
	"version": {
		Type:        framework.TypeString,
		Description: "SDK key format version segment (dtNN), e.g. dt01.",
		Required:    true,
	},
	"release_stage": {
		Type:        framework.TypeString,
		Description: "Release-stage key.",
		Required:    true,
	},
	"project": {
		Type:        framework.TypeString,
		Description: "Project key.",
		Required:    true,
	},
	"type": {
		Type:        framework.TypeString,
		Description: "SDK key type: web, server, or mobile.",
		Required:    true,
	},
}

// coordinatePathSuffix is the trailing coordinate pattern shared by the read and
// rotate paths. The type segment is constrained to the enum.
const coordinatePathSuffix = "(?P<version>[^/]+)/(?P<release_stage>[^/]+)/(?P<project>[^/]+)/(?P<type>web|server|mobile)$"

// currentKey is the plugin's record of the active key for a coordinate. The
// full key is retained so revoke can build the deleteSdkKey path; only the
// public prefix may be logged.
type currentKey struct {
	Version         string    `json:"version"`
	ReleaseStage    string    `json:"release_stage"`
	Project         string    `json:"project"`
	Type            string    `json:"type"`
	FullSDKKey      string    `json:"full_sdk_key"`
	PublicPrefix    string    `json:"public_prefix"`
	UpstreamVersion int       `json:"upstream_version"`
	CreatedAt       time.Time `json:"created_at"`
	LastRotatedAt   time.Time `json:"last_rotated_at,omitempty"`
}

// currentStorageKey is flat (hex-encoded) so the coordinate's slashes don't
// create storage "folders" — Vault's List is hierarchical, so a slash-bearing
// key would not be enumerable by listCurrentKeys.
func currentStorageKey(coord coordinate) string {
	return storageCurrentPrefix + hex.EncodeToString([]byte(coord.String()))
}

// coordinate reconstructs the coordinate this record belongs to.
func (ck *currentKey) coordinate() coordinate {
	return coordinate{
		Version:      ck.Version,
		ReleaseStage: ck.ReleaseStage,
		Project:      ck.Project,
		Type:         fmclient.SdkKeyType(ck.Type),
	}
}

func (b *backend) readCurrentKey(ctx context.Context, s logical.Storage, coord coordinate) (*currentKey, error) {
	return getJSON[currentKey](ctx, s, currentStorageKey(coord))
}

func (b *backend) writeCurrentKey(ctx context.Context, s logical.Storage, ck *currentKey) error {
	return putJSON(ctx, s, currentStorageKey(ck.coordinate()), ck)
}

// clearCurrentIfMatches removes the current-key record for coord iff it still
// points at fullKey. It takes the coordinate lock, so callers must not already
// hold it.
func (b *backend) clearCurrentIfMatches(ctx context.Context, s logical.Storage, coord coordinate, fullKey string) error {
	lock := b.lockCoordinate(coord)
	lock.Lock()
	defer lock.Unlock()

	ck, err := b.readCurrentKey(ctx, s, coord)
	if err != nil || ck == nil {
		return err
	}
	if ck.FullSDKKey != fullKey {
		return nil
	}
	return s.Delete(ctx, currentStorageKey(coord))
}

func (b *backend) sdkKeySecret() *framework.Secret {
	return &framework.Secret{
		Type: secretTypeSDKKey,
		Fields: map[string]*framework.FieldSchema{
			"sdk_key": {
				Type:        framework.TypeString,
				Description: "The full SDK key.",
			},
			"public_prefix": {
				Type:        framework.TypeString,
				Description: "Log-safe public prefix of the SDK key.",
			},
		},
		Renew:  b.secretRenew,
		Revoke: b.secretRevoke,
	}
}

func (b *backend) pathCoordinateRead() *framework.Path {
	return &framework.Path{
		Pattern: coordinatePathSuffix,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "feature-management",
			OperationVerb:   "read",
			OperationSuffix: "sdk-key",
		},
		Fields: coordinateFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathCoordinateReadOp},
		},
		HelpSynopsis:    "Read (and lazily mint) the current SDK key for a coordinate, issuing a lease.",
		HelpDescription: "Returns the current SDK key for <version>/<release-stage>/<project>/<type>, minting one via the FM service if none exists. The key is wrapped in a Vault lease; when the lease expires or is revoked the key is deleted in the FM service.",
	}
}

// coordinateFromRequest parses and validates the coordinate from the request
// path and resolves its policy role. On a client error it returns a non-nil
// *logical.Response (a 4xx) that the caller must return unchanged.
func (b *backend) coordinateFromRequest(ctx context.Context, req *logical.Request, d *framework.FieldData) (coordinate, *roleEntry, *logical.Response) {
	coord, err := parseCoordinate(
		d.Get("version").(string),
		d.Get("release_stage").(string),
		d.Get("project").(string),
		d.Get("type").(string),
	)
	if err != nil {
		return coordinate{}, nil, logical.ErrorResponse(err.Error())
	}
	role, err := b.resolveRole(ctx, req.Storage, coord)
	if err != nil {
		return coordinate{}, nil, logical.ErrorResponse(err.Error())
	}
	return coord, role, nil
}

func (b *backend) pathCoordinateReadOp(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	coord, role, errResp := b.coordinateFromRequest(ctx, req, d)
	if errResp != nil {
		return errResp, nil
	}

	lock := b.lockCoordinate(coord)
	lock.Lock()
	defer lock.Unlock()

	ck, err := b.readCurrentKey(ctx, req.Storage, coord)
	if err != nil {
		return nil, err
	}
	var warning string
	if ck == nil {
		ck, warning, err = b.mintAndStore(ctx, req.Storage, coord, false)
		if err != nil {
			b.Logger().Error("failed to mint SDK key", "coordinate", coord.String(), "error", err)
			return nil, fmt.Errorf("mint SDK key for %s failed (verify the FM service URL/credentials in %q): %w", coord, storageConfig, err)
		}
	}

	resp := b.Secret(secretTypeSDKKey).Response(
		map[string]interface{}{
			"sdk_key":       ck.FullSDKKey,
			"public_prefix": ck.PublicPrefix,
		},
		map[string]interface{}{
			"full_sdk_key":  ck.FullSDKKey,
			"public_prefix": ck.PublicPrefix,
			"project":       ck.Project,
			"release_stage": ck.ReleaseStage,
			"type":          ck.Type,
			"version":       ck.Version,
			"coordinate":    coord.String(),
		},
	)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	if warning != "" {
		resp.AddWarning(warning)
	}
	return resp, nil
}

// secretRenew extends the lease only. It deliberately does NOT rotate: FM has no
// rotate endpoint, renewals are frequent/automatic, and coupling rotation to
// renewal would churn upstream CDN config. Rotation stays explicit on the rotate
// path.
func (b *backend) secretRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}
	if coordStr, ok := req.Secret.InternalData["coordinate"].(string); ok {
		if coord, err := parseCoordinateString(coordStr); err == nil {
			if role, err := b.resolveRole(ctx, req.Storage, coord); err == nil {
				resp.Secret.TTL = role.TTL
				resp.Secret.MaxTTL = role.MaxTTL
			}
		}
	}
	return resp, nil
}

// secretRevoke deletes the SDK key in the FM service. A failed delete leaves an
// orphaned active key (the central failure mode): it enqueues a tombstone for
// retry and returns the error so Vault also retries revocation.
func (b *backend) secretRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	full, _ := req.Secret.InternalData["full_sdk_key"].(string)
	project, _ := req.Secret.InternalData["project"].(string)
	stage, _ := req.Secret.InternalData["release_stage"].(string)
	coordStr, _ := req.Secret.InternalData["coordinate"].(string)
	prefix, _ := req.Secret.InternalData["public_prefix"].(string)
	if full == "" {
		return nil, fmt.Errorf("revoke: missing internal full_sdk_key")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	delErr := client.DeleteSdkKey(ctx, project, stage, full)
	if delErr != nil && !fmclient.IsNotFound(delErr) {
		if coord, perr := parseCoordinateString(coordStr); perr == nil {
			_ = b.enqueueTombstone(ctx, req.Storage, coord, full, time.Now())
		}
		b.Logger().Error("revoke deleteSdkKey failed; enqueued for retry",
			"coordinate", coordStr, "public_prefix", prefix, "error", delErr)
		return nil, delErr
	}

	// Success or already gone: clear the current record if it still points here
	// so the next read re-mints.
	if coord, perr := parseCoordinateString(coordStr); perr == nil {
		if err := b.clearCurrentIfMatches(ctx, req.Storage, coord, full); err != nil {
			b.Logger().Warn("failed to clear current key after revoke", "coordinate", coordStr, "error", err)
		}
	}
	return nil, nil
}

// listCurrentKeys decodes every current-key record. Used by reconciliation and
// the orphan reaper.
func (b *backend) listCurrentKeys(ctx context.Context, s logical.Storage) ([]*currentKey, error) {
	return listAndDecode[currentKey](ctx, s, storageCurrentPrefix)
}
