package featuremanagement

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// coordinateFields is the field schema for the coordinate read path.
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

// coordinatePathSuffix is the coordinate pattern of the read path.
const coordinatePathSuffix = "(?P<version>[^/]+)/(?P<release_stage>[^/]+)/(?P<project>[^/]+)/(?P<type>web|server|mobile)$"

// currentKey is the plugin's record of the key it provisioned for a coordinate.
type currentKey struct {
	Version      string    `json:"version"`
	ReleaseStage string    `json:"release_stage"`
	Project      string    `json:"project"`
	Type         string    `json:"type"`
	FullSDKKey   string    `json:"full_sdk_key"`
	PublicPrefix string    `json:"public_prefix"`
	CreatedAt    time.Time `json:"created_at"`
}

// currentStorageKey is hex-encoded so the coordinate's slashes stay enumerable by List.
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

// clearCurrentIfMatches deletes coord's record iff it still points at fullKey; it takes the lock.
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

// createJitter bounds the randomized pause before creating a key. A var so tests can disable it.
var createJitter = 2 * time.Second

// sleepCtx waits for d, or returns early if the request is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pickKey chooses the key of that type every instance converges on, or nil if FM holds none.
func pickKey(list *fmclient.SDKKeyList, t fmclient.SdkKeyType) *fmclient.SDKKeyDetails {
	if list == nil {
		return nil
	}
	keys := list.OfType(t)
	var best *fmclient.SDKKeyDetails
	for i := range keys {
		if best == nil || winsOver(&keys[i], best) {
			best = &keys[i]
		}
	}
	return best
}

// winsOver ranks a above b, newest first; every instance must apply this identically to converge.
func winsOver(a, b *fmclient.SDKKeyDetails) bool {
	at, bt := createdAt(a), createdAt(b)
	if !at.Equal(bt) {
		return at.After(bt)
	}
	return fmclient.PublicPrefix(a.SdkKey) < fmclient.PublicPrefix(b.SdkKey)
}

// createdAt is the key's creation time, or the zero time when FM omits modificationInfo.
func createdAt(d *fmclient.SDKKeyDetails) time.Time {
	if d.ModificationInfo == nil {
		return time.Time{}
	}
	return d.ModificationInfo.CreatedTime
}

// provision adopts FM's key for coord or creates one; the caller MUST hold the coordinate lock.
func (b *backend) provision(ctx context.Context, s logical.Storage, coord coordinate) (*currentKey, string, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, "", err
	}

	// a 404 means the project or release stage is absent; let the create surface that
	list, err := client.ListSdkKeys(ctx, coord.Project, coord.ReleaseStage)
	if err != nil && !fmclient.IsNotFound(err) {
		return nil, "", fmt.Errorf("list SDK keys: %w", err)
	}

	chosen := pickKey(list, coord.Type)
	created := false

	// narrow the cold-start race: give another instance's create time to become visible
	if chosen == nil && createJitter > 0 {
		if err := sleepCtx(ctx, time.Duration(rand.Int63n(int64(createJitter)))); err != nil {
			return nil, "", err
		}
		if recheck, err := client.ListSdkKeys(ctx, coord.Project, coord.ReleaseStage); err == nil {
			chosen = pickKey(recheck, coord.Type)
		}
	}

	if chosen == nil {
		details, err := client.CreateSdkKey(ctx, coord.Project, coord.ReleaseStage, coord.Type)
		if err != nil {
			return nil, "", fmt.Errorf("create SDK key: %w", err)
		}
		created = true
		chosen = details

		// another instance may have created one in the same window; converge on one winner
		if list, err := client.ListSdkKeys(ctx, coord.Project, coord.ReleaseStage); err == nil {
			if winner := pickKey(list, coord.Type); winner != nil && winner.SdkKey != chosen.SdkKey {
				b.Logger().Info("adopted another instance's key after a concurrent create",
					"coordinate", coord.String(),
					"adopted", fmclient.PublicPrefix(winner.SdkKey),
					"abandoned", fmclient.PublicPrefix(chosen.SdkKey))
				chosen = winner
			}
		}
	}

	ck := &currentKey{
		Version:      coord.Version,
		ReleaseStage: coord.ReleaseStage,
		Project:      coord.Project,
		Type:         string(coord.Type),
		FullSDKKey:   chosen.SdkKey,
		PublicPrefix: fmclient.PublicPrefix(chosen.SdkKey),
		CreatedAt:    time.Now().UTC(),
	}

	if err := b.writeCurrentKey(ctx, s, ck); err != nil {
		if created {
			// the key exists upstream but is unrecorded; the next read adopts it
			b.Logger().Error("created SDK key could not be stored",
				"coordinate", coord.String(), "public_prefix", ck.PublicPrefix, "error", err)
		}
		return nil, "", fmt.Errorf("store current key: %w", err)
	}

	var warning string
	if tv := tokenVersion(chosen.SdkKey); tv != "" && tv != coord.Version {
		warning = fmt.Sprintf("requested version %q but the FM service holds a %q-format key", coord.Version, tv)
	}
	return ck, warning, nil
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
		HelpSynopsis:    "Read (and lazily provision) the SDK key for a coordinate.",
		HelpDescription: "Returns the SDK key for <version>/<release-stage>/<project>/<type>, provisioning one via the FM service if the plugin has not already done so. The key is static: repeated reads return the same value, and the plugin never deletes or rotates it.",
	}
}

// coordinateFromRequest parses the coordinate; a non-nil response is a 4xx the caller must return.
func (b *backend) coordinateFromRequest(ctx context.Context, req *logical.Request, d *framework.FieldData) (coordinate, *logical.Response) {
	coord, err := parseCoordinate(
		d.Get("version").(string),
		d.Get("release_stage").(string),
		d.Get("project").(string),
		d.Get("type").(string),
	)
	if err != nil {
		return coordinate{}, logical.ErrorResponse(err.Error())
	}
	// a matching role is the mount's allowlist of coordinates it may serve
	if err := b.coordinateAllowed(ctx, req.Storage, coord); err != nil {
		return coordinate{}, logical.ErrorResponse(err.Error())
	}
	return coord, nil
}

func (b *backend) pathCoordinateReadOp(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	coord, errResp := b.coordinateFromRequest(ctx, req, d)
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
	provisioned := false
	if ck == nil {
		provisioned = true
		ck, warning, err = b.provision(ctx, req.Storage, coord)
		if err != nil {
			b.Logger().Error("failed to provision SDK key", "coordinate", coord.String(), "error", err)
			return nil, fmt.Errorf("provision SDK key for %s failed (verify the FM service URL/credentials in %q): %w", coord, storageConfig, err)
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"sdk_key":       ck.FullSDKKey,
			"public_prefix": ck.PublicPrefix,
		},
	}
	if warning != "" {
		resp.AddWarning(warning)
	}
	b.metrics.recordIssued(ctx, coord, provisioned)
	return resp, nil
}

// repointCurrentIfMatches moves the record onto newKey iff it still holds prev's key; takes the lock.
func (b *backend) repointCurrentIfMatches(ctx context.Context, s logical.Storage, prev *currentKey, newKey string) error {
	coord := prev.coordinate()
	lock := b.lockCoordinate(coord)
	lock.Lock()
	defer lock.Unlock()

	ck, err := b.readCurrentKey(ctx, s, coord)
	if err != nil || ck == nil {
		return err
	}
	if ck.FullSDKKey != prev.FullSDKKey {
		return nil
	}
	ck.FullSDKKey = newKey
	ck.PublicPrefix = fmclient.PublicPrefix(newKey)
	ck.CreatedAt = time.Now().UTC()
	return b.writeCurrentKey(ctx, s, ck)
}

// listCurrentKeys decodes every current-key record. Used by reconciliation.
func (b *backend) listCurrentKeys(ctx context.Context, s logical.Storage) ([]*currentKey, error) {
	return listAndDecode[currentKey](ctx, s, storageCurrentPrefix)
}
