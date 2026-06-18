package featuremanagement

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathRotate() *framework.Path {
	return &framework.Path{
		Pattern: "rotate/" + coordinatePathSuffix,
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "feature-management",
			OperationVerb:   "rotate",
			OperationSuffix: "sdk-key",
		},
		Fields: coordinateFields,
		Operations: map[logical.Operation]framework.OperationHandler{
			// POST/PUT map to UpdateOperation; no ExistenceCheck/CreateOperation
			// so the framework doesn't require one.
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotateOp},
		},
		HelpSynopsis:    "Force an immediate rotation for a coordinate (create-new, delete-old after grace).",
		HelpDescription: "Mints a new SDK key for the coordinate and schedules the predecessor for deletion after the role's rotation_grace window (make-before-break). Consumers must re-read the coordinate path to obtain the new key under a fresh lease.",
	}
}

func (b *backend) pathRotateOp(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	coord, role, errResp := b.coordinateFromRequest(ctx, req, d)
	if errResp != nil {
		return errResp, nil
	}

	lock := b.lockCoordinate(coord)
	lock.Lock()
	defer lock.Unlock()

	predecessor, err := b.readCurrentKey(ctx, req.Storage, coord)
	if err != nil {
		return nil, err
	}

	newKey, warning, err := b.mintAndStore(ctx, req.Storage, coord, true)
	if err != nil {
		b.Logger().Error("failed to rotate SDK key", "coordinate", coord.String(), "error", err)
		return nil, fmt.Errorf("rotate SDK key for %s failed (verify the FM service URL/credentials in %q): %w", coord, storageConfig, err)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"sdk_key":       newKey.FullSDKKey,
			"public_prefix": newKey.PublicPrefix,
			"version":       newKey.Version,
		},
	}
	if warning != "" {
		resp.AddWarning(warning)
	}

	// Make-before-break: the predecessor is deleted only after the grace window,
	// by the periodic sweep. There is no synchronous delete here.
	if predecessor != nil && predecessor.FullSDKKey != newKey.FullSDKKey {
		deleteAfter := time.Now().Add(role.RotationGrace)
		if err := b.enqueueTombstone(ctx, req.Storage, coord, predecessor.FullSDKKey, deleteAfter); err != nil {
			return nil, err
		}
		resp.Data["rotated_from"] = predecessor.PublicPrefix
		resp.Data["predecessor_delete_after"] = deleteAfter.UTC().Format(time.RFC3339)
	}

	resp.AddWarning("consumers must re-read the coordinate path to obtain the rotated key under a new lease")
	return resp, nil
}
