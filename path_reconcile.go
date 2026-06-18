package featuremanagement

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

func (b *backend) pathReconcile() *framework.Path {
	return &framework.Path{
		Pattern: "reconcile$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "feature-management",
			OperationVerb:   "reconcile",
		},
		Fields: map[string]*framework.FieldSchema{
			"delete_orphans": {
				Type:        framework.TypeBool,
				Description: "If true, delete FM keys that the plugin does not track and that are not queued for deletion.",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathReconcileOp},
		},
		HelpSynopsis:    "Reconcile plugin state against the FM service.",
		HelpDescription: "Clears current-key records whose key the FM service no longer has (out-of-band rotation) and reports orphaned keys (present in FM, untracked, not queued). Set delete_orphans=true to delete those orphans.",
	}
}

func (b *backend) pathReconcileOp(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if b.isStandby() {
		return logical.ErrorResponse("reconcile must run on the active node"), nil
	}
	deleteOrphans := d.Get("delete_orphans").(bool)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	currents, err := b.listCurrentKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	tracked, err := b.allTrackedKeys(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	type bucket struct{ project, stage string }
	buckets := map[bucket]bool{}
	for _, ck := range currents {
		buckets[bucket{ck.Project, ck.ReleaseStage}] = true
	}

	clearedStale := []string{}
	orphans := []string{}

	// 1. Clear current records whose key FM no longer has (FM rotated it out-of-band).
	for _, ck := range currents {
		list, err := client.ListSdkKeys(ctx, ck.Project, ck.ReleaseStage)
		if err != nil {
			return nil, err
		}
		found := false
		for _, k := range list.OfType(fmclient.SdkKeyType(ck.Type)) {
			if k.SdkKey == ck.FullSDKKey {
				found = true
				break
			}
		}
		if !found {
			if err := b.clearCurrentIfMatches(ctx, req.Storage, ck.coordinate(), ck.FullSDKKey); err != nil {
				return nil, err
			}
			clearedStale = append(clearedStale, ck.PublicPrefix)
		}
	}

	// 2. Detect (and optionally delete) orphans across known buckets.
	for bkt := range buckets {
		list, err := client.ListSdkKeys(ctx, bkt.project, bkt.stage)
		if err != nil {
			return nil, err
		}
		for _, k := range list.All() {
			if tracked[k.SdkKey] {
				continue
			}
			orphans = append(orphans, fmclient.PublicPrefix(k.SdkKey))
			if deleteOrphans {
				if err := client.DeleteSdkKey(ctx, bkt.project, bkt.stage, k.SdkKey); err != nil && !fmclient.IsNotFound(err) {
					return nil, err
				}
			}
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cleared_stale_current": clearedStale,
			"orphans":               orphans,
			"orphans_deleted":       deleteOrphans,
		},
	}, nil
}
