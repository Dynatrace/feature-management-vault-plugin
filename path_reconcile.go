package featuremanagement

import (
	"context"
	"time"

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
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathReconcileOp},
		},
		HelpSynopsis:    "Re-point the mount's records at the SDK keys the FM service currently holds.",
		HelpDescription: "Moves each stored record onto the newest key FM holds for its coordinate, and clears the record when FM holds none. This is how an out-of-band key rotation reaches consumers. The reconciliation loop does this on a schedule; this path runs a pass immediately. Nothing is deleted in the FM service.",
	}
}

func (b *backend) pathReconcileOp(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if b.isStandby() {
		return logical.ErrorResponse("reconcile must run on the active node"), nil
	}
	cleared, updated, err := b.reconcile(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"cleared_stale_current": cleared,
			"updated_to_newest":     updated,
		},
	}, nil
}

// periodicFunc is the reconciliation loop: one pass per configured interval, on the active node.
func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	if b.isStandby() {
		return nil
	}

	cfg, cfgErr := b.readConfig(ctx, req.Storage)
	if cfgErr != nil {
		return cfgErr
	}
	if !cfg.reconcileEnabled() {
		return nil
	}

	b.reconcileMu.Lock()
	due := time.Now().After(b.nextReconcile)
	if due {
		b.nextReconcile = nextReconcileAt(cfg.reconcileInterval())
	}
	b.reconcileMu.Unlock()
	if !due {
		return nil
	}

	cleared, updated, err := b.reconcile(ctx, req.Storage)
	if err != nil {
		return err
	}
	if len(cleared) > 0 || len(updated) > 0 {
		b.Logger().Info("reconciliation loop re-pointed records",
			"cleared", len(cleared), "updated", len(updated))
	}
	return nil
}

// reconcile moves each record onto FM's newest key, clearing it when FM holds none. Deletes nothing.
func (b *backend) reconcile(ctx context.Context, s logical.Storage) (cleared, updated []string, err error) {
	currents, err := b.listCurrentKeys(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	cleared, updated = []string{}, []string{}
	if len(currents) == 0 {
		// nothing to check, so an unconfigured or idle mount never builds a client
		return cleared, updated, nil
	}

	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, nil, err
	}

	for _, ck := range currents {
		list, err := client.ListSdkKeys(ctx, ck.Project, ck.ReleaseStage)
		switch {
		case fmclient.IsNotFound(err):
			// project or release stage is gone, so the record is stale too
			list = &fmclient.SDKKeyList{}
		case err != nil:
			return nil, nil, err
		}

		winner := pickKey(list, fmclient.SdkKeyType(ck.Type))
		switch {
		case winner == nil:
			if err := b.clearCurrentIfMatches(ctx, s, ck.coordinate(), ck.FullSDKKey); err != nil {
				return nil, nil, err
			}
			cleared = append(cleared, ck.PublicPrefix)
		case winner.SdkKey != ck.FullSDKKey:
			if err := b.repointCurrentIfMatches(ctx, s, ck, winner.SdkKey); err != nil {
				return nil, nil, err
			}
			updated = append(updated, fmclient.PublicPrefix(winner.SdkKey))
		}
	}
	return cleared, updated, nil
}
