package featuremanagement

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// createWAL is the write-ahead intent recorded before a createSdkKey call so a
// crash between create and store can be reconciled (orphan reaper).
type createWAL struct {
	Coordinate   string `json:"coordinate" mapstructure:"coordinate"`
	Project      string `json:"project" mapstructure:"project"`
	ReleaseStage string `json:"release_stage" mapstructure:"release_stage"`
	Type         string `json:"type" mapstructure:"type"`
}

// mintAndStore creates a new SDK key for coord and persists it as the current
// key, guarded by a WAL. The caller MUST hold the coordinate lock. The returned
// warning is non-empty when the minted key's format version differs from the
// requested coordinate version.
func (b *backend) mintAndStore(ctx context.Context, s logical.Storage, coord coordinate, rotated bool) (*currentKey, string, error) {
	walID, err := framework.PutWAL(ctx, s, walKindCreate, &createWAL{
		Coordinate:   coord.String(),
		Project:      coord.Project,
		ReleaseStage: coord.ReleaseStage,
		Type:         string(coord.Type),
	})
	if err != nil {
		return nil, "", fmt.Errorf("write-ahead log: %w", err)
	}

	client, err := b.getClient(ctx, s)
	if err != nil {
		_ = framework.DeleteWAL(ctx, s, walID) // no side effect yet
		return nil, "", err
	}

	details, err := client.CreateSdkKey(ctx, coord.Project, coord.ReleaseStage, coord.Type)
	if err != nil {
		_ = framework.DeleteWAL(ctx, s, walID) // create failed; nothing to roll back
		return nil, "", fmt.Errorf("create SDK key: %w", err)
	}

	now := time.Now().UTC()
	ck := &currentKey{
		Version:         coord.Version,
		ReleaseStage:    coord.ReleaseStage,
		Project:         coord.Project,
		Type:            string(coord.Type),
		FullSDKKey:      details.SdkKey,
		PublicPrefix:    fmclient.PublicPrefix(details.SdkKey),
		UpstreamVersion: details.Version,
		CreatedAt:       now,
	}
	if rotated {
		ck.LastRotatedAt = now
	}

	if err := b.writeCurrentKey(ctx, s, ck); err != nil {
		// Created in FM but couldn't store: leave the WAL so walRollback reaps
		// the orphan via listSdkKeys.
		return nil, "", fmt.Errorf("store current key: %w", err)
	}

	// The record is durable; commit (delete) the WAL.
	_ = framework.DeleteWAL(ctx, s, walID)

	var warning string
	if tv := tokenVersion(details.SdkKey); tv != "" && tv != coord.Version {
		warning = fmt.Sprintf("requested version %q but the FM service minted a %q-format key", coord.Version, tv)
	}
	return ck, warning, nil
}

// allTrackedKeys returns the set of full SDK keys the plugin legitimately
// tracks: every current-key record (across all coordinates that share an FM
// project/stage/type bucket) plus every queued deletion. The orphan reaper must
// never delete a key in this set.
func (b *backend) allTrackedKeys(ctx context.Context, s logical.Storage) (map[string]bool, error) {
	cks, err := b.listCurrentKeys(ctx, s)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(cks))
	for _, ck := range cks {
		set[ck.FullSDKKey] = true
	}
	tomb, err := b.tombstonedKeys(ctx, s)
	if err != nil {
		return nil, err
	}
	for k := range tomb {
		set[k] = true
	}
	return set, nil
}

// walRollback reaps SDK keys orphaned by a crashed create. It deletes any FM key
// in the WAL's project/stage/type bucket that is neither a tracked current key
// nor a queued deletion. WALRollbackMinAge ensures a merely-slow create has time
// to commit its current-key record before it is treated as an orphan.
func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	if kind != walKindCreate {
		return nil
	}
	if b.isStandby() {
		return nil
	}

	var w createWAL
	if err := mapstructure.Decode(data, &w); err != nil {
		return fmt.Errorf("decode create WAL: %w", err)
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return err
	}

	tracked, err := b.allTrackedKeys(ctx, req.Storage)
	if err != nil {
		return err
	}

	list, err := client.ListSdkKeys(ctx, w.Project, w.ReleaseStage)
	if err != nil {
		return err
	}
	for _, k := range list.OfType(fmclient.SdkKeyType(w.Type)) {
		if tracked[k.SdkKey] {
			continue
		}
		if err := client.DeleteSdkKey(ctx, w.Project, w.ReleaseStage, k.SdkKey); err != nil && !fmclient.IsNotFound(err) {
			return err
		}
		b.Logger().Warn("walRollback reaped orphaned SDK key from a crashed create",
			"coordinate", w.Coordinate, "public_prefix", fmclient.PublicPrefix(k.SdkKey))
	}
	return nil
}
