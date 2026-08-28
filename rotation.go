package featuremanagement

import (
	"context"
	"errors"
	"time"

	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

const (
	// maxDeleteAttempts is the point after which a failing deferred delete is
	// dead-lettered (retried slowly) rather than dropped.
	maxDeleteAttempts = 10
	// deadLetterBackoff is the slow retry cadence for dead-lettered tombstones.
	deadLetterBackoff = time.Hour
)

// deletionTombstone is a durable record of an SDK key scheduled for deletion
// after a rotation grace window (or immediately, on a failed revoke). It
// survives plugin/Vault restarts because it lives in logical storage.
type deletionTombstone struct {
	ID            string    `json:"id"`
	Coordinate    string    `json:"coordinate"`
	Project       string    `json:"project"`
	ReleaseStage  string    `json:"release_stage"`
	Type          string    `json:"type"`
	FullSDKKey    string    `json:"full_sdk_key"`
	PublicPrefix  string    `json:"public_prefix"`
	DeleteAfter   time.Time `json:"delete_after"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

func (b *backend) enqueueTombstone(ctx context.Context, s logical.Storage, coord coordinate, fullKey string, deleteAfter time.Time) error {
	id, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}
	return b.putTombstone(ctx, s, &deletionTombstone{
		ID:           id,
		Coordinate:   coord.String(),
		Project:      coord.Project,
		ReleaseStage: coord.ReleaseStage,
		Type:         string(coord.Type),
		FullSDKKey:   fullKey,
		PublicPrefix: fmclient.PublicPrefix(fullKey),
		DeleteAfter:  deleteAfter,
		CreatedAt:    time.Now().UTC(),
	})
}

func (b *backend) putTombstone(ctx context.Context, s logical.Storage, t *deletionTombstone) error {
	return putJSON(ctx, s, storageTombstonePrefix+t.ID, t)
}

func (b *backend) listTombstones(ctx context.Context, s logical.Storage) ([]*deletionTombstone, error) {
	return listAndDecode[deletionTombstone](ctx, s, storageTombstonePrefix)
}

// tombstonedKeys returns the set of full SDK keys currently scheduled for
// deletion, so the orphan reaper never deletes an in-grace predecessor.
func (b *backend) tombstonedKeys(ctx context.Context, s logical.Storage) (map[string]bool, error) {
	tombs, err := b.listTombstones(ctx, s)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(tombs))
	for _, t := range tombs {
		set[t.FullSDKKey] = true
	}
	return set, nil
}

// periodicFunc sweeps the deletion queue, deleting predecessor keys whose grace
// window has elapsed. Failures are retried on the next tick (and dead-lettered
// after maxDeleteAttempts) — a failed delete is never silently dropped, because
// it represents the central "orphaned active key" failure mode.
func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	if b.isStandby() {
		return nil
	}

	b.rotateWorkingClientIfDue(ctx, req.Storage)

	tombs, err := b.listTombstones(ctx, req.Storage)
	if err != nil {
		return err
	}

	now := time.Now()
	var errs []error
	for _, t := range tombs {
		if now.Before(t.DeleteAfter) {
			continue
		}
		client, err := b.getClient(ctx, req.Storage)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		delErr := client.DeleteSdkKey(ctx, t.Project, t.ReleaseStage, t.FullSDKKey)
		if delErr == nil || fmclient.IsNotFound(delErr) {
			if err := req.Storage.Delete(ctx, storageTombstonePrefix+t.ID); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		t.Attempts++
		t.LastError = delErr.Error()
		t.LastAttemptAt = now
		b.Logger().Warn("deferred SDK key delete failed (orphan risk)",
			"coordinate", t.Coordinate, "public_prefix", t.PublicPrefix,
			"attempts", t.Attempts, "error", delErr)
		if t.Attempts >= maxDeleteAttempts {
			t.DeleteAfter = now.Add(deadLetterBackoff)
		}
		if err := b.putTombstone(ctx, req.Storage, t); err != nil {
			errs = append(errs, err)
		}
		errs = append(errs, delErr)
	}
	return errors.Join(errs...)
}
