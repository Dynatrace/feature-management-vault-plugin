package featuremanagement

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
)

// getJSON reads and JSON-decodes the entry at key into a *T. It returns
// (nil, nil) when the key does not exist.
func getJSON[T any](ctx context.Context, s logical.Storage, key string) (*T, error) {
	entry, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	v := new(T)
	if err := entry.DecodeJSON(v); err != nil {
		return nil, err
	}
	return v, nil
}

// putJSON JSON-encodes v and stores it at key.
func putJSON(ctx context.Context, s logical.Storage, key string, v any) error {
	entry, err := logical.StorageEntryJSON(key, v)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// listAndDecode lists the immediate children under prefix and decodes each into
// a *T. Keys must be flat (no nested "folders") under prefix, which Vault's
// hierarchical List would otherwise return as bare folder names.
func listAndDecode[T any](ctx context.Context, s logical.Storage, prefix string) ([]*T, error) {
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]*T, 0, len(keys))
	for _, k := range keys {
		v, err := getJSON[T](ctx, s, prefix+k)
		if err != nil {
			return nil, err
		}
		if v != nil {
			out = append(out, v)
		}
	}
	return out, nil
}
