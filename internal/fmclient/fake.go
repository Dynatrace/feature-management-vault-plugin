package fmclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Fake is an in-memory FMClient for unit tests and the local mock FM server.
// It is safe for concurrent use. Tests can force failures via the *Err hooks
// and inspect the Created/Deleted call logs.
type Fake struct {
	mu sync.Mutex

	// keys maps "project/release-stage" -> active keys for that stage.
	keys    map[string]*SDKKeyList
	version int
	geo     string

	// Failure-injection hooks; when set, the corresponding call returns the error.
	CreateErr error
	ListErr   error
	DeleteErr error

	// Call logs (public prefixes only) for assertions.
	Created []string
	Deleted []string
}

var _ FMClient = (*Fake)(nil)

// NewFake returns an empty in-memory fake client.
func NewFake() *Fake {
	return &Fake{keys: map[string]*SDKKeyList{}, geo: "us"}
}

func coordKey(project, releaseStage string) string {
	return project + "/" + releaseStage
}

// CreateSdkKey implements FMClient.
func (f *Fake) CreateSdkKey(_ context.Context, project, releaseStage string, keyType SdkKeyType) (*SDKKeyDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.CreateErr != nil {
		return nil, f.CreateErr
	}
	if !keyType.Valid() {
		return nil, fmt.Errorf("fmclient(fake): invalid key type %q", keyType)
	}

	f.version++
	now := time.Now().UTC()
	details := SDKKeyDetails{
		SdkKey: f.newKey(keyType),
		Type:   keyType,
		ModificationInfo: &ModificationInfo{
			CreatedBy:        "fake",
			CreatedTime:      now,
			LastModifiedBy:   "fake",
			LastModifiedTime: now,
		},
		Version: f.version,
	}

	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		list = &SDKKeyList{}
		f.keys[coordKey(project, releaseStage)] = list
	}
	switch keyType {
	case SdkKeyTypeWeb:
		list.Web = append(list.Web, details)
	case SdkKeyTypeMobile:
		list.Mobile = append(list.Mobile, details)
	case SdkKeyTypeServer:
		list.Server = append(list.Server, details)
	}
	f.Created = append(f.Created, PublicPrefix(details.SdkKey))
	return &details, nil
}

// ListSdkKeys implements FMClient.
func (f *Fake) ListSdkKeys(_ context.Context, project, releaseStage string) (*SDKKeyList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		return &SDKKeyList{}, nil
	}
	// Return a copy so callers can't mutate internal state.
	cp := *list
	return &cp, nil
}

// DeleteSdkKey implements FMClient.
func (f *Fake) DeleteSdkKey(_ context.Context, project, releaseStage, sdkKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		return ErrNotFound
	}
	removed := false
	list.Web, removed = removeKey(list.Web, sdkKey, removed)
	list.Mobile, removed = removeKey(list.Mobile, sdkKey, removed)
	list.Server, removed = removeKey(list.Server, sdkKey, removed)
	if !removed {
		return ErrNotFound
	}
	f.Deleted = append(f.Deleted, PublicPrefix(sdkKey))
	return nil
}

// ActiveCount returns the total number of active keys for a coordinate (test helper).
func (f *Fake) ActiveCount(project, releaseStage string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		return 0
	}
	return len(list.Web) + len(list.Mobile) + len(list.Server)
}

func removeKey(in []SDKKeyDetails, sdkKey string, already bool) ([]SDKKeyDetails, bool) {
	out := in[:0]
	for _, d := range in {
		if d.SdkKey == sdkKey {
			already = true
			continue
		}
		out = append(out, d)
	}
	return out, already
}

// newKey builds a syntactically valid SDK key:
// {token}.{platform}_{geo}_{publicRandom}.{secret}_{sha1}
func (f *Fake) newKey(t SdkKeyType) string {
	return fmt.Sprintf("dt01.%s_%s_%s.%s_%s", t, f.geo, randAlphaNum(10), randHex(16), randHex(5))
}

const alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randAlphaNum(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphanum[int(b[i])%len(alphanum)]
	}
	return string(b)
}

// randHex returns 2*nBytes lowercase hex characters.
func randHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
