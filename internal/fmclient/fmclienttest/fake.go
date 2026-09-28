// Package fmclienttest is an in-memory fmclient.FMClient shared by the plugin tests and mock server.
package fmclienttest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// Fake is a concurrency-safe in-memory fmclient.FMClient; the *Err hooks force failures.
type Fake struct {
	mu sync.Mutex

	// keys maps "project/release-stage" -> active keys for that stage.
	keys    map[string]*fmclient.SDKKeyList
	version int
	geo     string

	// Failure-injection hooks; when set, the corresponding call returns the error.
	CreateErr error
	ListErr   error

	// BeforeList runs at the top of ListSdkKeys so a test can simulate another instance racing it.
	BeforeList func()

	// Call log (public prefixes only) for assertions.
	Created []string
}

var _ fmclient.FMClient = (*Fake)(nil)

// New returns an empty in-memory fake client.
func New() *Fake {
	return &Fake{keys: map[string]*fmclient.SDKKeyList{}, geo: "us"}
}

func coordKey(project, releaseStage string) string {
	return project + "/" + releaseStage
}

// CreateSdkKey implements fmclient.FMClient.
func (f *Fake) CreateSdkKey(_ context.Context, project, releaseStage string, keyType fmclient.SdkKeyType) (*fmclient.SDKKeyDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.CreateErr != nil {
		return nil, f.CreateErr
	}
	if !keyType.Valid() {
		return nil, fmt.Errorf("fmclienttest: invalid key type %q", keyType)
	}

	f.version++
	now := time.Now().UTC()
	details := fmclient.SDKKeyDetails{
		SdkKey: f.newKey(keyType),
		Type:   keyType,
		ModificationInfo: &fmclient.ModificationInfo{
			CreatedBy:        "fake",
			CreatedTime:      now,
			LastModifiedBy:   "fake",
			LastModifiedTime: now,
		},
		Version: f.version,
	}

	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		list = &fmclient.SDKKeyList{}
		f.keys[coordKey(project, releaseStage)] = list
	}
	switch keyType {
	case fmclient.SdkKeyTypeWeb:
		list.Web = append(list.Web, details)
	case fmclient.SdkKeyTypeMobile:
		list.Mobile = append(list.Mobile, details)
	case fmclient.SdkKeyTypeServer:
		list.Server = append(list.Server, details)
	}
	f.Created = append(f.Created, fmclient.PublicPrefix(details.SdkKey))
	return &details, nil
}

// ListSdkKeys implements fmclient.FMClient.
func (f *Fake) ListSdkKeys(_ context.Context, project, releaseStage string) (*fmclient.SDKKeyList, error) {
	if f.BeforeList != nil {
		f.BeforeList()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		return &fmclient.SDKKeyList{}, nil
	}
	// Return a copy so callers can't mutate internal state.
	cp := *list
	return &cp, nil
}

// Drop simulates a key disappearing from the FM service out of band; not an FMClient method.
func (f *Fake) Drop(project, releaseStage, sdkKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		return
	}
	match := func(d fmclient.SDKKeyDetails) bool { return d.SdkKey == sdkKey }
	list.Web = slices.DeleteFunc(list.Web, match)
	list.Mobile = slices.DeleteFunc(list.Mobile, match)
	list.Server = slices.DeleteFunc(list.Server, match)
}

// ActiveCount returns the total number of active keys for a coordinate.
func (f *Fake) ActiveCount(project, releaseStage string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.keys[coordKey(project, releaseStage)]
	if list == nil {
		return 0
	}
	return len(list.Web) + len(list.Mobile) + len(list.Server)
}

// newKey builds a syntactically valid SDK key:
// {token}.{platform}_{geo}_{publicRandom}.{secret}_{sha1}
func (f *Fake) newKey(t fmclient.SdkKeyType) string {
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
