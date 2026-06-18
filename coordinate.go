package featuremanagement

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

var (
	// versionPattern matches the SDK-key FORMAT version segment (the `dtNN`
	// token), e.g. dt01. This is the SDK key format version, NOT an API or
	// plugin version.
	versionPattern = regexp.MustCompile(`^dt[0-9]{2}$`)

	// keyPattern matches the FM API ProjectKey / ReleaseStageKey schema.
	keyPattern = regexp.MustCompile(`^[a-z][a-z0-9-_]{1,254}[a-z0-9]$`)
)

// coordinate identifies a single SDK key by its addressable elements. Each
// element is a path segment so Vault policies can regex-match any of them to
// scope a consumer (e.g. to its own project + release stage).
type coordinate struct {
	Version      string
	ReleaseStage string
	Project      string
	Type         fmclient.SdkKeyType
}

// String returns the canonical coordinate, used as the storage-key suffix and
// the per-coordinate lock key.
func (c coordinate) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", c.Version, c.ReleaseStage, c.Project, c.Type)
}

// parseCoordinate builds and validates a coordinate from path field values.
// Validation defends against path-segment injection: a crafted segment could
// otherwise escape a consumer's Vault policy regex or address an unintended FM
// resource.
func parseCoordinate(version, releaseStage, project, typ string) (coordinate, error) {
	c := coordinate{
		Version:      version,
		ReleaseStage: releaseStage,
		Project:      project,
		Type:         fmclient.SdkKeyType(typ),
	}
	if !versionPattern.MatchString(version) {
		return coordinate{}, fmt.Errorf("invalid version %q: must match dt<NN> (e.g. dt01)", version)
	}
	if !keyPattern.MatchString(releaseStage) {
		return coordinate{}, fmt.Errorf("invalid release-stage %q", releaseStage)
	}
	if !keyPattern.MatchString(project) {
		return coordinate{}, fmt.Errorf("invalid project %q", project)
	}
	if !c.Type.Valid() {
		return coordinate{}, fmt.Errorf("invalid type %q: must be web, server, or mobile", typ)
	}
	return c, nil
}

// parseCoordinateString parses a canonical coordinate string
// ("version/release-stage/project/type"), used to rebuild a coordinate from a
// lease's internal data or a WAL/tombstone record.
func parseCoordinateString(s string) (coordinate, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 4 {
		return coordinate{}, fmt.Errorf("invalid coordinate %q", s)
	}
	return parseCoordinate(parts[0], parts[1], parts[2], parts[3])
}

// tokenVersion extracts the `dtNN` token from a full SDK key, used to verify a
// minted key's format version matches the requested coordinate.
func tokenVersion(sdkKey string) string {
	for i := 0; i < len(sdkKey); i++ {
		if sdkKey[i] == '.' {
			return sdkKey[:i]
		}
	}
	return ""
}
