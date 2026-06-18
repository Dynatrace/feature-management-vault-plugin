package featuremanagement

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// Role policy defaults (see SDK Key Lifecycle in the scoping doc).
const (
	defaultRoleTTL       = 2280 * time.Hour // ~3 months
	defaultRoleMaxTTL    = 4560 * time.Hour // ~6 months
	defaultRotationGrace = 2 * time.Hour
)

// roleEntry is a policy template. Its constraints are optional; an empty field
// is a wildcard. The coordinate read path resolves the most-specific matching
// role to obtain TTLs and the rotation grace window.
type roleEntry struct {
	Name            string        `json:"name"`
	ProjectKey      string        `json:"project_key,omitempty"`
	ReleaseStageKey string        `json:"release_stage_key,omitempty"`
	Type            string        `json:"type,omitempty"` // web|server|mobile; empty = any
	TTL             time.Duration `json:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
	RotationGrace   time.Duration `json:"rotation_grace"`
}

// matches reports whether the role applies to coord, and how many constraints
// it pins (its specificity). A role with no constraints matches everything at
// specificity 0 (a catch-all).
func (r *roleEntry) matches(coord coordinate) (bool, int) {
	spec := 0
	if r.ProjectKey != "" {
		if r.ProjectKey != coord.Project {
			return false, 0
		}
		spec++
	}
	if r.ReleaseStageKey != "" {
		if r.ReleaseStageKey != coord.ReleaseStage {
			return false, 0
		}
		spec++
	}
	if r.Type != "" {
		if r.Type != string(coord.Type) {
			return false, 0
		}
		spec++
	}
	return true, spec
}

func (b *backend) readRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	return getJSON[roleEntry](ctx, s, storageRolePrefix+name)
}

// resolveRole returns the most-specific role matching coord. If several roles
// tie at the top specificity the match is ambiguous and an error is returned;
// if none match, the caller must create a matching or catch-all role.
func (b *backend) resolveRole(ctx context.Context, s logical.Storage, coord coordinate) (*roleEntry, error) {
	names, err := s.List(ctx, storageRolePrefix)
	if err != nil {
		return nil, err
	}
	var best *roleEntry
	bestSpec := -1
	tie := false
	for _, name := range names {
		role, err := b.readRole(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		ok, spec := role.matches(coord)
		if !ok {
			continue
		}
		switch {
		case spec > bestSpec:
			best, bestSpec, tie = role, spec, false
		case spec == bestSpec:
			tie = true
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no role matches coordinate %q; create a matching role or an unconstrained catch-all role", coord)
	}
	if tie {
		return nil, fmt.Errorf("ambiguous role match for coordinate %q: multiple roles match with equal specificity", coord)
	}
	return best, nil
}

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "feature-management",
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role.",
				Required:    true,
			},
			"project_key": {
				Type:        framework.TypeString,
				Description: "Optional project-key constraint. Empty matches any project.",
			},
			"release_stage_key": {
				Type:        framework.TypeString,
				Description: "Optional release-stage-key constraint. Empty matches any release stage.",
			},
			"type": {
				Type:        framework.TypeLowerCaseString,
				Description: "Optional SDK key type constraint (web, server, or mobile). Empty matches any type.",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL before rotation. Defaults to 2280h (~3 months).",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL. Defaults to 4560h.",
			},
			"rotation_grace": {
				Type:        framework.TypeDurationSecond,
				Description: "Overlap window during which the predecessor key remains valid after rotation. Defaults to 2h.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		ExistenceCheck:  b.roleExistenceCheck,
		HelpSynopsis:    "Manage policy-template roles (TTL, rotation grace, optional coordinate constraints).",
		HelpDescription: "A role supplies the TTL/max-TTL/rotation-grace policy for the coordinates it matches. Constraints (project_key, release_stage_key, type) are optional; empty fields are wildcards.",
	}
}

func (b *backend) pathRolesList() *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "feature-management",
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
		},
		HelpSynopsis: "List configured roles.",
	}
}

func (b *backend) roleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	role, err := b.readRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("role name is required"), nil
	}

	role, err := b.readRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &roleEntry{
			Name:          name,
			TTL:           defaultRoleTTL,
			MaxTTL:        defaultRoleMaxTTL,
			RotationGrace: defaultRotationGrace,
		}
	}

	if v, ok := d.GetOk("project_key"); ok {
		role.ProjectKey = v.(string)
	}
	if v, ok := d.GetOk("release_stage_key"); ok {
		role.ReleaseStageKey = v.(string)
	}
	if v, ok := d.GetOk("type"); ok {
		role.Type = v.(string)
	}
	if v, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("rotation_grace"); ok {
		role.RotationGrace = time.Duration(v.(int)) * time.Second
	}

	if role.Type != "" && !fmclient.SdkKeyType(role.Type).Valid() {
		return logical.ErrorResponse("invalid type %q: must be web, server, or mobile", role.Type), nil
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl (%s) must not exceed max_ttl (%s)", role.TTL, role.MaxTTL), nil
	}
	if role.RotationGrace <= 0 {
		return logical.ErrorResponse("rotation_grace must be greater than zero"), nil
	}

	var resp *logical.Response
	if role.TTL > 0 && role.RotationGrace >= role.TTL {
		resp = &logical.Response{}
		resp.AddWarning("rotation_grace is >= ttl; the grace window should be short relative to the key lifecycle")
	}

	if err := putJSON(ctx, req.Storage, storageRolePrefix+name, role); err != nil {
		return nil, err
	}
	return resp, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := b.readRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"project_key":       role.ProjectKey,
			"release_stage_key": role.ReleaseStageKey,
			"type":              role.Type,
			"ttl":               int64(role.TTL.Seconds()),
			"max_ttl":           int64(role.MaxTTL.Seconds()),
			"rotation_grace":    int64(role.RotationGrace.Seconds()),
		},
	}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, storageRolePrefix+d.Get("name").(string)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, storageRolePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
