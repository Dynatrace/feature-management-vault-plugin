package featuremanagement

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dynatrace/feature-management-vault-plugin/internal/fmclient"
)

// roleEntry allowlists the coordinates a mount may serve; an empty field is a wildcard.
type roleEntry struct {
	Name            string `json:"name"`
	ProjectKey      string `json:"project_key,omitempty"`
	ReleaseStageKey string `json:"release_stage_key,omitempty"`
	Type            string `json:"type,omitempty"` // web|server|mobile; empty = any
}

// matches reports whether the role permits coord; an empty constraint is a wildcard.
func (r *roleEntry) matches(coord coordinate) bool {
	if r.ProjectKey != "" && r.ProjectKey != coord.Project {
		return false
	}
	if r.ReleaseStageKey != "" && r.ReleaseStageKey != coord.ReleaseStage {
		return false
	}
	if r.Type != "" && r.Type != string(coord.Type) {
		return false
	}
	return true
}

func (b *backend) readRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	return getJSON[roleEntry](ctx, s, storageRolePrefix+name)
}

// coordinateAllowed returns nil when any role permits coord; overlapping roles simply union.
func (b *backend) coordinateAllowed(ctx context.Context, s logical.Storage, coord coordinate) error {
	names, err := s.List(ctx, storageRolePrefix)
	if err != nil {
		return err
	}
	for _, name := range names {
		role, err := b.readRole(ctx, s, name)
		if err != nil {
			return err
		}
		if role != nil && role.matches(coord) {
			return nil
		}
	}
	return fmt.Errorf("no role matches coordinate %q; create a matching role or an unconstrained catch-all role", coord)
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
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		ExistenceCheck:  b.roleExistenceCheck,
		HelpSynopsis:    "Manage the roles that allowlist which coordinates the mount may serve.",
		HelpDescription: "A coordinate is served if any role matches it; overlapping roles union. Constraints (project_key, release_stage_key, type) are optional; empty fields are wildcards, so an unconstrained role is a catch-all.",
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
		role = &roleEntry{Name: name}
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

	if role.Type != "" && !fmclient.SdkKeyType(role.Type).Valid() {
		return logical.ErrorResponse("invalid type %q: must be web, server, or mobile", role.Type), nil
	}

	if err := putJSON(ctx, req.Storage, storageRolePrefix+name, role); err != nil {
		return nil, err
	}
	return nil, nil
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
