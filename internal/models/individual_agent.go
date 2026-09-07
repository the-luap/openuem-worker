package models

import (
	"context"
	"errors"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/site"
	"github.com/open-uem/ent/tag"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/ent/tenant"
	"github.com/open-uem/nats/enrollment/registry"
)

var ErrAgentScope = errors.New("agent request scope is not authorized")

// AuthorizeIndividualRequest checks existing desktop records and every requested
// profile/task against the durable enrollment scope. A first inventory report or
// configuration request can arrive before the desktop inventory row exists.
func (m *Model) AuthorizeIndividualRequest(ctx context.Context, identity registry.Identity, operation string, profileID int, taskIDs []int) error {
	a, err := m.Client.Agent.Query().Where(agent.ID(identity.ID)).WithSite(func(q *ent.SiteQuery) { q.WithTenant() }).Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) || (operation != "report" && operation != "agentconfig") {
			return ErrAgentScope
		}
	} else {
		if len(a.Edges.Site) != 1 || a.Edges.Site[0].ID != identity.SiteID || a.Edges.Site[0].Edges.Tenant == nil || a.Edges.Site[0].Edges.Tenant.ID != identity.TenantID {
			return ErrAgentScope
		}
	}
	if profileID > 0 {
		allowed, err := m.Client.Profile.Query().Where(profile.ID(profileID), profile.DisabledEQ(false), profileScope(identity.SiteID, identity.TenantID), profile.Or(profile.ApplyToAll(true), profile.HasTagsWith(tag.HasOwnerWith(agent.ID(identity.ID), agent.HasSiteWith(site.ID(identity.SiteID), site.HasTenantWith(tenant.ID(identity.TenantID))))))).Exist(ctx)
		if err != nil || !allowed {
			return ErrAgentScope
		}
	}
	if len(taskIDs) > 0 {
		if profileID <= 0 {
			return ErrAgentScope
		}
		count, err := m.Client.Task.Query().Where(task.IDIn(taskIDs...), task.HasProfileWith(profile.ID(profileID))).Count(ctx)
		if err != nil || count != len(taskIDs) {
			return ErrAgentScope
		}
	}
	return nil
}
