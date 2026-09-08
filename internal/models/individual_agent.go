package models

import (
	"context"
	"database/sql"
	"errors"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/profile"
	"github.com/open-uem/ent/site"
	"github.com/open-uem/ent/tag"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/ent/tenant"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

var ErrAgentScope = errors.New("agent request scope is not authorized")

// AuthorizeIndividualRotation holds the inventory row, all scope edges and site
// ownership until the caller commits registry delivery/result and audit. Locking
// the parent row FOR UPDATE also prevents a concurrent FK-backed edge insertion;
// locking existing edges prevents their deletion during authorization.
// Registry callers must take their identity lock before these inventory locks.
func (m *Model) AuthorizeIndividualRotation(ctx context.Context, tx *sql.Tx, identity registry.Identity) error {
	if tx == nil || identity.Platform != "macos" || !enrollment.ValidDeviceID(identity.ID) || identity.TenantID <= 0 || identity.SiteID <= 0 {
		return ErrAgentScope
	}
	var id string
	if err := tx.QueryRowContext(ctx, `SELECT oid FROM agents WHERE oid=$1 FOR UPDATE`, identity.ID).Scan(&id); err != nil {
		return ErrAgentScope
	}
	rows, err := tx.QueryContext(ctx, `SELECT e.site_id,s.tenant_sites FROM site_agents e JOIN sites s ON s.id=e.site_id WHERE e.agent_id=$1 ORDER BY e.site_id LIMIT 2 FOR SHARE OF e,s`, identity.ID)
	if err != nil {
		return ErrAgentScope
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var siteID, tenantID int
		if rows.Scan(&siteID, &tenantID) != nil || siteID != identity.SiteID || tenantID != identity.TenantID {
			return ErrAgentScope
		}
		count++
	}
	if rows.Err() != nil || count != 1 {
		return ErrAgentScope
	}
	return nil
}

// AuthorizeIndividualRequest checks existing desktop records and every requested
// profile/task against the durable enrollment scope. First inventory, hardware
// and configuration requests can arrive before the desktop inventory row exists.
func (m *Model) AuthorizeIndividualRequest(ctx context.Context, identity registry.Identity, operation string, profileID int, taskIDs []int) error {
	a, err := m.Client.Agent.Query().Where(agent.ID(identity.ID)).WithSite(func(q *ent.SiteQuery) { q.WithTenant() }).Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) || (operation != "report" && operation != "agentconfig" && operation != "hardware") {
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
