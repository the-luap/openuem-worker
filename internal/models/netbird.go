package models

import (
	"context"
	"database/sql"
	"errors"
	"github.com/open-uem/ent"
	"github.com/open-uem/nats/legacysecret"
)

func (m *Model) GetNetbirdSettings(ctx context.Context, tenantID int) (*ent.NetbirdSettings, error) {
	if tenantID <= 0 {
		return nil, errors.New("NetBird organization is unavailable")
	}
	result := &ent.NetbirdSettings{}
	var bounded bool
	err := m.DB.QueryRowContext(ctx, `SELECT n.id,coalesce(octet_length(n.management_url),0)<=2048 AND coalesce(octet_length(n.access_token),0)<=$2,
 CASE WHEN octet_length(n.management_url)<=2048 THEN n.management_url ELSE '' END,
 CASE WHEN octet_length(n.access_token)<=$2 THEN n.access_token ELSE '' END
 FROM netbird_settings n JOIN tenants t ON t.tenant_netbird=n.id WHERE t.id=$1`, tenantID, legacysecret.MaxStoredSize).Scan(&result.ID, &bounded, &result.ManagementURL, &result.AccessToken)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &ent.NotFoundError{}
	}
	if err != nil || !bounded {
		return nil, errors.New("NetBird settings are unavailable")
	}
	return result, nil
}
