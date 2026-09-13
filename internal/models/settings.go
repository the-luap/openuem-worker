package models

import (
	"context"
	"errors"
	"strconv"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/settings"
	"github.com/open-uem/ent/tenant"
	"github.com/open-uem/nats/legacysecret"
)

func (m *Model) GetSettings(t string) (*ent.Settings, error) {
	if t == "" {
		return m.Client.Settings.Query().Where(settings.Not(settings.HasTenant())).Only(context.Background())
	} else {
		tenantID, err := strconv.Atoi(t)
		if err != nil {
			return m.Client.Settings.Query().Where(settings.Not(settings.HasTenant())).Only(context.Background())
		}

		s, err := m.Client.Settings.Query().Where(settings.HasTenantWith(tenant.ID(tenantID))).Only(context.Background())
		if err != nil {
			return m.Client.Settings.Query().Where(settings.Not(settings.HasTenant())).Only(context.Background())
		}
		return s, nil
	}
}

// GetSMTPSettings returns only the global notification configuration. It never
// falls back across organizations and never returns an oversized stored secret.
func (m *Model) GetSMTPSettings(ctx context.Context) (*ent.Settings, error) {
	rows, err := m.DB.QueryContext(ctx, `SELECT id,
 coalesce(octet_length(smtp_server),0)<=253 AND coalesce(octet_length(smtp_user),0)<=1024 AND coalesce(octet_length(message_from),0)<=320 AND coalesce(octet_length(smtp_auth),0)<=32 AND coalesce(octet_length(smtp_encryption_type),0)<=32 AND coalesce(octet_length(smtp_password),0)<=$1,
 CASE WHEN octet_length(smtp_auth)<=32 THEN smtp_auth ELSE '' END,
 CASE WHEN octet_length(smtp_password)<=$1 THEN smtp_password ELSE '' END,coalesce(smtp_port,0),
 CASE WHEN octet_length(smtp_server)<=253 THEN smtp_server ELSE '' END,
 CASE WHEN octet_length(smtp_user)<=1024 THEN smtp_user ELSE '' END,
 CASE WHEN octet_length(message_from)<=320 THEN message_from ELSE '' END,
 CASE WHEN octet_length(smtp_encryption_type)<=32 THEN smtp_encryption_type ELSE '' END
 FROM settings WHERE tenant_settings IS NULL ORDER BY id LIMIT 2`, legacysecret.MaxStoredSize)
	if err != nil {
		return nil, errors.New("SMTP settings are unavailable")
	}
	defer rows.Close()
	var result *ent.Settings
	for rows.Next() {
		if result != nil {
			return nil, errors.New("SMTP settings are ambiguous")
		}
		result = &ent.Settings{}
		var bounded bool
		if err := rows.Scan(&result.ID, &bounded, &result.SMTPAuth, &result.SMTPPassword, &result.SMTPPort, &result.SMTPServer, &result.SMTPUser, &result.MessageFrom, &result.SMTPEncryptionType); err != nil {
			return nil, errors.New("SMTP settings are unavailable")
		}
		if !bounded {
			return nil, errors.New("SMTP settings are unavailable")
		}
	}
	if rows.Err() != nil {
		return nil, errors.New("SMTP settings are unavailable")
	}
	if result == nil {
		return nil, &ent.NotFoundError{}
	}
	return result, nil
}
