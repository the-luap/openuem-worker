package models

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
	ent "github.com/open-uem/ent"
)

type Model struct {
	Client *ent.Client
	DB     *sql.DB
}

func New(dbUrl string) (*Model, error) {
	model := Model{}

	db, err := sql.Open("pgx", dbUrl)
	if err != nil {
		return nil, fmt.Errorf("could not connect with Postgres database: %v", err)
	}

	model.Client = ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	model.DB = db

	// TODO Automatic migrations only in development
	ctx := context.Background()
	if os.Getenv("ENV") != "prod" {
		// Startup must not remove columns or indexes owned by additive identity
		// migrations or another component version in a rolling deployment.
		if err := model.Client.Schema.Create(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	return &model, nil
}

func (m *Model) Close() {
	m.Client.Close()
}
