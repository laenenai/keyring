package postgres_test

import (
	"context"
	"testing"

	"github.com/laenenai/keyring/keymanager/kekstore"
	"github.com/laenenai/keyring/keyringtest"
	keyringpostgres "github.com/laenenai/keyring/postgres"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const postgresImage = "postgres@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b"

func TestPostgresStoreConforms(t *testing.T) {
	if testing.Short() {
		t.Skip("Postgres conformance requires a container")
	}

	ctx := t.Context()
	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("keyring"),
		tcpostgres.WithUsername("keyring"),
		tcpostgres.WithPassword("keyring"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start Postgres: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate Postgres: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("Postgres connection string: %v", err)
	}
	store, err := keyringpostgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Logf("close store: %v", err)
		}
	})
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	keyringtest.RunKEKStoreSuite(t, func(_ *testing.T) kekstore.KEKStore {
		return store
	})
}
