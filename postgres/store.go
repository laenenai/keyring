// Package postgres provides a durable KEKStore for the local keyring adapter.
//
// It is a separately versioned companion module so the core keyring module
// stays free of database drivers. The store keeps only wrapped KEK material:
// the root key is never sent here, so a stolen database backup is useless
// without the root key.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	// Register the pgx database/sql driver used by Open.
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/laenenai/keyring/internal/domain"
	"github.com/laenenai/keyring/keymanager/kekstore"
)

// Schema creates the tables this store uses. Migrate applies it idempotently.
const Schema = `
CREATE TABLE IF NOT EXISTS keyring_keks (
	id text PRIMARY KEY,
	destroyed_at timestamptz
);

CREATE TABLE IF NOT EXISTS keyring_kek_versions (
	kek_id text NOT NULL REFERENCES keyring_keks (id) ON DELETE CASCADE,
	version bigint NOT NULL CHECK (version > 0),
	wrapped bytea NOT NULL,
	PRIMARY KEY (kek_id, version)
);
`

// Store is a Postgres-backed kekstore.KEKStore. It is safe for concurrent
// use through database/sql's connection pool.
type Store struct {
	db *sql.DB
}

// Open opens a Postgres connection pool and verifies it is reachable. It does
// not create the schema; call Migrate (or apply Schema in your migration
// system) before using the store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("keyring/postgres: open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("keyring/postgres: connect: %w", err)
	}
	return &Store{db: db}, nil
}

// New returns a store over an existing database handle. The caller owns the
// handle and must not close it while the store is in use.
func New(db *sql.DB) *Store { return &Store{db: db} }

// Close closes the underlying connection pool.
func (s *Store) Close() error { return s.db.Close() }

// Migrate creates the store's tables. It is safe to run repeatedly.
func (s *Store) Migrate(ctx context.Context) error {
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS keyring_keks (
			id text PRIMARY KEY,
			destroyed_at timestamptz
		)`,
		`CREATE TABLE IF NOT EXISTS keyring_kek_versions (
			kek_id text NOT NULL REFERENCES keyring_keks (id) ON DELETE CASCADE,
			version bigint NOT NULL CHECK (version > 0),
			wrapped bytea NOT NULL,
			PRIMARY KEY (kek_id, version)
		)`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("keyring/postgres: migrate: %w", err)
		}
	}
	return nil
}

// CreateKEKVersion implements kekstore.KEKStore.
func (s *Store) CreateKEKVersion(ctx context.Context, id domain.KEKID, version domain.KEKVersion, wrapped []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring/postgres: create KEK version: %w", err)
	}
	if err := id.Validate(); err != nil {
		return err
	}
	if err := version.Validate(); err != nil {
		return err
	}
	if len(wrapped) == 0 {
		return fmt.Errorf("%w: no wrapped KEK material to store", domain.ErrInvalidKeyMaterial)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("keyring/postgres: begin create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO keyring_keks (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`,
		string(id)); err != nil {
		return fmt.Errorf("keyring/postgres: create KEK row: %w", err)
	}

	var destroyedAt *time.Time
	if err := tx.QueryRowContext(ctx,
		`SELECT destroyed_at FROM keyring_keks WHERE id = $1 FOR UPDATE`,
		string(id)).Scan(&destroyedAt); err != nil {
		return fmt.Errorf("keyring/postgres: lock KEK row: %w", err)
	}
	if destroyedAt != nil {
		return fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
	}

	result, err := tx.ExecContext(ctx,
		`INSERT INTO keyring_kek_versions (kek_id, version, wrapped)
		 VALUES ($1, $2, $3) ON CONFLICT (kek_id, version) DO NOTHING`,
		string(id), uint64(version), wrapped)
	if err != nil {
		return fmt.Errorf("keyring/postgres: insert KEK version: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("keyring/postgres: inspect KEK version insert: %w", err)
	}
	if inserted == 0 {
		return fmt.Errorf("%w: %s %s", kekstore.ErrKEKVersionExists, id, version)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("keyring/postgres: commit create: %w", err)
	}
	return nil
}

// CurrentKEKVersion implements kekstore.KEKStore.
func (s *Store) CurrentKEKVersion(ctx context.Context, id domain.KEKID) (domain.KEKVersion, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("keyring/postgres: read current KEK version: %w", err)
	}
	if err := id.Validate(); err != nil {
		return 0, err
	}

	var destroyedAt *time.Time
	var current *int64
	err := s.db.QueryRowContext(ctx, `
		SELECT k.destroyed_at, MAX(v.version)
		FROM keyring_keks AS k
		LEFT JOIN keyring_kek_versions AS v ON v.kek_id = k.id
		WHERE k.id = $1
		GROUP BY k.destroyed_at`, string(id)).Scan(&destroyedAt, &current)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: %s", domain.ErrKEKNotFound, id)
	}
	if err != nil {
		return 0, fmt.Errorf("keyring/postgres: read current KEK version: %w", err)
	}
	if destroyedAt != nil {
		return 0, fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
	}
	if current == nil || *current <= 0 || *current > math.MaxUint32 {
		return 0, fmt.Errorf("%w: %s has no usable versions", domain.ErrKEKNotFound, id)
	}
	return domain.KEKVersion(*current), nil
}

// WrappedKEK implements kekstore.KEKStore.
func (s *Store) WrappedKEK(ctx context.Context, id domain.KEKID, version domain.KEKVersion) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keyring/postgres: read wrapped KEK: %w", err)
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if err := version.Validate(); err != nil {
		return nil, err
	}

	var destroyedAt *time.Time
	var wrapped []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT k.destroyed_at, v.wrapped
		FROM keyring_keks AS k
		JOIN keyring_kek_versions AS v ON v.kek_id = k.id
		WHERE k.id = $1 AND v.version = $2`,
		string(id), uint64(version)).Scan(&destroyedAt, &wrapped)
	if err == nil {
		if destroyedAt != nil {
			return nil, fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
		}
		return wrapped, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("keyring/postgres: read wrapped KEK: %w", err)
	}

	// Distinguish destroyed, absent KEK, and absent version.
	var kekDestroyed *time.Time
	err = s.db.QueryRowContext(ctx,
		`SELECT destroyed_at FROM keyring_keks WHERE id = $1`, string(id)).Scan(&kekDestroyed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("%w: %s", domain.ErrKEKNotFound, id)
	case err != nil:
		return nil, fmt.Errorf("keyring/postgres: read KEK state: %w", err)
	case kekDestroyed != nil:
		return nil, fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
	default:
		return nil, fmt.Errorf("%w: %s %s", domain.ErrKEKNotFound, id, version)
	}
}

// DestroyKEK implements kekstore.KEKStore.
func (s *Store) DestroyKEK(ctx context.Context, id domain.KEKID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring/postgres: destroy KEK: %w", err)
	}
	if err := id.Validate(); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("keyring/postgres: begin destroy: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var destroyedAt *time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT destroyed_at FROM keyring_keks WHERE id = $1 FOR UPDATE`,
		string(id)).Scan(&destroyedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: %s", domain.ErrKEKNotFound, id)
	case err != nil:
		return fmt.Errorf("keyring/postgres: lock KEK row: %w", err)
	case destroyedAt != nil:
		return nil
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE keyring_keks SET destroyed_at = now() WHERE id = $1`, string(id)); err != nil {
		return fmt.Errorf("keyring/postgres: mark KEK destroyed: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM keyring_kek_versions WHERE kek_id = $1`, string(id)); err != nil {
		return fmt.Errorf("keyring/postgres: erase KEK material: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("keyring/postgres: commit destroy: %w", err)
	}
	return nil
}
