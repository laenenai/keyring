package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/laenen-ai/keyring/internal/domain"
)

// ErrKEKVersionExists is returned by KEKStore.CreateKEKVersion when the
// named (KEK, version) pair is already stored. It is the store's optimistic
// concurrency signal: two processes that decide to create or rotate the same
// KEK at the same instant must not both win, and the loser re-reads the
// current version rather than overwriting the winner's key material — which
// would make every record the winner wrapped unreadable.
var ErrKEKVersionExists = errors.New("keyring/local: KEK version already exists")

// KEKStore is where this adapter keeps KEK material, wrapped under the
// deployment root key, and the record of which KEKs have been destroyed. It
// is a port rather than a fixed implementation because the material has to
// outlive the process — a KEK that vanishes takes every DEK wrapped under it
// with it — and where a deployment keeps it (Postgres, in CAS design §8.3's
// case) is not this module's business.
//
// Implementations must be safe for concurrent use. They see only ciphertext:
// the wrapped bytes are opaque, and a store that is fully compromised yields
// nothing without the root key, which is the property that makes a stolen
// database backup useless (CAS design §8.1).
//
// Three rules an implementation must hold, which MemKEKStore's behavior and
// local_test.go's TestMemKEKStoreSemantics pin exactly:
//
//  1. Destruction is terminal. Once DestroyKEK has been called for a KEK id,
//     every method naming that id returns domain.ErrKEKDestroyed forever —
//     CreateKEKVersion included, so a destroyed KEK is never resurrected
//     under its own name — and the stored material is gone, not flagged.
//  2. A KEK that was never created is domain.ErrKEKNotFound, which is a
//     different fact from destroyed and must stay distinguishable.
//  3. CreateKEKVersion is create-only: an existing (id, version) is
//     ErrKEKVersionExists, never an overwrite.
type KEKStore interface {
	// CreateKEKVersion stores wrapped as the material for version of the
	// KEK named by id, creating the KEK if this is its first version. It
	// returns ErrKEKVersionExists if that version is already stored, and
	// domain.ErrKEKDestroyed if the KEK has been destroyed.
	CreateKEKVersion(ctx context.Context, id domain.KEKID, version domain.KEKVersion, wrapped []byte) error

	// CurrentKEKVersion returns the highest stored version of the KEK named
	// by id: domain.ErrKEKNotFound if it has no versions, and
	// domain.ErrKEKDestroyed if it has been destroyed.
	CurrentKEKVersion(ctx context.Context, id domain.KEKID) (domain.KEKVersion, error)

	// WrappedKEK returns the stored material for one version of one KEK:
	// domain.ErrKEKNotFound if that KEK or that version is not stored, and
	// domain.ErrKEKDestroyed if the KEK has been destroyed. The returned
	// slice is the caller's own; mutating it must not affect the store.
	WrappedKEK(ctx context.Context, id domain.KEKID, version domain.KEKVersion) ([]byte, error)

	// DestroyKEK erases the material for every version of the KEK named by
	// id and records the destruction permanently. It returns
	// domain.ErrKEKNotFound for a KEK that was never created — an erasure
	// certificate must not be able to claim a key was destroyed when
	// nothing happened — and nil for one already destroyed, so a retried
	// erasure job converges.
	DestroyKEK(ctx context.Context, id domain.KEKID) error
}

// MemKEKStore is an in-memory KEKStore.
//
// It is the right store for tests, for the conformance suite, and for a
// process whose encrypted data does not outlive it. It is the wrong store
// for anything else, and the failure mode is total rather than gradual: when
// the process exits, every KEK goes with it, and every DEK wrapped under
// those KEKs — and therefore every byte of content those DEKs encrypted —
// becomes permanently unreadable. That is crypto-shredding by accident. A
// deployment that stores content must supply a persistent KEKStore.
//
// It is safe for concurrent use.
type MemKEKStore struct {
	mu   sync.RWMutex
	keks map[domain.KEKID]*memKEK
}

// memKEK is one KEK's stored state: its wrapped material per version, and
// whether it has been destroyed. A destroyed KEK keeps its entry — with no
// material — because "destroyed" is a fact that must survive, and survive
// distinguishably from "never existed".
type memKEK struct {
	versions  map[domain.KEKVersion][]byte
	destroyed bool
}

// NewMemKEKStore returns an empty in-memory KEKStore. Read MemKEKStore's doc
// comment before using it anywhere content is persisted.
func NewMemKEKStore() *MemKEKStore {
	return &MemKEKStore{keks: make(map[domain.KEKID]*memKEK)}
}

// CreateKEKVersion implements KEKStore.
func (s *MemKEKStore) CreateKEKVersion(ctx context.Context, id domain.KEKID, version domain.KEKVersion, wrapped []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring/local: create KEK version: %w", err)
	}
	if len(wrapped) == 0 {
		return fmt.Errorf("%w: no wrapped KEK material to store", domain.ErrInvalidKeyMaterial)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	kek, ok := s.keks[id]
	switch {
	case ok && kek.destroyed:
		return fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
	case !ok:
		kek = &memKEK{versions: make(map[domain.KEKVersion][]byte)}
		s.keks[id] = kek
	}
	if _, exists := kek.versions[version]; exists {
		return fmt.Errorf("%w: %s %s", ErrKEKVersionExists, id, version)
	}
	kek.versions[version] = bytes.Clone(wrapped)
	return nil
}

// CurrentKEKVersion implements KEKStore.
func (s *MemKEKStore) CurrentKEKVersion(ctx context.Context, id domain.KEKID) (domain.KEKVersion, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("keyring/local: read current KEK version: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	kek, ok := s.keks[id]
	switch {
	case !ok:
		return 0, fmt.Errorf("%w: %s", domain.ErrKEKNotFound, id)
	case kek.destroyed:
		return 0, fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
	case len(kek.versions) == 0:
		return 0, fmt.Errorf("%w: %s has no versions", domain.ErrKEKNotFound, id)
	}
	return slices.Max(slices.Collect(maps.Keys(kek.versions))), nil
}

// WrappedKEK implements KEKStore.
func (s *MemKEKStore) WrappedKEK(ctx context.Context, id domain.KEKID, version domain.KEKVersion) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keyring/local: read wrapped KEK: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	kek, ok := s.keks[id]
	switch {
	case !ok:
		return nil, fmt.Errorf("%w: %s", domain.ErrKEKNotFound, id)
	case kek.destroyed:
		return nil, fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, id)
	}
	wrapped, ok := kek.versions[version]
	if !ok {
		return nil, fmt.Errorf("%w: %s %s", domain.ErrKEKNotFound, id, version)
	}
	return bytes.Clone(wrapped), nil
}

// DestroyKEK implements KEKStore.
func (s *MemKEKStore) DestroyKEK(ctx context.Context, id domain.KEKID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring/local: destroy KEK: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	kek, ok := s.keks[id]
	if !ok {
		return fmt.Errorf("%w: %s", domain.ErrKEKNotFound, id)
	}
	if kek.destroyed {
		return nil
	}
	// Zeroize before dropping the references: the material is wrapped, but
	// leaving a copy of it on the heap for the garbage collector to get to
	// eventually is not what "destroyed" should mean.
	for version, wrapped := range kek.versions {
		clear(wrapped)
		delete(kek.versions, version)
	}
	kek.destroyed = true
	return nil
}
