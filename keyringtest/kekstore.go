package keyringtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/kekstore"
)

// RunKEKStoreSuite runs the contract every kekstore.KEKStore implementation must
// satisfy. newStore is called once per subtest, receiving that subtest's own
// *T, so an implementation that needs per-test setup and teardown (a schema,
// a transaction that rolls back, a connection pool) registers it with
// t.Cleanup inside newStore and every subtest gets fresh, isolated state.
// Each subtest also mints its own KEK ids, so an implementation whose backing
// store is shared across subtests never has two of them collide.
//
// The store is the one component of the local adapter whose failure mode is
// total rather than gradual: a KEK that vanishes takes every DEK wrapped
// under it, and therefore every byte those DEKs encrypted, with it. CAS
// design §8.3 puts the real one in Postgres, and this suite exists so that
// implementation is held to exactly what local.MemKEKStore does rather than
// to whatever its author inferred — the semantics were previously pinned only
// by a test of the in-memory store, which could not be run against anything
// else.
//
// Nothing here inspects how material is stored or encoded. The store sees
// only ciphertext and must hand back the same bytes; that it cannot read them
// is what makes a stolen database backup useless (CAS design §8.1), and it is
// also why this suite stores byte sequences that are not valid UTF-8 and not
// null-free: an implementation that put them in a text column would pass a
// test written with friendlier fixtures and corrupt real key material.
func RunKEKStoreSuite(t *testing.T, newStore func(t *testing.T) kekstore.KEKStore) {
	t.Helper()

	t.Run("AbsentKEKIsErrKEKNotFound", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		absent := newKEKID(t)

		if _, err := store.CurrentKEKVersion(ctx, absent); !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Errorf("CurrentKEKVersion(absent) error = %v, want ErrKEKNotFound", err)
		}
		if _, err := store.WrappedKEK(ctx, absent, keyring.FirstKEKVersion); !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Errorf("WrappedKEK(absent) error = %v, want ErrKEKNotFound", err)
		}
		// An erasure certificate records which keys were destroyed, so
		// destroying a KEK that never existed must not report success.
		if err := store.DestroyKEK(ctx, absent); !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Errorf("DestroyKEK(absent) error = %v, want ErrKEKNotFound", err)
		}
	})

	t.Run("StoredMaterialComesBackByteIdentical", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		id := newKEKID(t)
		material := awkwardMaterial()

		if err := store.CreateKEKVersion(ctx, id, keyring.FirstKEKVersion, material); err != nil {
			t.Fatalf("CreateKEKVersion: %v", err)
		}
		got, err := store.WrappedKEK(ctx, id, keyring.FirstKEKVersion)
		if err != nil {
			t.Fatalf("WrappedKEK: %v", err)
		}
		if !bytes.Equal(got, material) {
			t.Fatalf("WrappedKEK returned %d bytes that differ from the %d stored", len(got), len(material))
		}

		// The returned slice is the caller's own: a store that handed out its
		// own buffer would have its key material zeroized by the first caller
		// that cleared what it was given, and the adapter does clear it.
		clear(got)
		again, err := store.WrappedKEK(ctx, id, keyring.FirstKEKVersion)
		if err != nil {
			t.Fatalf("WrappedKEK after mutating an earlier result: %v", err)
		}
		if !bytes.Equal(again, material) {
			t.Fatal("mutating the bytes returned by WrappedKEK changed the stored record")
		}

		// And the store must not retain the caller's buffer either: the
		// adapter zeroizes what it passed in once the call returns.
		passed := bytes.Clone(material)
		second := keyring.KEKVersion(2)
		if err := store.CreateKEKVersion(ctx, id, second, passed); err != nil {
			t.Fatalf("CreateKEKVersion(v2): %v", err)
		}
		clear(passed)
		stored, err := store.WrappedKEK(ctx, id, second)
		if err != nil {
			t.Fatalf("WrappedKEK(v2): %v", err)
		}
		if !bytes.Equal(stored, material) {
			t.Fatal("zeroizing the buffer passed to CreateKEKVersion destroyed the stored record")
		}
	})

	// CreateKEKVersionIsCreateOnly is the rule that keeps a rotation race from
	// destroying data. Two processes that decide to create or rotate the same
	// KEK at the same instant must not both win: if the loser's material
	// overwrote the winner's, every record the winner had already wrapped
	// under that version would be permanently unreadable.
	t.Run("CreateKEKVersionIsCreateOnly", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		id := newKEKID(t)
		first := []byte("the first material, which must survive")
		second := []byte("the second material, which must be refused")

		if err := store.CreateKEKVersion(ctx, id, keyring.FirstKEKVersion, first); err != nil {
			t.Fatalf("CreateKEKVersion: %v", err)
		}
		if err := store.CreateKEKVersion(ctx, id, keyring.FirstKEKVersion, second); !errors.Is(err, kekstore.ErrKEKVersionExists) {
			t.Fatalf("CreateKEKVersion of an existing version error = %v, want ErrKEKVersionExists", err)
		}
		got, err := store.WrappedKEK(ctx, id, keyring.FirstKEKVersion)
		if err != nil {
			t.Fatalf("WrappedKEK: %v", err)
		}
		if !bytes.Equal(got, first) {
			t.Fatal("a refused CreateKEKVersion overwrote the stored material anyway")
		}
	})

	t.Run("CurrentKEKVersionIsTheHighestStored", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		id := newKEKID(t)
		material := []byte("material")

		// Created out of order on purpose: "current" is the highest version,
		// not the most recently written one, so an implementation that
		// remembered the last write would be wrong here.
		for _, version := range []keyring.KEKVersion{1, 3, 2} {
			if err := store.CreateKEKVersion(ctx, id, version, material); err != nil {
				t.Fatalf("CreateKEKVersion(%s): %v", version, err)
			}
		}
		current, err := store.CurrentKEKVersion(ctx, id)
		if err != nil {
			t.Fatalf("CurrentKEKVersion: %v", err)
		}
		if current != keyring.KEKVersion(3) {
			t.Errorf("CurrentKEKVersion = %s, want v3 (the highest stored version)", current)
		}

		if _, err := store.WrappedKEK(ctx, id, keyring.KEKVersion(9)); !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Errorf("WrappedKEK(version that was never created) error = %v, want ErrKEKNotFound", err)
		}
	})

	t.Run("ListKEKVersionsIsAscending", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		id := newKEKID(t)
		material := []byte("material")
		for _, version := range []keyring.KEKVersion{3, 1, 2} {
			if err := store.CreateKEKVersion(ctx, id, version, material); err != nil {
				t.Fatalf("CreateKEKVersion(%s): %v", version, err)
			}
		}
		versions, err := store.ListKEKVersions(ctx, id)
		if err != nil {
			t.Fatalf("ListKEKVersions: %v", err)
		}
		want := []keyring.KEKVersion{1, 2, 3}
		if len(versions) != len(want) {
			t.Fatalf("ListKEKVersions = %v, want %v", versions, want)
		}
		for i := range want {
			if versions[i] != want[i] {
				t.Fatalf("ListKEKVersions = %v, want %v", versions, want)
			}
		}
	})

	// DestructionIsTerminal is the store's half of crypto-shredding. The
	// material must be gone rather than flagged, and the fact must outlive it:
	// every method naming a destroyed KEK answers ErrKEKDestroyed forever,
	// CreateKEKVersion included, so a destroyed KEK is never resurrected under
	// its own name and a later unwrap of a pre-shredding record cannot be
	// confused with a post-shredding one.
	t.Run("DestructionIsTerminal", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		id := newKEKID(t)
		material := []byte("material")

		for _, version := range []keyring.KEKVersion{1, 2} {
			if err := store.CreateKEKVersion(ctx, id, version, material); err != nil {
				t.Fatalf("CreateKEKVersion(%s): %v", version, err)
			}
		}
		if err := store.DestroyKEK(ctx, id); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		// Repeated, because there must be no retry, cache expiry or reconnect
		// that brings the material back.
		for attempt := range 3 {
			checks := []struct {
				name string
				err  error
			}{
				{"CurrentKEKVersion", errorFrom(func() error { _, err := store.CurrentKEKVersion(ctx, id); return err })},
				{"WrappedKEK(v1)", errorFrom(func() error { _, err := store.WrappedKEK(ctx, id, 1); return err })},
				{"WrappedKEK(v2)", errorFrom(func() error { _, err := store.WrappedKEK(ctx, id, 2); return err })},
				{"CreateKEKVersion(v3)", store.CreateKEKVersion(ctx, id, 3, material)},
			}
			for _, check := range checks {
				if !errors.Is(check.err, keyring.ErrKEKDestroyed) {
					t.Errorf("%s after DestroyKEK (attempt %d) error = %v, want ErrKEKDestroyed",
						check.name, attempt+1, check.err)
				}
			}
		}

		// Destroying an already-destroyed KEK is nil, so a retried erasure job
		// converges rather than failing forever on its own success.
		if err := store.DestroyKEK(ctx, id); err != nil {
			t.Errorf("second DestroyKEK = %v, want nil (destruction is idempotent)", err)
		}
	})

	t.Run("DestructionIsScopedToOneKEK", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		doomed, survivor := newKEKID(t), newKEKID(t)
		material := []byte("material")

		if err := store.CreateKEKVersion(ctx, doomed, keyring.FirstKEKVersion, material); err != nil {
			t.Fatalf("CreateKEKVersion(doomed): %v", err)
		}
		if err := store.CreateKEKVersion(ctx, survivor, keyring.FirstKEKVersion, material); err != nil {
			t.Fatalf("CreateKEKVersion(survivor): %v", err)
		}
		if err := store.DestroyKEK(ctx, doomed); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		got, err := store.WrappedKEK(ctx, survivor, keyring.FirstKEKVersion)
		if err != nil {
			t.Fatalf("WrappedKEK(survivor) after destroying another KEK: %v", err)
		}
		if !bytes.Equal(got, material) {
			t.Fatal("destroying one KEK corrupted another's material")
		}
	})

	// EmptyMaterialIsRejected: the store is the last place that can tell the
	// difference between "a wrapped KEK" and "nothing", and a stored empty
	// record would be read back later as a KEK version that exists and
	// decrypts to nothing.
	t.Run("EmptyMaterialIsRejected", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()

		for name, material := range map[string][]byte{"nil": nil, "empty": {}} {
			t.Run(name, func(t *testing.T) {
				id := newKEKID(t)
				if err := store.CreateKEKVersion(ctx, id, keyring.FirstKEKVersion, material); !errors.Is(err, keyring.ErrInvalidKeyMaterial) {
					t.Fatalf("CreateKEKVersion(%s material) error = %v, want ErrInvalidKeyMaterial", name, err)
				}
				// And it must not have created the KEK on the way to failing.
				if _, err := store.CurrentKEKVersion(ctx, id); !errors.Is(err, keyring.ErrKEKNotFound) {
					t.Fatalf("CurrentKEKVersion after a refused create error = %v, want ErrKEKNotFound", err)
				}
			})
		}
	})

	// ConcurrentCreatesOfOneVersionHaveOneWinner is the property the
	// create-only rule exists for, exercised rather than assumed: whether it
	// is enforced by a mutex or by a unique constraint, exactly one caller
	// must win and the material that ends up stored must be the winner's.
	t.Run("ConcurrentCreatesOfOneVersionHaveOneWinner", func(t *testing.T) {
		store := newStore(t)
		ctx := context.Background()
		id := newKEKID(t)

		const goroutines = 8
		candidates := make([][]byte, goroutines)
		errs := make([]error, goroutines)
		var wg sync.WaitGroup
		for i := range goroutines {
			candidates[i] = []byte(fmt.Sprintf("material from goroutine %d", i))
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = store.CreateKEKVersion(ctx, id, keyring.FirstKEKVersion, candidates[i])
			}()
		}
		wg.Wait()

		winners := 0
		winner := -1
		for i, err := range errs {
			switch {
			case err == nil:
				winners++
				winner = i
			case errors.Is(err, kekstore.ErrKEKVersionExists):
			default:
				t.Errorf("goroutine %d: CreateKEKVersion error = %v, want nil or ErrKEKVersionExists", i, err)
			}
		}
		if winners != 1 {
			t.Fatalf("%d of %d concurrent CreateKEKVersion calls succeeded, want exactly 1", winners, goroutines)
		}

		stored, err := store.WrappedKEK(ctx, id, keyring.FirstKEKVersion)
		if err != nil {
			t.Fatalf("WrappedKEK: %v", err)
		}
		if !bytes.Equal(stored, candidates[winner]) {
			t.Fatal("the stored material is not the material of the call that succeeded")
		}
	})

	t.Run("CancelledContextIsRespected", func(t *testing.T) {
		store := newStore(t)
		id := newKEKID(t)
		material := []byte("material")

		if err := store.CreateKEKVersion(context.Background(), id, keyring.FirstKEKVersion, material); err != nil {
			t.Fatalf("CreateKEKVersion: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		checks := []struct {
			name string
			err  error
		}{
			{"CreateKEKVersion", store.CreateKEKVersion(ctx, newKEKID(t), keyring.FirstKEKVersion, material)},
			{"CurrentKEKVersion", errorFrom(func() error { _, err := store.CurrentKEKVersion(ctx, id); return err })},
			{"WrappedKEK", errorFrom(func() error { _, err := store.WrappedKEK(ctx, id, keyring.FirstKEKVersion); return err })},
			{"DestroyKEK", store.DestroyKEK(ctx, id)},
		}
		for _, check := range checks {
			if !errors.Is(check.err, context.Canceled) {
				t.Errorf("%s with a cancelled context: error = %v, want context.Canceled", check.name, check.err)
			}
		}
	})
}

// awkwardMaterial returns bytes a store must carry unchanged and that a store
// which treated them as text would mangle: a null byte, invalid UTF-8, and a
// byte that a naive escaping layer would quote.
func awkwardMaterial() []byte {
	material := []byte{0x01, 0x00, 0xFF, 0xFE, '\'', '"', '\\', '\n', 0x7F, 0x80}
	for b := range 256 {
		material = append(material, byte(b))
	}
	return material
}

// errorFrom runs call and returns its error, so a two-result method can be
// listed in a table of checks alongside a one-result one.
func errorFrom(call func() error) error { return call() }
