package kekstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/kekstore"
	"github.com/laenenai/keyring/keyringtest"
)

func TestMemKEKStoreConformance(t *testing.T) {
	keyringtest.RunKEKStoreSuite(t, func(_ *testing.T) kekstore.KEKStore {
		return kekstore.NewMemKEKStore()
	})
}

func TestZeroValueMemKEKStoreIsUsable(t *testing.T) {
	t.Parallel()

	var store kekstore.MemKEKStore
	ctx := context.Background()
	if err := store.CreateKEKVersion(ctx, "kek-zero", 1, []byte("material")); err != nil {
		t.Fatalf("CreateKEKVersion on zero value: %v", err)
	}
	got, err := store.WrappedKEK(ctx, "kek-zero", 1)
	if err != nil {
		t.Fatalf("WrappedKEK: %v", err)
	}
	if string(got) != "material" {
		t.Fatalf("WrappedKEK = %q", got)
	}
}

func TestMemKEKStoreValidatesIdentifiers(t *testing.T) {
	t.Parallel()

	store := kekstore.NewMemKEKStore()
	if err := store.CreateKEKVersion(context.Background(), "", 1, []byte("x")); !errors.Is(err, keyring.ErrInvalidIdentifier) {
		t.Fatalf("CreateKEKVersion(empty id) = %v, want ErrInvalidIdentifier", err)
	}
	if err := store.CreateKEKVersion(context.Background(), "k", 0, []byte("x")); !errors.Is(err, keyring.ErrInvalidIdentifier) {
		t.Fatalf("CreateKEKVersion(version 0) = %v, want ErrInvalidIdentifier", err)
	}
}

func TestMemKEKStoreListsVersionsInOrder(t *testing.T) {
	t.Parallel()

	store := kekstore.NewMemKEKStore()
	ctx := context.Background()
	for _, version := range []keyring.KEKVersion{3, 1, 2} {
		if err := store.CreateKEKVersion(ctx, "kek-list", version, []byte("x")); err != nil {
			t.Fatalf("CreateKEKVersion(%s): %v", version, err)
		}
	}
	got, err := store.ListKEKVersions(ctx, "kek-list")
	if err != nil {
		t.Fatalf("ListKEKVersions: %v", err)
	}
	want := []keyring.KEKVersion{1, 2, 3}
	if len(got) != len(want) {
		t.Fatalf("ListKEKVersions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ListKEKVersions = %v, want %v", got, want)
		}
	}
}
