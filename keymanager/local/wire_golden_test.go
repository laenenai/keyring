package local_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/local"
)

// TestWireFormatGolden pins a record written by the v1 local format. The
// fixture was generated once from the committed layout; changing the HKDF
// info, AAD prefixes, header layout or format version must be a deliberate
// migration, not an invisible compatibility break.
func TestWireFormatGolden(t *testing.T) {
	t.Parallel()

	const (
		kekRecordHex = "01101112131415161718191a1b1c1d1e1f202122232425262728292a2b5f62db3efe977268f7fe06046bbe1457332d957d0b6f5e3506bcd00347198fe822d8cc411619679c6802c9b8c64f5699"
		dekRecordHex = "01303132333435363738393a3b3c3d3e3f404142434445464748494a4bc28e05729316241a20be8e51642fed2f1bb458c780989b7ca06d485728597520819a760e5f2a4e1eb0b3fdc0237a15bd"
	)
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i + 1)
	}
	kekRecord, err := hex.DecodeString(kekRecordHex)
	if err != nil {
		t.Fatalf("decode KEK fixture: %v", err)
	}
	dekRecord, err := hex.DecodeString(dekRecordHex)
	if err != nil {
		t.Fatalf("decode DEK fixture: %v", err)
	}
	store := local.NewMemKEKStore()
	if err := store.CreateKEKVersion(context.Background(), keyring.KEKID("kek-golden"), keyring.FirstKEKVersion, kekRecord); err != nil {
		t.Fatalf("store fixture KEK: %v", err)
	}
	km, err := local.Open(context.Background(), local.Config{RootKey: root, Store: store})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := km.UnwrapDEK(context.Background(), keyring.WrappedDEK{
		KEKID:      "kek-golden",
		KEKVersion: keyring.FirstKEKVersion,
		KeyID:      "key-golden",
		Format:     keyring.WrappedDEKFormatLocal,
		Ciphertext: dekRecord,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK of the v1 fixture: %v", err)
	}
	defer got.Destroy()
	want := make([]byte, keyring.DEKSize)
	for i := range want {
		want[i] = byte(0x61 + i)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatal("the v1 fixture unwrapped to different key material")
	}
}
