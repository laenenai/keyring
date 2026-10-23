package local_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laenenai/keyring"
	"github.com/laenenai/keyring/keymanager/local"
	"github.com/laenenai/keyring/keyringtest"
)

// TestLocalKeyManagerConformance is the authoritative test for this
// adapter: the shared contract, unchanged. Everything else in this file
// tests properties specific to *this* adapter's scheme — its root key
// handling, its wire format, its non-deterministic wrapping — which the
// suite deliberately does not assert because another adapter could
// legitimately differ.
func TestLocalKeyManagerConformance(t *testing.T) {
	t.Parallel()

	keyringtest.RunKeyManagerSuite(t, func(t *testing.T) keyring.KeyManager {
		return newKeyManager(t, randomRootKey(t), local.NewMemKEKStore())
	})
}

func TestOpenRejectsUnusableConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatalf("write empty key file: %v", err)
	}
	shortFile := filepath.Join(dir, "short")
	if err := os.WriteFile(shortFile, []byte("too short"), 0o600); err != nil {
		t.Fatalf("write short key file: %v", err)
	}

	cases := []struct {
		name string
		cfg  local.Config
	}{
		{"no_root_key_at_all", local.Config{Store: local.NewMemKEKStore()}},
		{
			"both_root_key_and_root_key_file",
			local.Config{RootKey: randomRootKey(t), RootKeyFile: shortFile, Store: local.NewMemKEKStore()},
		},
		{
			"root_key_too_short",
			local.Config{RootKey: bytes.Repeat([]byte{7}, local.MinRootKeyLen-1), Store: local.NewMemKEKStore()},
		},
		{
			"root_key_all_zero",
			local.Config{RootKey: make([]byte, local.MinRootKeyLen), Store: local.NewMemKEKStore()},
		},
		{"no_store", local.Config{RootKey: randomRootKey(t)}},
		{
			"unreadable_root_key_file",
			local.Config{RootKeyFile: filepath.Join(dir, "does-not-exist"), Store: local.NewMemKEKStore()},
		},
		{"empty_root_key_file", local.Config{RootKeyFile: emptyFile, Store: local.NewMemKEKStore()}},
		{"short_root_key_file", local.Config{RootKeyFile: shortFile, Store: local.NewMemKEKStore()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := local.Open(context.Background(), tc.cfg); !errors.Is(err, keyring.ErrInvalidConfig) {
				t.Fatalf("Open(%s) error = %v, want ErrInvalidConfig", tc.name, err)
			}
		})
	}
}

// TestOpenRejectsUnusableConfigWithoutLeakingTheRootKey: Open's error is the
// one error in this adapter that is handed a root key, and it is returned at
// startup where it is most likely to be logged verbatim.
func TestOpenRejectsUnusableConfigWithoutLeakingTheRootKey(t *testing.T) {
	t.Parallel()

	root := randomRootKey(t)
	_, err := local.Open(context.Background(), local.Config{RootKey: root}) // no store
	if err == nil {
		t.Fatal("Open with no store returned nil error")
	}
	for name, encoded := range map[string]string{
		"raw":    string(root),
		"hex":    hex.EncodeToString(root),
		"base64": base64.StdEncoding.EncodeToString(root),
	} {
		if strings.Contains(err.Error(), encoded) {
			t.Errorf("Open error leaked the root key as %s: %v", name, err)
		}
	}
}

// TestRootKeyFileEncodings pins the documented decode rule for a root key
// file: hex, base64 or raw bytes, each yielding the same key material, so an
// operator who writes the key with xxd, base64 or head -c 32 /dev/urandom
// gets the same deployment either way — and a record wrapped under one form
// unwraps under another.
func TestRootKeyFileEncodings(t *testing.T) {
	t.Parallel()

	root := randomRootKey(t)
	dir := t.TempDir()
	files := map[string][]byte{
		"hex":                 []byte(hex.EncodeToString(root)),
		"hex_with_newline":    []byte(hex.EncodeToString(root) + "\n"),
		"base64":              []byte(base64.StdEncoding.EncodeToString(root)),
		"base64_raw":          []byte(base64.RawStdEncoding.EncodeToString(root)),
		"base64_with_newline": []byte(base64.StdEncoding.EncodeToString(root) + "\n"),
		"raw":                 root,
	}

	store := local.NewMemKEKStore()
	reference := newKeyManager(t, root, store)
	ctx := context.Background()

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	material := bytes.Clone(dek.Bytes())

	wrapped, err := reference.WrapDEK(ctx, "kek-encodings", "key-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	for name, contents := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("write key file: %v", err)
			}

			km, err := local.Open(ctx, local.Config{RootKeyFile: path, Store: store})
			if err != nil {
				t.Fatalf("Open with a %s root key file: %v", name, err)
			}
			got, err := km.UnwrapDEK(ctx, wrapped)
			if err != nil {
				t.Fatalf("UnwrapDEK with a %s root key file: %v", name, err)
			}
			t.Cleanup(got.Destroy)
			if !bytes.Equal(got.Bytes(), material) {
				t.Fatalf("a %s root key file decoded to different key material", name)
			}
		})
	}
}

// TestWrapIsNonDeterministic is an adapter-specific property, not a port
// one: this adapter wraps with AES-256-GCM, where the same key and nonce
// used twice is catastrophic, so each wrap must draw a fresh salt and nonce.
// A deterministic wrapping scheme (RFC 3394 AES-KW, say) would be a
// legitimate adapter, which is why the shared suite does not assert this.
func TestWrapIsNonDeterministic(t *testing.T) {
	t.Parallel()

	km := newKeyManager(t, randomRootKey(t), local.NewMemKEKStore())
	ctx := context.Background()

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	seen := make(map[string]bool, 16)
	for i := range 16 {
		wrapped, err := km.WrapDEK(ctx, "kek-1", "key-1", dek)
		if err != nil {
			t.Fatalf("WrapDEK %d: %v", i, err)
		}
		if seen[string(wrapped.Ciphertext)] {
			t.Fatalf("WrapDEK %d produced a ciphertext seen before: the salt or nonce is being reused", i)
		}
		seen[string(wrapped.Ciphertext)] = true

		got, err := km.UnwrapDEK(ctx, wrapped)
		if err != nil {
			t.Fatalf("UnwrapDEK %d: %v", i, err)
		}
		got.Destroy()
	}
}

// TestCiphertextLayout pins this adapter's committed wire format, because
// records written by one build are read by the next one.
func TestCiphertextLayout(t *testing.T) {
	t.Parallel()

	km := newKeyManager(t, randomRootKey(t), local.NewMemKEKStore())
	ctx := context.Background()

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	wrapped, err := km.WrapDEK(ctx, "kek-1", "key-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if got, want := wrapped.Ciphertext[0], byte(local.WrapFormatVersion); got != want {
		t.Errorf("ciphertext[0] = %#x, want the format version %#x", got, want)
	}
	// 1 format byte + 16-byte salt + 12-byte nonce + 32-byte DEK + 16-byte
	// GCM tag.
	if got, want := len(wrapped.Ciphertext), 1+16+12+keyring.DEKSize+16; got != want {
		t.Errorf("len(ciphertext) = %d, want %d", got, want)
	}

	t.Run("UnknownFormatVersionIsRejected", func(t *testing.T) {
		forged := wrapped
		forged.Ciphertext = bytes.Clone(wrapped.Ciphertext)
		forged.Ciphertext[0] = 0xFE
		if _, err := km.UnwrapDEK(ctx, forged); !errors.Is(err, keyring.ErrUnwrapFailed) {
			t.Fatalf("UnwrapDEK of an unknown format version error = %v, want ErrUnwrapFailed", err)
		}
	})
}

// TestRecordsOutliveTheProcessGivenTheRootKeyAndStore is what makes this
// adapter usable at all: a wrapped DEK is readable by a later process with
// the same root key and the same KEK store. The MemKEKStore here stands in
// for the persistent store a deployment must supply; its own doc comment
// says what happens if one does not.
func TestRecordsOutliveTheProcessGivenTheRootKeyAndStore(t *testing.T) {
	t.Parallel()

	root := randomRootKey(t)
	store := local.NewMemKEKStore()
	ctx := context.Background()

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	material := bytes.Clone(dek.Bytes())

	first := newKeyManager(t, root, store)
	wrapped, err := first.WrapDEK(ctx, "kek-1", "key-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if _, err := first.RotateKEK(ctx, "kek-1"); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}

	// A second key manager over the same inputs: a restarted process.
	second := newKeyManager(t, root, store)
	got, err := second.UnwrapDEK(ctx, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK from a second key manager: %v", err)
	}
	t.Cleanup(got.Destroy)
	if !bytes.Equal(got.Bytes(), material) {
		t.Fatal("a second key manager unwrapped the record to the wrong key material")
	}

	// The rotation is in the store, not in the first manager's memory: the
	// second manager wraps under the rotated version too.
	afterRestart, err := second.WrapDEK(ctx, "kek-1", "key-2", dek)
	if err != nil {
		t.Fatalf("WrapDEK from a second key manager: %v", err)
	}
	if afterRestart.KEKVersion <= wrapped.KEKVersion {
		t.Fatalf("second key manager wrapped under %s, want a version newer than %s",
			afterRestart.KEKVersion, wrapped.KEKVersion)
	}
}

// TestDestroyedKEKIsGoneFromTheStore is the adapter-specific half of
// crypto-shredding: the suite proves a destroyed KEK's DEKs no longer
// unwrap, and this proves the reason is that the key material is *gone*
// rather than that one key manager instance is refusing to use it. A
// destroyed KEK must stay destroyed for a fresh process holding the same
// root key and the same store — otherwise erasure would be undone by a
// restart.
func TestDestroyedKEKIsGoneFromTheStore(t *testing.T) {
	t.Parallel()

	root := randomRootKey(t)
	store := local.NewMemKEKStore()
	ctx := context.Background()

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	km := newKeyManager(t, root, store)
	wrapped, err := km.WrapDEK(ctx, "kek-doomed", "key-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if err := km.DestroyKEK(ctx, "kek-doomed"); err != nil {
		t.Fatalf("DestroyKEK: %v", err)
	}

	if _, err := store.WrappedKEK(ctx, "kek-doomed", wrapped.KEKVersion); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Fatalf("store still answers for a destroyed KEK: error = %v, want ErrKEKDestroyed", err)
	}

	restarted := newKeyManager(t, root, store)
	if _, err := restarted.UnwrapDEK(ctx, wrapped); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Fatalf("UnwrapDEK after a restart error = %v, want ErrKEKDestroyed (erasure must survive a restart)", err)
	}
	if _, err := restarted.WrapDEK(ctx, "kek-doomed", "key-2", dek); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Fatalf("WrapDEK after a restart error = %v, want ErrKEKDestroyed (a shredded KEK is never resurrected)", err)
	}
}

// TestWrongRootKeyCannotUnwrap: the KEK material in the store is itself
// wrapped under the root key, so an attacker holding the store — a stolen
// database backup, CAS design §8.1's threat model — holds nothing usable.
func TestWrongRootKeyCannotUnwrap(t *testing.T) {
	t.Parallel()

	store := local.NewMemKEKStore()
	ctx := context.Background()

	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	wrapped, err := newKeyManager(t, randomRootKey(t), store).WrapDEK(ctx, "kek-1", "key-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	impostor := newKeyManager(t, randomRootKey(t), store)
	got, err := impostor.UnwrapDEK(ctx, wrapped)
	if !errors.Is(err, keyring.ErrUnwrapFailed) {
		t.Fatalf("UnwrapDEK with the wrong root key error = %v, want ErrUnwrapFailed", err)
	}
	if !got.IsZero() {
		t.Fatal("UnwrapDEK with the wrong root key returned key material")
	}
}

// TestMemKEKStoreConformance holds the in-memory store to the shared
// KEKStore contract. The semantics used to be pinned by a test of this one
// implementation, which could not be run against the persistent store CAS
// design §8.3 calls for; they are now a suite, so that store is held to the
// same contract rather than to whatever its author inferred.
func TestMemKEKStoreConformance(t *testing.T) {
	t.Parallel()

	// The factory takes the subtest's own *T so that an implementation can
	// register setup and teardown with it; an in-memory store needs neither,
	// which is why this one ignores it.
	keyringtest.RunKEKStoreSuite(t, func(_ *testing.T) local.KEKStore {
		return local.NewMemKEKStore()
	})
}

// newKeyManager opens a local key manager over root and store, failing the
// test rather than returning an error.
func newKeyManager(t *testing.T, root []byte, store local.KEKStore) keyring.KeyManager {
	t.Helper()
	km, err := local.Open(context.Background(), local.Config{RootKey: root, Store: store})
	if err != nil {
		t.Fatalf("local.Open: %v", err)
	}
	return km
}

// randomRootKey returns a fresh deployment root key.
func randomRootKey(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, local.MinRootKeyLen)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("read a random root key: %v", err)
	}
	return b
}
