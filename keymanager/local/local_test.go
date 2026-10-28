package local_test

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
			local.Config{RootKey: randomRootKey(t), RootKeyFile: shortFile, RootKeyEncoding: local.RootKeyEncodingRaw, Store: local.NewMemKEKStore()},
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
			local.Config{RootKeyFile: filepath.Join(dir, "does-not-exist"), RootKeyEncoding: local.RootKeyEncodingRaw, Store: local.NewMemKEKStore()},
		},
		{"empty_root_key_file", local.Config{RootKeyFile: emptyFile, RootKeyEncoding: local.RootKeyEncodingRaw, Store: local.NewMemKEKStore()}},
		{"short_root_key_file", local.Config{RootKeyFile: shortFile, RootKeyEncoding: local.RootKeyEncodingRaw, Store: local.NewMemKEKStore()}},
		{"root_key_file_missing_encoding", local.Config{RootKeyFile: shortFile, Store: local.NewMemKEKStore()}},
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
	files := map[string]struct {
		contents []byte
		encoding local.RootKeyEncoding
	}{
		"hex":                 {[]byte(hex.EncodeToString(root)), local.RootKeyEncodingHex},
		"hex_with_newline":    {[]byte(hex.EncodeToString(root) + "\n"), local.RootKeyEncodingHex},
		"base64":              {[]byte(base64.StdEncoding.EncodeToString(root)), local.RootKeyEncodingBase64},
		"base64_raw":          {[]byte(base64.RawStdEncoding.EncodeToString(root)), local.RootKeyEncodingBase64},
		"base64_with_newline": {[]byte(base64.StdEncoding.EncodeToString(root) + "\n"), local.RootKeyEncodingBase64},
		"raw":                 {root, local.RootKeyEncodingRaw},
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

	for name, file := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, file.contents, 0o600); err != nil {
				t.Fatalf("write key file: %v", err)
			}

			km, err := local.Open(ctx, local.Config{
				RootKeyFile:     path,
				RootKeyEncoding: file.encoding,
				Store:           store,
			})
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

// TestRootKeyFileRejectsMalformedInput pins the explicit-encoding rule. A
// truncated hex/base64 key or an unlabelled text file must fail at Open rather
// than silently use different material. Raw is byte-for-byte: a 42-byte file
// is a valid raw key, not a mistake to reinterpret.
func TestRootKeyFileRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := bytes.Repeat([]byte{0x5A}, local.MinRootKeyLen)
	hexKey := hex.EncodeToString(root)
	base64Key := base64.StdEncoding.EncodeToString(root)

	cases := []struct {
		name     string
		contents []byte
		encoding local.RootKeyEncoding
		wantErr  bool
	}{
		{"missing_encoding", []byte(hexKey), "", true},
		{"truncated_hex", []byte(hexKey[:len(hexKey)-1]), local.RootKeyEncodingHex, true},
		{"internal_space_hex", []byte(hexKey[:32] + " " + hexKey[32:]), local.RootKeyEncodingHex, true},
		{"truncated_base64", []byte(base64Key[:len(base64Key)-2]), local.RootKeyEncodingBase64, true},
		{"internal_newline_base64", []byte(base64Key[:20] + "\n" + base64Key[20:]), local.RootKeyEncodingBase64, true},
		{"raw_without_encoding", root, "", true},
		{"raw_exact_42_bytes", bytes.Repeat([]byte("a"), 42), local.RootKeyEncodingRaw, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, tc.contents, 0o600); err != nil {
				t.Fatalf("write key file: %v", err)
			}
			_, err := local.Open(context.Background(), local.Config{
				RootKeyFile:     path,
				RootKeyEncoding: tc.encoding,
				Store:           local.NewMemKEKStore(),
			})
			if tc.wantErr {
				if !errors.Is(err, keyring.ErrInvalidConfig) {
					t.Fatalf("Open(%s) error = %v, want ErrInvalidConfig", tc.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open(%s): %v", tc.name, err)
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

// TestConfigAndKeyManagerRedactTheRootKeyInEveryRendering is a regression
// test for a real leak. local.Config carries the deployment root key in an
// exported RootKey field and had no rendering methods at all, so
// fmt.Sprintf("%v", cfg) printed the key's bytes and json.Marshal(cfg)
// emitted them as base64 — the encoding most likely to survive being pasted
// into an issue. local.KeyManager retains the wrapping key derived from it
// and had no methods either.
//
// A configuration struct logged at startup is the normal thing for a caller
// to do, which is what makes this the leak that matters rather than a
// theoretical one.
func TestConfigAndKeyManagerRedactTheRootKeyInEveryRendering(t *testing.T) {
	t.Parallel()

	root := randomRootKey(t)
	cfg := local.Config{
		RootKey:     root,
		RootKeyFile: "",
		Store:       local.NewMemKEKStore(),
	}

	t.Run("Config", func(t *testing.T) {
		keyringtest.NoSecretLeaksInAnyRendering(t, cfg, root)
	})

	km, err := local.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Run("KeyManager", func(t *testing.T) {
		// The manager does not retain the root key — Open zeroizes its copy
		// once the wrapping key is derived — but the root key is what an
		// operator would search a log for, and the derived key is material
		// in its own right, so both are off limits.
		keyringtest.NoSecretLeaksInAnyRendering(t, km, root)
	})
}

// TestConfigDoesNotLeakTheRootKeyThroughXMLOrGob: fmt, json and slog are not
// the only encoders a caller may use. XML and gob consult their own interfaces
// and see the exported RootKey field unless the type redacts them explicitly.
func TestConfigDoesNotLeakTheRootKeyThroughXMLOrGob(t *testing.T) {
	t.Parallel()

	root := bytes.Repeat([]byte{'A'}, local.MinRootKeyLen)
	cfg := local.Config{RootKey: root}

	x, err := xml.Marshal(cfg)
	if err != nil {
		t.Fatalf("xml.Marshal: %v", err)
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cfg); err != nil {
		t.Fatalf("gob.Encode: %v", err)
	}

	for name, rendering := range map[string]string{
		"xml": string(x),
		"gob": buf.String(),
	} {
		for label, encoded := range map[string]string{
			"raw":    string(root),
			"hex":    hex.EncodeToString(root),
			"base64": base64.StdEncoding.EncodeToString(root),
		} {
			if strings.Contains(rendering, encoded) {
				t.Errorf("%s leaked the root key as %s: %q", name, label, rendering)
			}
		}
		if !strings.Contains(rendering, keyring.Redacted) {
			t.Errorf("%s does not contain a redaction marker: %q", name, rendering)
		}
	}
}

// TestKeyManagerValueRedactsTheDerivedWrappingKey: redaction must survive a
// dereference/copy of the manager. A caller that logs *km or puts a manager
// value in a struct does not get the pointer method set, and fmt then reflects
// the unexported wrapKey bytes.
func TestKeyManagerValueRedactsTheDerivedWrappingKey(t *testing.T) {
	t.Parallel()

	root := randomRootKey(t)
	km, err := local.Open(context.Background(), local.Config{
		RootKey: root,
		Store:   local.NewMemKEKStore(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	wrapKey, err := hkdf.Key(sha256.New, root, nil, "keyring/local/root-wrap/v1", local.MinRootKeyLen)
	if err != nil {
		t.Fatalf("derive expected wrapping key: %v", err)
	}
	t.Cleanup(func() { clear(wrapKey) })

	for name, rendering := range map[string]string{
		"value %v":  fmt.Sprintf("%v", *km),
		"value %+v": fmt.Sprintf("%+v", *km),
		"value %#v": fmt.Sprintf("%#v", *km),
	} {
		for label, encoded := range map[string]string{
			"raw":      string(wrapKey),
			"go slice": fmt.Sprintf("%v", wrapKey),
			"hex":      hex.EncodeToString(wrapKey),
			"base64":   base64.StdEncoding.EncodeToString(wrapKey),
		} {
			if strings.Contains(rendering, encoded) {
				t.Errorf("%s leaked the derived wrapping key as %s: %s", name, label, rendering)
			}
		}
		if !strings.Contains(rendering, keyring.Redacted) {
			t.Errorf("%s does not contain a redaction marker: %s", name, rendering)
		}
	}
}

func TestWrongAdapterFormatIsRejected(t *testing.T) {
	t.Parallel()

	km := newKeyManager(t, randomRootKey(t), local.NewMemKEKStore())
	ctx := context.Background()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	wrapped, err := km.WrapDEK(ctx, "kek-format", "key-1", dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	wrapped.Format = keyring.WrappedDEKFormatOpenBaoTransit
	if _, err := km.UnwrapDEK(ctx, wrapped); !errors.Is(err, keyring.ErrInvalidWrappedDEK) {
		t.Fatalf("UnwrapDEK(wrong format) = %v, want ErrInvalidWrappedDEK", err)
	}
	if _, err := km.RewrapDEK(ctx, wrapped); !errors.Is(err, keyring.ErrInvalidWrappedDEK) {
		t.Fatalf("RewrapDEK(wrong format) = %v, want ErrInvalidWrappedDEK", err)
	}
}

type blockingStore struct {
	local.KEKStore
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingStore) CurrentKEKVersion(ctx context.Context, id keyring.KEKID) (keyring.KEKVersion, error) {
	if id == "kek-race" {
		s.once.Do(func() { close(s.started) })
		<-s.release
	}
	return s.KEKStore.CurrentKEKVersion(ctx, id)
}

func TestDestroyWaitsForInFlightWrap(t *testing.T) {
	t.Parallel()

	store := &blockingStore{
		KEKStore: local.NewMemKEKStore(),
		started:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	km := newKeyManager(t, randomRootKey(t), store)
	ctx := context.Background()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	wrapDone := make(chan error, 1)
	go func() {
		_, err := km.WrapDEK(ctx, "kek-race", "key-1", dek)
		wrapDone <- err
	}()
	<-store.started

	destroyDone := make(chan error, 1)
	go func() { destroyDone <- km.DestroyKEK(ctx, "kek-race") }()
	select {
	case err := <-destroyDone:
		t.Fatalf("DestroyKEK completed while a wrap held the KEK: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(store.release)
	if err := <-wrapDone; err != nil {
		t.Fatalf("WrapDEK that started before destroy: %v", err)
	}
	if err := <-destroyDone; err != nil {
		t.Fatalf("DestroyKEK: %v", err)
	}
	if _, err := km.UnwrapDEK(ctx, keyring.WrappedDEK{
		KEKID:      "kek-race",
		KEKVersion: keyring.FirstKEKVersion,
		KeyID:      "key-1",
		Ciphertext: []byte("whatever"),
	}); !errors.Is(err, keyring.ErrKEKDestroyed) {
		t.Fatalf("UnwrapDEK after destroy = %v, want ErrKEKDestroyed", err)
	}
}

func TestCloseRejectsFurtherUseAndIsIdempotent(t *testing.T) {
	t.Parallel()

	km := newKeyManager(t, randomRootKey(t), local.NewMemKEKStore())
	closer, ok := km.(interface{ Close() error })
	if !ok {
		t.Fatal("local.KeyManager does not implement Close")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	if _, err := km.WrapDEK(context.Background(), "kek-closed", "key-1", dek); !errors.Is(err, keyring.ErrClosed) {
		t.Fatalf("WrapDEK after Close = %v, want ErrClosed", err)
	}
}

func TestCloseDoesNotRaceInFlightOperations(t *testing.T) {
	t.Parallel()

	km := newKeyManager(t, randomRootKey(t), local.NewMemKEKStore())
	closer, ok := km.(interface{ Close() error })
	if !ok {
		t.Fatal("local.KeyManager does not implement Close")
	}
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for range 100 {
			_, _ = km.WrapDEK(context.Background(), "kek-close-race", "key-1", dek)
		}
	}()
	close(start)
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done
}
