// Package keyringtest holds the conformance suites for the keyring module:
// the authoritative, executable description of what this module's ports must
// do. An interface says what the operations are called; the suites here say
// what they mean, including every edge an interface cannot state — what fails
// closed, what is idempotent, which errors are deliberately uninformative,
// and what a destroyed KEK does to the DEKs wrapped under it.
//
// There are two, one per port:
//
//   - RunKeyManagerSuite, for keyring.KeyManager. Every adapter passes it:
//     the in-process AES-GCM one, the OpenBao transit one, and an adapter a
//     consumer writes against its own KMS.
//   - RunKEKStoreSuite, for kekstore.KEKStore, where the local adapter keeps
//     wrapped KEK material. It exists so that the persistent implementation
//     CAS design §8.3 calls for is held to exactly what the in-memory one
//     does.
//
// It is a sibling package rather than a suite.go inside keymanager for two
// reasons, both forced (see CONVENTIONS.md). Identifiers in _test.go files
// are not importable from another module, and CHARTER.md defines adoption as
// this suite running green in a consumer's own CI against the consumer's own
// wiring — so the suite cannot be test-only. But a non-test file that
// imports testing would put testing in the production import graph of every
// consumer that imports the port, so it cannot live beside the port either.
// httptest is to http what this package is to keyring.
//
// An adapter's own test file is one function long:
//
//	func TestMyKeyManagerConformance(t *testing.T) {
//		keyringtest.RunKeyManagerSuite(t, func(t *testing.T) keyring.KeyManager {
//			return myAdapter(t)
//		})
//	}
package keyringtest

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/laenenai/keyring"
)

// RunKeyManagerSuite runs the contract every KeyManager adapter must
// satisfy. newKM is called once per subtest, receiving that subtest's own
// *T, so an adapter that needs per-test setup and teardown (a fresh root
// key, a scratch transit mount, a transaction that rolls back) can register
// it with t.Cleanup inside newKM and get fresh, isolated state for every
// subtest.
//
// Each subtest also mints its own KEK ids, so an adapter whose backend is
// shared across subtests — a single OpenBao instance, one KMS account —
// never has two subtests collide on the same key.
//
// Every assertion here must hold for any key manager — an in-process AES-GCM
// wrapper, OpenBao's transit engine, AWS KMS, a tenant's HSM. Nothing here
// inspects an adapter's wire format, its storage, or its key derivation.
// Properties that are true of one wrapping scheme but not another belong in
// that adapter's own test file: the local adapter's non-deterministic
// ciphertext (a fresh nonce per wrap) is tested in local/local_test.go
// precisely because a deterministic scheme such as RFC 3394 AES-KW would be
// a legitimate adapter that this suite must not reject.
func RunKeyManagerSuite(t *testing.T, newKM func(t *testing.T) keyring.KeyManager) {
	t.Helper()

	t.Run("WrapUnwrapRoundTrip", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())

		wrapped, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}
		if err := wrapped.Validate(); err != nil {
			t.Fatalf("WrapDEK returned a record that does not validate: %v", err)
		}
		if wrapped.Format == keyring.WrappedDEKFormatLegacy {
			t.Error("WrapDEK returned a record without an adapter format")
		}
		if wrapped.KEKID != kekID {
			t.Errorf("wrapped.KEKID = %q, want %q", wrapped.KEKID, kekID)
		}
		if wrapped.KeyID != keyID {
			t.Errorf("wrapped.KeyID = %q, want %q", wrapped.KeyID, keyID)
		}
		if wrapped.KEKVersion < keyring.FirstKEKVersion {
			t.Errorf("wrapped.KEKVersion = %s, want at least %s", wrapped.KEKVersion, keyring.FirstKEKVersion)
		}

		// The one thing a "wrapped" DEK must never be is the DEK. An
		// adapter that stored the key verbatim (or base64'd it) would pass
		// a naive round-trip test and fail here.
		assertNoKeyMaterial(t, "wrapped ciphertext", string(wrapped.Ciphertext), material)

		// WrapDEK does not take ownership: the caller's DEK is still live
		// and unchanged afterwards.
		if err := dek.Validate(); err != nil {
			t.Errorf("caller's DEK after WrapDEK: Validate() = %v, want nil (WrapDEK must not destroy it)", err)
		}
		if !bytes.Equal(dek.Bytes(), material) {
			t.Error("WrapDEK modified the caller's DEK")
		}

		got, err := km.UnwrapDEK(ctx, wrapped)
		if err != nil {
			t.Fatalf("UnwrapDEK: %v", err)
		}
		t.Cleanup(got.Destroy)
		if err := got.Validate(); err != nil {
			t.Fatalf("UnwrapDEK returned unusable key material: %v", err)
		}
		if !bytes.Equal(got.Bytes(), material) {
			t.Fatal("unwrapped DEK does not match the DEK that was wrapped")
		}
	})

	t.Run("UnwrapReturnsIndependentlyOwnedDEKs", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())
		wrapped, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		first, err := km.UnwrapDEK(ctx, wrapped)
		if err != nil {
			t.Fatalf("first UnwrapDEK: %v", err)
		}
		second, err := km.UnwrapDEK(ctx, wrapped)
		if err != nil {
			t.Fatalf("second UnwrapDEK: %v", err)
		}
		t.Cleanup(second.Destroy)

		// Destroying one unwrapped DEK must not reach into the other, nor
		// into anything the adapter caches: an adapter that returns a
		// shared buffer would hand the next caller a zeroized key.
		first.Destroy()
		if !bytes.Equal(second.Bytes(), material) {
			t.Fatal("destroying one unwrapped DEK invalidated another unwrap of the same record")
		}

		third, err := km.UnwrapDEK(ctx, wrapped)
		if err != nil {
			t.Fatalf("UnwrapDEK after destroying an earlier result: %v", err)
		}
		t.Cleanup(third.Destroy)
		if !bytes.Equal(third.Bytes(), material) {
			t.Fatal("unwrap after destroying an earlier result returned the wrong key material")
		}
	})

	// GenerateDEKMintsAKeyInsideTheKeyManager covers the method that exists
	// so a caller never has to mint key material itself: the DEK is produced
	// by the key manager — from the key store's own entropy, where there is
	// one — and comes back together with the record to persist.
	t.Run("GenerateDEKMintsAKeyInsideTheKeyManager", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek, wrapped, err := km.GenerateDEK(ctx, kekID, keyID)
		if err != nil {
			t.Fatalf("GenerateDEK: %v", err)
		}
		t.Cleanup(dek.Destroy)
		if err := dek.Validate(); err != nil {
			t.Fatalf("GenerateDEK returned unusable key material: %v", err)
		}
		material := bytes.Clone(dek.Bytes())

		if err := wrapped.Validate(); err != nil {
			t.Fatalf("GenerateDEK returned a record that does not validate: %v", err)
		}
		if wrapped.Format == keyring.WrappedDEKFormatLegacy {
			t.Error("GenerateDEK returned a record without an adapter format")
		}
		if wrapped.KEKID != kekID {
			t.Errorf("wrapped.KEKID = %q, want %q", wrapped.KEKID, kekID)
		}
		if wrapped.KeyID != keyID {
			t.Errorf("wrapped.KeyID = %q, want %q", wrapped.KeyID, keyID)
		}
		// The KEK did not exist before this call: GenerateDEK creates it, on
		// the same terms as WrapDEK does.
		if wrapped.KEKVersion < keyring.FirstKEKVersion {
			t.Errorf("wrapped.KEKVersion = %s, want at least %s", wrapped.KEKVersion, keyring.FirstKEKVersion)
		}
		assertNoKeyMaterial(t, "GenerateDEK ciphertext", string(wrapped.Ciphertext), material)

		// The record round-trips, which is the only thing that makes the
		// returned DEK useful: a caller encrypts with the DEK, stores the
		// record, and must get the same key back.
		got, err := km.UnwrapDEK(ctx, wrapped)
		if err != nil {
			t.Fatalf("UnwrapDEK of a GenerateDEK record: %v", err)
		}
		t.Cleanup(got.Destroy)
		if !bytes.Equal(got.Bytes(), material) {
			t.Fatal("the record GenerateDEK returned unwrapped to different key material than the DEK it returned")
		}

		// And the record names the KEK's current version, so a GenerateDEK
		// after a rotation is wrapped under the new one.
		rotated, err := km.RotateKEK(ctx, kekID)
		if err != nil {
			t.Fatalf("RotateKEK: %v", err)
		}
		afterRotation, nextWrapped, err := km.GenerateDEK(ctx, kekID, newKeyID(t))
		if err != nil {
			t.Fatalf("GenerateDEK after RotateKEK: %v", err)
		}
		t.Cleanup(afterRotation.Destroy)
		if nextWrapped.KEKVersion != rotated {
			t.Errorf("GenerateDEK after RotateKEK recorded %s, want the new current version %s",
				nextWrapped.KEKVersion, rotated)
		}
	})

	// GenerateDEKReturnsIndependentlyOwnedDEKs is the same ownership rule
	// UnwrapDEK has, asserted here too because a key manager that minted DEKs
	// from a shared buffer — or handed out the same key twice — would be a
	// catastrophic adapter that a single-call test cannot detect.
	t.Run("GenerateDEKReturnsIndependentlyOwnedDEKs", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID := newKEKID(t)

		first, firstRecord, err := km.GenerateDEK(ctx, kekID, newKeyID(t))
		if err != nil {
			t.Fatalf("first GenerateDEK: %v", err)
		}
		second, secondRecord, err := km.GenerateDEK(ctx, kekID, newKeyID(t))
		if err != nil {
			t.Fatalf("second GenerateDEK: %v", err)
		}
		t.Cleanup(second.Destroy)

		if first.Equal(second) {
			t.Fatal("two GenerateDEK calls returned the same key material")
		}
		secondMaterial := bytes.Clone(second.Bytes())

		// Destroying one must not reach into the other, nor into anything the
		// adapter kept: these are two independent secrets.
		first.Destroy()
		if !bytes.Equal(second.Bytes(), secondMaterial) {
			t.Fatal("destroying one generated DEK invalidated another")
		}

		// Both records still open, and to the keys they were generated with:
		// destroying the caller's copy of a DEK says nothing about the record.
		reopened, err := km.UnwrapDEK(ctx, secondRecord)
		if err != nil {
			t.Fatalf("UnwrapDEK of the second record: %v", err)
		}
		t.Cleanup(reopened.Destroy)
		if !bytes.Equal(reopened.Bytes(), secondMaterial) {
			t.Fatal("the second record unwrapped to the wrong key material")
		}
		stillGood, err := km.UnwrapDEK(ctx, firstRecord)
		if err != nil {
			t.Fatalf("UnwrapDEK of the first record after destroying its DEK: %v", err)
		}
		t.Cleanup(stillGood.Destroy)
		if stillGood.IsZero() {
			t.Fatal("the first record unwrapped to no key material after its generated DEK was destroyed")
		}
	})

	t.Run("GenerateDEKFailsClosed", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		destroyed := newKEKID(t)
		if _, _, err := km.GenerateDEK(ctx, destroyed, keyID); err != nil {
			t.Fatalf("GenerateDEK under the KEK about to be destroyed: %v", err)
		}
		if err := km.DestroyKEK(ctx, destroyed); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		cases := []struct {
			name    string
			kekID   keyring.KEKID
			keyID   keyring.KeyID
			wantErr error
		}{
			{"empty_kek_id", "", keyID, keyring.ErrInvalidIdentifier},
			{"empty_key_id", kekID, "", keyring.ErrInvalidIdentifier},
			{"kek_id_with_separator", "a/b", keyID, keyring.ErrInvalidIdentifier},
			{"key_id_with_null_byte", kekID, keyring.KeyID("a\x00b"), keyring.ErrInvalidIdentifier},
			{"over_long_kek_id", keyring.KEKID(strings.Repeat("x", 257)), keyID, keyring.ErrInvalidIdentifier},
			// A shredded KEK is never resurrected, by any door: generating a
			// DEK under one must fail exactly as wrapping under one does.
			{"destroyed_kek", destroyed, keyID, keyring.ErrKEKDestroyed},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dek, wrapped, err := km.GenerateDEK(ctx, tc.kekID, tc.keyID)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("GenerateDEK(%s) error = %v, want %v", tc.name, err, tc.wantErr)
				}
				assertNoDEKReturned(t, "GenerateDEK("+tc.name+")", dek)
				if len(wrapped.Ciphertext) != 0 {
					t.Fatalf("GenerateDEK(%s) returned a record despite failing", tc.name)
				}
			})
		}
	})

	t.Run("DistinctKeyIDsUnderOneKEKAreIndependent", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID := newKEKID(t)

		type record struct {
			wrapped keyring.WrappedDEK
			//redact:plain — a canary this subtest searches renderings for,
			// not material a running system holds; see redactlint's
			// -include-tests and CONVENTIONS.md's "Rendering a secret".
			material []byte
		}
		records := make([]record, 0, 3)
		for range 3 {
			dek := newDEK(t)
			material := bytes.Clone(dek.Bytes())
			wrapped, err := km.WrapDEK(ctx, kekID, newKeyID(t), dek)
			if err != nil {
				t.Fatalf("WrapDEK: %v", err)
			}
			records = append(records, record{wrapped: wrapped, material: material})
		}

		for i, rec := range records {
			got, err := km.UnwrapDEK(ctx, rec.wrapped)
			if err != nil {
				t.Fatalf("UnwrapDEK(record %d): %v", i, err)
			}
			if !bytes.Equal(got.Bytes(), rec.material) {
				t.Fatalf("record %d unwrapped to the wrong key material", i)
			}
			got.Destroy()
		}
	})

	t.Run("UnwrapOfUnknownKEKIsErrKEKNotFound", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()

		dek := newDEK(t)
		wrapped, err := km.WrapDEK(ctx, newKEKID(t), newKeyID(t), dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		// A record whose ciphertext is real but whose KEK was never
		// created: the adapter has nothing to decrypt it with and must say
		// so, rather than reporting a generic failure a caller cannot act
		// on (a missing KEK is an operational fault; a failed unwrap is a
		// trust fault).
		unknown := relabel(wrapped, func(w *keyring.WrappedDEK) { w.KEKID = newKEKID(t) })
		got, err := km.UnwrapDEK(ctx, unknown)
		if !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Fatalf("UnwrapDEK(unknown KEK) error = %v, want ErrKEKNotFound", err)
		}
		assertNoDEKReturned(t, "UnwrapDEK(unknown KEK)", got)
	})

	t.Run("RotateKEKOfUnknownKEKIsErrKEKNotFound", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()

		if _, err := km.RotateKEK(ctx, newKEKID(t)); !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Fatalf("RotateKEK(unknown KEK) error = %v, want ErrKEKNotFound (rotation is not creation)", err)
		}
	})

	t.Run("DestroyKEKOfUnknownKEKIsErrKEKNotFound", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()

		// An erasure certificate records which keys were destroyed, so
		// "destroy a KEK that never existed" must not report success.
		if err := km.DestroyKEK(ctx, newKEKID(t)); !errors.Is(err, keyring.ErrKEKNotFound) {
			t.Fatalf("DestroyKEK(unknown KEK) error = %v, want ErrKEKNotFound", err)
		}
	})

	t.Run("RotateKEKProducesStrictlyIncreasingVersionsAndWrapsUnderTheLatest", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID := newKEKID(t)

		dek := newDEK(t)
		first, err := km.WrapDEK(ctx, kekID, newKeyID(t), dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		previous := first.KEKVersion
		for i := range 3 {
			rotated, err := km.RotateKEK(ctx, kekID)
			if err != nil {
				t.Fatalf("RotateKEK %d: %v", i+1, err)
			}
			if rotated <= previous {
				t.Fatalf("RotateKEK %d returned %s, want a version greater than %s", i+1, rotated, previous)
			}

			wrapped, err := km.WrapDEK(ctx, kekID, newKeyID(t), dek)
			if err != nil {
				t.Fatalf("WrapDEK after RotateKEK %d: %v", i+1, err)
			}
			if wrapped.KEKVersion != rotated {
				t.Fatalf("WrapDEK after RotateKEK %d recorded %s, want the new current version %s",
					i+1, wrapped.KEKVersion, rotated)
			}
			previous = rotated
		}
	})

	// DEKWrappedUnderOldKEKVersionStillUnwrapsAfterRotation is the security
	// invariant that makes rotation affordable, and it is a hard requirement
	// of CAS design §8.3 rather than an optimization: because every wrapped
	// DEK records the KEK version that wrapped it, rotating a KEK is adding
	// a version and (at most, lazily) re-wrapping these small records. An
	// adapter that could only unwrap under the KEK's *current* version would
	// force every byte of content under that KEK to be read, decrypted and
	// re-encrypted on every rotation — which in practice means rotation
	// never happens.
	t.Run("DEKWrappedUnderOldKEKVersionStillUnwrapsAfterRotation", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())
		old, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		v2, err := km.RotateKEK(ctx, kekID)
		if err != nil {
			t.Fatalf("RotateKEK: %v", err)
		}
		if v2 <= old.KEKVersion {
			t.Fatalf("RotateKEK returned %s, want greater than %s", v2, old.KEKVersion)
		}

		// The whole point: the v1 record is untouched on disk and still
		// opens, after one rotation and after a second.
		got, err := km.UnwrapDEK(ctx, old)
		if err != nil {
			t.Fatalf("UnwrapDEK of a %s record after rotation to %s: %v", old.KEKVersion, v2, err)
		}
		if !bytes.Equal(got.Bytes(), material) {
			t.Fatal("record wrapped under the old KEK version unwrapped to the wrong key material")
		}

		if _, err := km.RotateKEK(ctx, kekID); err != nil {
			t.Fatalf("second RotateKEK: %v", err)
		}
		stillOld, err := km.UnwrapDEK(ctx, old)
		if err != nil {
			t.Fatalf("UnwrapDEK of a %s record after two rotations: %v", old.KEKVersion, err)
		}
		if !bytes.Equal(stillOld.Bytes(), material) {
			t.Fatal("record wrapped under the first KEK version unwrapped to the wrong key material after two rotations")
		}

		// Lazy re-wrapping, the only migration rotation requires: unwrap
		// the old record, wrap it again, and the new record names the
		// current version while the DEK — and therefore the content it
		// encrypted — is unchanged.
		rewrapped, err := km.WrapDEK(ctx, kekID, keyID, stillOld)
		if err != nil {
			t.Fatalf("re-wrap under the current version: %v", err)
		}
		stillOld.Destroy()
		got.Destroy()
		if rewrapped.KEKVersion <= old.KEKVersion {
			t.Fatalf("re-wrapped record records %s, want a version newer than %s", rewrapped.KEKVersion, old.KEKVersion)
		}
		final, err := km.UnwrapDEK(ctx, rewrapped)
		if err != nil {
			t.Fatalf("UnwrapDEK of the re-wrapped record: %v", err)
		}
		t.Cleanup(final.Destroy)
		if !bytes.Equal(final.Bytes(), material) {
			t.Fatal("re-wrapping changed the DEK, which would have required re-encrypting the content")
		}
	})

	// RewrapDEKMovesARecordToTheLatestKEKVersion is what makes CAS design
	// §8.3's "KEK rotation is lazy re-wrapping rather than re-encrypting
	// content" an operation this port actually offers. The previous subtest
	// proves the unwrap-then-wrap version of it is possible; this one proves
	// the port has a first-class method for it, which is the only form a key
	// manager can perform without the DEK leaving the key store.
	t.Run("RewrapDEKMovesARecordToTheLatestKEKVersion", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())
		v1Record, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		v2, err := km.RotateKEK(ctx, kekID)
		if err != nil {
			t.Fatalf("RotateKEK: %v", err)
		}
		if v2 <= v1Record.KEKVersion {
			t.Fatalf("RotateKEK returned %s, want greater than %s", v2, v1Record.KEKVersion)
		}

		v2Record, err := km.RewrapDEK(ctx, v1Record)
		if err != nil {
			t.Fatalf("RewrapDEK: %v", err)
		}
		if err := v2Record.Validate(); err != nil {
			t.Fatalf("RewrapDEK returned a record that does not validate: %v", err)
		}
		if v2Record.KEKVersion != v2 {
			t.Errorf("RewrapDEK recorded %s, want the KEK's current version %s", v2Record.KEKVersion, v2)
		}
		if v2Record.KEKID != kekID || v2Record.KeyID != keyID {
			t.Errorf("RewrapDEK returned kek=%q key=%q, want kek=%q key=%q",
				v2Record.KEKID, v2Record.KeyID, kekID, keyID)
		}
		if bytes.Equal(v2Record.Ciphertext, v1Record.Ciphertext) {
			t.Error("RewrapDEK returned the input ciphertext unchanged; nothing was re-wrapped")
		}

		// The point of the whole exercise: the DEK is the same one, so the
		// content it encrypted is not re-encrypted.
		got, err := km.UnwrapDEK(ctx, v2Record)
		if err != nil {
			t.Fatalf("UnwrapDEK of the rewrapped record: %v", err)
		}
		t.Cleanup(got.Destroy)
		if !bytes.Equal(got.Bytes(), material) {
			t.Fatal("the rewrapped record unwrapped to different key material; re-wrapping must not change the DEK")
		}

		// Re-wrapping is a new record, not a destructive migration: the old
		// one is still on disk and still opens, so a caller can write the new
		// record and only then forget the old one.
		stillOld, err := km.UnwrapDEK(ctx, v1Record)
		if err != nil {
			t.Fatalf("UnwrapDEK of the original record after RewrapDEK: %v", err)
		}
		t.Cleanup(stillOld.Destroy)
		if !bytes.Equal(stillOld.Bytes(), material) {
			t.Fatal("RewrapDEK invalidated the record it was given")
		}

		// A record already at the latest version is re-wrapped, not rejected:
		// a lazy rotation job walks records it cannot cheaply filter, and the
		// second pass over one must converge rather than error.
		again, err := km.RewrapDEK(ctx, v2Record)
		if err != nil {
			t.Fatalf("RewrapDEK of a record already at the current version: %v", err)
		}
		if again.KEKVersion != v2 {
			t.Errorf("RewrapDEK at the current version recorded %s, want %s", again.KEKVersion, v2)
		}
		final, err := km.UnwrapDEK(ctx, again)
		if err != nil {
			t.Fatalf("UnwrapDEK of the twice-rewrapped record: %v", err)
		}
		t.Cleanup(final.Destroy)
		if !bytes.Equal(final.Bytes(), material) {
			t.Fatal("re-wrapping twice changed the DEK")
		}
	})

	// RewrapDEKNeverYieldsPlaintext is the security invariant that is the
	// reason RewrapDEK is a port method at all rather than sugar for
	// unwrap-then-wrap. OpenBao transit's rewrap endpoint never returns
	// plaintext, which is what makes it safe to hand a lazy rotation job a
	// token that can rewrap but not decrypt; a port method that was defined as
	// unwrap-then-wrap would throw that away, and an adapter implemented that
	// way cannot be told apart from a correct one except by the properties
	// asserted here and — for the transit adapter, which is the one where it
	// matters — by that adapter's own test that no response body on the path
	// contains the DEK.
	t.Run("RewrapDEKNeverYieldsPlaintext", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())
		record, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		destroyedKEK := newKEKID(t)
		if _, err := km.WrapDEK(ctx, destroyedKEK, keyID, dek); err != nil {
			t.Fatalf("WrapDEK under the KEK about to be destroyed: %v", err)
		}
		shredded := relabel(record, func(w *keyring.WrappedDEK) { w.KEKID = destroyedKEK })
		if err := km.DestroyKEK(ctx, destroyedKEK); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		// Every path through RewrapDEK, successful or not: the DEK must not
		// appear in the record it returns, in the error it returns, or in any
		// rendering of either. RewrapDEK's signature is the structural half of
		// the invariant — there is no DEK in it to return — and these
		// assertions are the half a wrong implementation could still fail.
		paths := []struct {
			name string
			call func() (keyring.WrappedDEK, error)
		}{
			{"latest_version", func() (keyring.WrappedDEK, error) { return km.RewrapDEK(ctx, record) }},
			{"after_rotation", func() (keyring.WrappedDEK, error) {
				if _, err := km.RotateKEK(ctx, kekID); err != nil {
					return keyring.WrappedDEK{}, err
				}
				return km.RewrapDEK(ctx, record)
			}},
			{"unknown_kek", func() (keyring.WrappedDEK, error) {
				return km.RewrapDEK(ctx, relabel(record, func(w *keyring.WrappedDEK) { w.KEKID = newKEKID(t) }))
			}},
			{"destroyed_kek", func() (keyring.WrappedDEK, error) { return km.RewrapDEK(ctx, shredded) }},
			{"tampered_ciphertext", func() (keyring.WrappedDEK, error) {
				return km.RewrapDEK(ctx, relabel(record, func(w *keyring.WrappedDEK) { w.Ciphertext[0] ^= 0xFF }))
			}},
			{"moved_key_id", func() (keyring.WrappedDEK, error) {
				return km.RewrapDEK(ctx, relabel(record, func(w *keyring.WrappedDEK) { w.KeyID = newKeyID(t) }))
			}},
			{"empty_ciphertext", func() (keyring.WrappedDEK, error) {
				return km.RewrapDEK(ctx, relabel(record, func(w *keyring.WrappedDEK) { w.Ciphertext = nil }))
			}},
		}
		for _, path := range paths {
			t.Run(path.name, func(t *testing.T) {
				rewrapped, err := path.call()
				assertNoKeyMaterial(t, "RewrapDEK("+path.name+") ciphertext", string(rewrapped.Ciphertext), material)
				assertNoKeyMaterial(t, "RewrapDEK("+path.name+") record rendering", rewrapped.String(), material)
				if err == nil {
					return
				}
				for label, rendering := range map[string]string{
					"Error()": err.Error(),
					"%v":      fmt.Sprintf("%v", err),
					"%+v":     fmt.Sprintf("%+v", err),
					"%s":      fmt.Sprintf("%s", err),
				} {
					assertNoKeyMaterial(t, "RewrapDEK("+path.name+") error rendered with "+label, rendering, material)
				}
			})
		}
	})

	t.Run("RewrapDEKFailsClosed", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		record, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}
		rotated, err := km.RotateKEK(ctx, kekID)
		if err != nil {
			t.Fatalf("RotateKEK: %v", err)
		}

		destroyedKEK := newKEKID(t)
		if _, err := km.WrapDEK(ctx, destroyedKEK, keyID, dek); err != nil {
			t.Fatalf("WrapDEK under the KEK about to be destroyed: %v", err)
		}
		if err := km.DestroyKEK(ctx, destroyedKEK); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		cases := []struct {
			name     string
			mutate   func(w *keyring.WrappedDEK)
			wantErrs []error
		}{
			{"empty_kek_id", func(w *keyring.WrappedDEK) { w.KEKID = "" }, []error{keyring.ErrInvalidIdentifier}},
			{"empty_key_id", func(w *keyring.WrappedDEK) { w.KeyID = "" }, []error{keyring.ErrInvalidIdentifier}},
			{"zero_kek_version", func(w *keyring.WrappedDEK) { w.KEKVersion = 0 }, []error{keyring.ErrInvalidIdentifier}},
			{"nil_ciphertext", func(w *keyring.WrappedDEK) { w.Ciphertext = nil }, []error{keyring.ErrInvalidWrappedDEK}},
			{
				// Rotation is not creation and neither is re-wrapping: a
				// record naming a KEK that was never created has nothing to be
				// re-wrapped under, and minting a KEK here would produce a
				// record that looks migrated and opens to nothing.
				"unknown_kek",
				func(w *keyring.WrappedDEK) { w.KEKID = newKEKID(t) },
				[]error{keyring.ErrKEKNotFound},
			},
			{
				"destroyed_kek",
				func(w *keyring.WrappedDEK) { w.KEKID = destroyedKEK },
				[]error{keyring.ErrKEKDestroyed},
			},
			{
				"wrong_kek_version",
				func(w *keyring.WrappedDEK) { w.KEKVersion = rotated },
				[]error{keyring.ErrUnwrapFailed},
			},
			{
				"kek_version_that_never_existed",
				func(w *keyring.WrappedDEK) { w.KEKVersion = rotated + 1000 },
				[]error{keyring.ErrKEKNotFound, keyring.ErrUnwrapFailed},
			},
			{
				"moved_key_id",
				func(w *keyring.WrappedDEK) { w.KeyID = newKeyID(t) },
				[]error{keyring.ErrUnwrapFailed},
			},
			{
				"flipped_ciphertext_bit",
				func(w *keyring.WrappedDEK) { w.Ciphertext[len(w.Ciphertext)-1] ^= 0x01 },
				[]error{keyring.ErrUnwrapFailed},
			},
			{
				"truncated_ciphertext",
				func(w *keyring.WrappedDEK) { w.Ciphertext = w.Ciphertext[:len(w.Ciphertext)-1] },
				[]error{keyring.ErrUnwrapFailed},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := km.RewrapDEK(ctx, relabel(record, tc.mutate))
				if !errorIsAny(err, tc.wantErrs) {
					t.Fatalf("RewrapDEK(%s) error = %v, want one of %v", tc.name, err, tc.wantErrs)
				}
				if len(got.Ciphertext) != 0 {
					t.Fatalf("RewrapDEK(%s) returned a record despite failing", tc.name)
				}
			})
		}

		// None of the failures above may have disturbed the real record.
		if _, err := km.RewrapDEK(ctx, record); err != nil {
			t.Fatalf("RewrapDEK of the untouched record after the forgery attempts: %v", err)
		}
	})

	// UnwrapWithWrongKEKFailsClosed covers every way a record can name a key
	// it was not wrapped under. All of them must fail, none of them may
	// return key material, and — with one documented exception — all of them
	// report the same ErrUnwrapFailed, because an error that says *which*
	// part of a forged record was wrong turns the key manager into an oracle.
	t.Run("UnwrapWithWrongKEKFailsClosed", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekA, kekB := newKEKID(t), newKEKID(t)
		keyID := newKeyID(t)

		dek := newDEK(t)
		underA, err := km.WrapDEK(ctx, kekA, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK under KEK A: %v", err)
		}
		// KEK B exists and is a perfectly good key — it simply is not the
		// one that wrapped this record.
		if _, err := km.WrapDEK(ctx, kekB, newKeyID(t), dek); err != nil {
			t.Fatalf("WrapDEK under KEK B: %v", err)
		}
		rotatedA, err := km.RotateKEK(ctx, kekA)
		if err != nil {
			t.Fatalf("RotateKEK(A): %v", err)
		}

		cases := []struct {
			name   string
			mutate func(w *keyring.WrappedDEK)
			// wantErrs lists the acceptable sentinels; more than one is
			// allowed only where two correct adapters genuinely differ.
			wantErrs []error
		}{
			{
				name:     "different_existing_kek",
				mutate:   func(w *keyring.WrappedDEK) { w.KEKID = kekB },
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
			{
				name:     "existing_but_wrong_kek_version",
				mutate:   func(w *keyring.WrappedDEK) { w.KEKVersion = rotatedA },
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
			{
				// An adapter that resolves key material by version reports
				// the missing version; one whose backend reads the version
				// out of the ciphertext reports the mismatch. Both fail
				// closed, which is the property under test.
				name:     "kek_version_that_never_existed",
				mutate:   func(w *keyring.WrappedDEK) { w.KEKVersion = rotatedA + 1000 },
				wantErrs: []error{keyring.ErrKEKNotFound, keyring.ErrUnwrapFailed},
			},
			{
				name:     "record_moved_to_a_different_key_id",
				mutate:   func(w *keyring.WrappedDEK) { w.KeyID = newKeyID(t) },
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
			{
				name: "flipped_ciphertext_bit",
				mutate: func(w *keyring.WrappedDEK) {
					w.Ciphertext[len(w.Ciphertext)-1] ^= 0x01
				},
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
			{
				name: "flipped_first_ciphertext_bit",
				mutate: func(w *keyring.WrappedDEK) {
					w.Ciphertext[0] ^= 0x80
				},
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
			{
				name: "truncated_ciphertext",
				mutate: func(w *keyring.WrappedDEK) {
					w.Ciphertext = w.Ciphertext[:len(w.Ciphertext)-1]
				},
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
			{
				name: "appended_ciphertext",
				mutate: func(w *keyring.WrappedDEK) {
					w.Ciphertext = append(w.Ciphertext, 0x00)
				},
				wantErrs: []error{keyring.ErrUnwrapFailed},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				forged := relabel(underA, tc.mutate)
				got, err := km.UnwrapDEK(ctx, forged)
				if !errorIsAny(err, tc.wantErrs) {
					t.Fatalf("UnwrapDEK(%s) error = %v, want one of %v", tc.name, err, tc.wantErrs)
				}
				assertNoDEKReturned(t, "UnwrapDEK("+tc.name+")", got)
			})
		}

		// The untouched record must still unwrap: none of the failures
		// above may have invalidated the real key.
		if _, err := km.UnwrapDEK(ctx, underA); err != nil {
			t.Fatalf("UnwrapDEK of the untouched record after the forgery attempts: %v", err)
		}
	})

	// DestroyedKEKMakesItsDEKsPermanentlyUnwrappable is crypto-shredding:
	// destroying one key must make every DEK wrapped under it — and so every
	// byte those DEKs encrypted, in every backup, archive tier and
	// object-store version that still holds the ciphertext — permanently
	// unreadable. Byte-deletion cannot make that promise; this is the
	// mechanism that can, which is why the destruction must be real in an
	// adapter rather than a flag the adapter could later ignore.
	t.Run("DestroyedKEKMakesItsDEKsPermanentlyUnwrappable", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		doomed, survivor := newKEKID(t), newKEKID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())

		v1Record, err := km.WrapDEK(ctx, doomed, newKeyID(t), dek)
		if err != nil {
			t.Fatalf("WrapDEK under the doomed KEK: %v", err)
		}
		if _, err := km.RotateKEK(ctx, doomed); err != nil {
			t.Fatalf("RotateKEK(doomed): %v", err)
		}
		v2Record, err := km.WrapDEK(ctx, doomed, newKeyID(t), dek)
		if err != nil {
			t.Fatalf("WrapDEK under the doomed KEK after rotation: %v", err)
		}
		survivorRecord, err := km.WrapDEK(ctx, survivor, newKeyID(t), dek)
		if err != nil {
			t.Fatalf("WrapDEK under the surviving KEK: %v", err)
		}

		if err := km.DestroyKEK(ctx, doomed); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		// Every version's records are gone, and stay gone however many
		// times they are asked for: there is no retry, cache expiry or
		// reconnect that brings them back.
		for _, rec := range []keyring.WrappedDEK{v1Record, v2Record} {
			for attempt := range 3 {
				got, err := km.UnwrapDEK(ctx, rec)
				if !errors.Is(err, keyring.ErrKEKDestroyed) {
					t.Fatalf("UnwrapDEK(%s, attempt %d) error = %v, want ErrKEKDestroyed", rec.KEKVersion, attempt+1, err)
				}
				assertNoDEKReturned(t, "UnwrapDEK after DestroyKEK", got)
			}
		}

		// A destroyed KEK is never resurrected under its own name: wrapping
		// again would otherwise mint a fresh version 1 and leave a caller
		// unable to tell a pre-shredding record from a post-shredding one.
		if _, err := km.WrapDEK(ctx, doomed, newKeyID(t), dek); !errors.Is(err, keyring.ErrKEKDestroyed) {
			t.Fatalf("WrapDEK under a destroyed KEK error = %v, want ErrKEKDestroyed", err)
		}
		if _, err := km.RotateKEK(ctx, doomed); !errors.Is(err, keyring.ErrKEKDestroyed) {
			t.Fatalf("RotateKEK of a destroyed KEK error = %v, want ErrKEKDestroyed", err)
		}

		// Destroying an already-destroyed KEK is nil, so a retried erasure
		// job converges rather than failing forever on its own success.
		if err := km.DestroyKEK(ctx, doomed); err != nil {
			t.Fatalf("second DestroyKEK = %v, want nil (destruction is idempotent)", err)
		}

		// Destruction is scoped to the KEK named: every other key in the
		// same key manager still works.
		got, err := km.UnwrapDEK(ctx, survivorRecord)
		if err != nil {
			t.Fatalf("UnwrapDEK under an unrelated KEK after DestroyKEK: %v", err)
		}
		t.Cleanup(got.Destroy)
		if !bytes.Equal(got.Bytes(), material) {
			t.Fatal("destroying one KEK corrupted a DEK wrapped under another")
		}
	})

	// NoKeyMaterialLeaksInErrors is the canary required project-wide: no
	// error, log line, or test failure message may contain key material. It
	// drives every failure path this port has while holding a DEK whose
	// bytes it knows, and asserts those bytes never surface in the returned
	// error — raw, hex (either case), or base64 (any alphabet).
	//
	// The "or logs" half of the invariant is held by the type rather than by
	// this subtest, which cannot see an adapter's logger: keyring.DEK renders
	// as [REDACTED] through fmt, encoding/json, encoding.TextMarshaler and
	// slog alike (see internal/domain's TestDEKNeverRendersItsMaterial), so
	// logging key material requires an adapter to deliberately reach for
	// Bytes() and format it — rather than being the accidental default of
	// logging a struct.
	t.Run("NoKeyMaterialLeaksInErrors", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		material := bytes.Clone(dek.Bytes())

		wrapped, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}
		destroyedKEK := newKEKID(t)
		if _, err := km.WrapDEK(ctx, destroyedKEK, keyID, dek); err != nil {
			t.Fatalf("WrapDEK under the KEK about to be destroyed: %v", err)
		}
		shredded := relabel(wrapped, func(w *keyring.WrappedDEK) { w.KEKID = destroyedKEK })
		if err := km.DestroyKEK(ctx, destroyedKEK); err != nil {
			t.Fatalf("DestroyKEK: %v", err)
		}

		zeroized := newDEK(t)
		zeroized.Destroy()

		failures := []struct {
			name string
			call func() error
		}{
			{"wrap_with_destroyed_dek", func() error {
				_, err := km.WrapDEK(ctx, kekID, keyID, zeroized)
				return err
			}},
			{"wrap_under_destroyed_kek", func() error {
				_, err := km.WrapDEK(ctx, destroyedKEK, keyID, dek)
				return err
			}},
			{"wrap_with_invalid_key_id", func() error {
				_, err := km.WrapDEK(ctx, kekID, keyring.KeyID("bad/key\x00id"), dek)
				return err
			}},
			{"unwrap_tampered_ciphertext", func() error {
				_, err := km.UnwrapDEK(ctx, relabel(wrapped, func(w *keyring.WrappedDEK) {
					w.Ciphertext[0] ^= 0xFF
				}))
				return err
			}},
			{"unwrap_unknown_kek", func() error {
				_, err := km.UnwrapDEK(ctx, relabel(wrapped, func(w *keyring.WrappedDEK) {
					w.KEKID = newKEKID(t)
				}))
				return err
			}},
			{"unwrap_destroyed_kek", func() error {
				_, err := km.UnwrapDEK(ctx, shredded)
				return err
			}},
			{"unwrap_empty_ciphertext", func() error {
				_, err := km.UnwrapDEK(ctx, relabel(wrapped, func(w *keyring.WrappedDEK) {
					w.Ciphertext = nil
				}))
				return err
			}},
			{"generate_under_destroyed_kek", func() error {
				_, _, err := km.GenerateDEK(ctx, destroyedKEK, keyID)
				return err
			}},
			{"generate_with_invalid_key_id", func() error {
				_, _, err := km.GenerateDEK(ctx, kekID, keyring.KeyID("bad/key\x00id"))
				return err
			}},
			{"rewrap_tampered_ciphertext", func() error {
				_, err := km.RewrapDEK(ctx, relabel(wrapped, func(w *keyring.WrappedDEK) {
					w.Ciphertext[0] ^= 0xFF
				}))
				return err
			}},
			{"rewrap_under_destroyed_kek", func() error {
				_, err := km.RewrapDEK(ctx, shredded)
				return err
			}},
			{"rewrap_unknown_kek", func() error {
				_, err := km.RewrapDEK(ctx, relabel(wrapped, func(w *keyring.WrappedDEK) {
					w.KEKID = newKEKID(t)
				}))
				return err
			}},
		}
		for _, failure := range failures {
			t.Run(failure.name, func(t *testing.T) {
				err := failure.call()
				if err == nil {
					t.Fatalf("%s returned a nil error, so there is no fail-closed behavior to check", failure.name)
				}
				for label, rendering := range map[string]string{
					"Error()": err.Error(),
					"%v":      fmt.Sprintf("%v", err),
					"%+v":     fmt.Sprintf("%+v", err),
					"%s":      fmt.Sprintf("%s", err),
				} {
					assertNoKeyMaterial(t, failure.name+" rendered with "+label, rendering, material)
				}
			})
		}
	})

	// RenderingsOfAGeneratedDEK is the other half of the invariant that
	// NoKeyMaterialLeaksInErrors covers only partly. That subtest drives the
	// error paths, which is where material escapes deliberately; this one
	// covers the renderings, which is where it escapes by accident — a %v in
	// a debug line, a %+v in a panic message, a config struct marshalled by
	// a diagnostics endpoint, a slog.Any on something that happens to carry
	// the key.
	//
	// It is in the suite rather than only in internal/domain because an
	// adapter is free to return a DEK it built itself, and because a
	// consumer's own adapter is exactly what this suite exists to hold.
	// NoSecretLeaksInAnyRendering also asserts the four interfaces are
	// present, so a DEK that happens not to leak today — because its
	// material sits behind an unexported field reflection cannot reach —
	// still fails if a method is missing.
	t.Run("RenderingsOfAGeneratedDEK", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()

		dek, _, err := km.GenerateDEK(ctx, newKEKID(t), newKeyID(t))
		if err != nil {
			t.Fatalf("GenerateDEK: %v", err)
		}
		t.Cleanup(dek.Destroy)

		material := bytes.Clone(dek.Bytes())
		NoSecretLeaksInAnyRendering(t, dek, material)
	})

	t.Run("InvalidInputIsRejected", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		valid, err := km.WrapDEK(ctx, kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		zeroized := newDEK(t)
		zeroized.Destroy()
		overLong := strings.Repeat("x", 257)

		t.Run("Wrap", func(t *testing.T) {
			cases := []struct {
				name    string
				kekID   keyring.KEKID
				keyID   keyring.KeyID
				dek     keyring.DEK
				wantErr error
			}{
				{"empty_kek_id", "", keyID, dek, keyring.ErrInvalidIdentifier},
				{"empty_key_id", kekID, "", dek, keyring.ErrInvalidIdentifier},
				{"kek_id_with_separator", "a/b", keyID, dek, keyring.ErrInvalidIdentifier},
				{"key_id_with_null_byte", kekID, keyring.KeyID("a\x00b"), dek, keyring.ErrInvalidIdentifier},
				{"over_long_kek_id", keyring.KEKID(overLong), keyID, dek, keyring.ErrInvalidIdentifier},
				{"zero_dek", kekID, keyID, keyring.DEK{}, keyring.ErrInvalidKeyMaterial},
				{"destroyed_dek", kekID, keyID, zeroized, keyring.ErrInvalidKeyMaterial},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got, err := km.WrapDEK(ctx, tc.kekID, tc.keyID, tc.dek)
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("WrapDEK(%s) error = %v, want %v", tc.name, err, tc.wantErr)
					}
					if len(got.Ciphertext) != 0 {
						t.Fatalf("WrapDEK(%s) returned a record despite failing", tc.name)
					}
				})
			}
		})

		t.Run("Unwrap", func(t *testing.T) {
			cases := []struct {
				name    string
				mutate  func(w *keyring.WrappedDEK)
				wantErr error
			}{
				{"empty_kek_id", func(w *keyring.WrappedDEK) { w.KEKID = "" }, keyring.ErrInvalidIdentifier},
				{"empty_key_id", func(w *keyring.WrappedDEK) { w.KeyID = "" }, keyring.ErrInvalidIdentifier},
				{"zero_kek_version", func(w *keyring.WrappedDEK) { w.KEKVersion = 0 }, keyring.ErrInvalidIdentifier},
				{"nil_ciphertext", func(w *keyring.WrappedDEK) { w.Ciphertext = nil }, keyring.ErrInvalidWrappedDEK},
				{"empty_ciphertext", func(w *keyring.WrappedDEK) { w.Ciphertext = []byte{} }, keyring.ErrInvalidWrappedDEK},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					got, err := km.UnwrapDEK(ctx, relabel(valid, tc.mutate))
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("UnwrapDEK(%s) error = %v, want %v", tc.name, err, tc.wantErr)
					}
					assertNoDEKReturned(t, "UnwrapDEK("+tc.name+")", got)
				})
			}
		})

		t.Run("RotateAndDestroy", func(t *testing.T) {
			if _, err := km.RotateKEK(ctx, ""); !errors.Is(err, keyring.ErrInvalidIdentifier) {
				t.Fatalf("RotateKEK(empty KEK id) error = %v, want ErrInvalidIdentifier", err)
			}
			if err := km.DestroyKEK(ctx, "a/b"); !errors.Is(err, keyring.ErrInvalidIdentifier) {
				t.Fatalf("DestroyKEK(unsafe KEK id) error = %v, want ErrInvalidIdentifier", err)
			}
		})
	})

	// A cancelled context must be honored by every method, including in an
	// adapter that does no I/O: a caller that cancels a request expects the
	// key operations under it to stop, and an adapter whose behavior depends
	// on whether it happens to be the local or the remote one is a latent
	// difference in how a timeout surfaces.
	t.Run("CancelledContextIsRespected", func(t *testing.T) {
		km := newKM(t)
		kekID, keyID := newKEKID(t), newKeyID(t)

		dek := newDEK(t)
		wrapped, err := km.WrapDEK(context.Background(), kekID, keyID, dek)
		if err != nil {
			t.Fatalf("WrapDEK: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := km.WrapDEK(ctx, kekID, keyID, dek); !errors.Is(err, context.Canceled) {
			t.Errorf("WrapDEK with a cancelled context: error = %v, want context.Canceled", err)
		}
		if got, err := km.UnwrapDEK(ctx, wrapped); !errors.Is(err, context.Canceled) {
			t.Errorf("UnwrapDEK with a cancelled context: error = %v, want context.Canceled", err)
		} else {
			assertNoDEKReturned(t, "UnwrapDEK with a cancelled context", got)
		}
		if _, err := km.RotateKEK(ctx, kekID); !errors.Is(err, context.Canceled) {
			t.Errorf("RotateKEK with a cancelled context: error = %v, want context.Canceled", err)
		}
		if err := km.DestroyKEK(ctx, kekID); !errors.Is(err, context.Canceled) {
			t.Errorf("DestroyKEK with a cancelled context: error = %v, want context.Canceled", err)
		}
		if dek, _, err := km.GenerateDEK(ctx, kekID, keyID); !errors.Is(err, context.Canceled) {
			t.Errorf("GenerateDEK with a cancelled context: error = %v, want context.Canceled", err)
		} else {
			assertNoDEKReturned(t, "GenerateDEK with a cancelled context", dek)
		}
		if _, err := km.RewrapDEK(ctx, wrapped); !errors.Is(err, context.Canceled) {
			t.Errorf("RewrapDEK with a cancelled context: error = %v, want context.Canceled", err)
		}
	})

	t.Run("ConcurrentWrapAndUnwrapAreSafe", func(t *testing.T) {
		km := newKM(t)
		ctx := context.Background()
		kekID := newKEKID(t)

		const goroutines = 8
		var wg sync.WaitGroup
		errs := make([]error, 2*goroutines)
		for i := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = wrapUnwrapOnce(ctx, km, kekID, keyring.KeyID(fmt.Sprintf("concurrent-%d", i)))
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[goroutines+i] = generateRewrapUnwrapOnce(ctx, km, kekID, keyring.KeyID(fmt.Sprintf("concurrent-generated-%d", i)))
			}()
		}
		// A rotation in flight: wraps that land either side of it record
		// different versions, and every record must still unwrap.
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := km.RotateKEK(ctx, kekID); err != nil && !errors.Is(err, keyring.ErrKEKNotFound) {
				t.Errorf("concurrent RotateKEK: %v", err)
			}
		}()
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
			}
		}
	})
}

// wrapUnwrapOnce mints a DEK, wraps it, unwraps it and checks the round
// trip, returning an error rather than failing a *testing.T so it is safe to
// call from a goroutine.
func wrapUnwrapOnce(ctx context.Context, km keyring.KeyManager, kekID keyring.KEKID, keyID keyring.KeyID) error {
	dek, err := keyring.NewDEK()
	if err != nil {
		return fmt.Errorf("NewDEK: %w", err)
	}
	defer dek.Destroy()
	material := bytes.Clone(dek.Bytes())

	wrapped, err := km.WrapDEK(ctx, kekID, keyID, dek)
	if err != nil {
		return fmt.Errorf("WrapDEK: %w", err)
	}
	got, err := km.UnwrapDEK(ctx, wrapped)
	if err != nil {
		return fmt.Errorf("UnwrapDEK: %w", err)
	}
	defer got.Destroy()
	if !bytes.Equal(got.Bytes(), material) {
		return errors.New("unwrapped DEK does not match the wrapped one")
	}
	return nil
}

// generateRewrapUnwrapOnce drives the two new methods end to end —
// GenerateDEK, RewrapDEK, UnwrapDEK — and checks that the key survives the
// round trip. Like wrapUnwrapOnce it returns an error rather than failing a
// *testing.T, so it is safe to call from a goroutine.
func generateRewrapUnwrapOnce(ctx context.Context, km keyring.KeyManager, kekID keyring.KEKID, keyID keyring.KeyID) error {
	dek, record, err := km.GenerateDEK(ctx, kekID, keyID)
	if err != nil {
		return fmt.Errorf("GenerateDEK: %w", err)
	}
	defer dek.Destroy()
	material := bytes.Clone(dek.Bytes())

	rewrapped, err := km.RewrapDEK(ctx, record)
	if err != nil {
		return fmt.Errorf("RewrapDEK: %w", err)
	}
	got, err := km.UnwrapDEK(ctx, rewrapped)
	if err != nil {
		return fmt.Errorf("UnwrapDEK of the rewrapped record: %w", err)
	}
	defer got.Destroy()
	if !bytes.Equal(got.Bytes(), material) {
		return errors.New("the rewrapped record unwrapped to different key material than was generated")
	}
	return nil
}

// relabel returns a copy of w with mutate applied, cloning the ciphertext so
// a mutation that flips a byte cannot corrupt the caller's own record.
func relabel(w keyring.WrappedDEK, mutate func(*keyring.WrappedDEK)) keyring.WrappedDEK {
	forged := w
	forged.Ciphertext = bytes.Clone(w.Ciphertext)
	mutate(&forged)
	return forged
}

// errorIsAny reports whether err matches any of the listed sentinels.
func errorIsAny(err error, sentinels []error) bool {
	for _, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// assertNoDEKReturned fails if a failed operation nevertheless handed back
// usable key material. Returning a DEK alongside an error would be a leak
// that a caller which checks err first would never notice — and one that a
// caller which forgets to check err would use.
func assertNoDEKReturned(t *testing.T, label string, dek keyring.DEK) {
	t.Helper()
	if !dek.IsZero() {
		t.Fatalf("%s returned an error and key material; a failed operation must return no key", label)
	}
}

// assertNoKeyMaterial fails if text contains material in any encoding a leak
// would plausibly take: raw bytes, hex in either case, base64 in any
// alphabet, or Go's own byte-slice formatting. One substring check per
// encoding catches an adapter that formatted key material with %v, %x, %q or
// base64 alike.
func assertNoKeyMaterial(t *testing.T, label, text string, material []byte) {
	t.Helper()
	if len(material) == 0 {
		t.Fatal("assertNoKeyMaterial called with no material, which would assert nothing")
	}
	encodings := map[string]string{
		"raw bytes":      string(material),
		"lower hex":      hex.EncodeToString(material),
		"upper hex":      strings.ToUpper(hex.EncodeToString(material)),
		"base64 std":     base64.StdEncoding.EncodeToString(material),
		"base64 raw std": base64.RawStdEncoding.EncodeToString(material),
		"base64 url":     base64.URLEncoding.EncodeToString(material),
		"base64 raw url": base64.RawURLEncoding.EncodeToString(material),
		"go byte slice":  fmt.Sprintf("%v", material),
	}
	for name, encoded := range encodings {
		if strings.Contains(text, encoded) {
			t.Errorf("%s leaked key material as %s", label, name)
		}
	}
}

// newDEK returns a fresh DEK that is destroyed when the test ends.
func newDEK(t *testing.T) keyring.DEK {
	t.Helper()
	dek, err := keyring.NewDEK()
	if err != nil {
		t.Fatalf("NewDEK: %v", err)
	}
	t.Cleanup(dek.Destroy)
	return dek
}

// newKEKID returns a KEK id unique to this process run, so subtests of an
// adapter whose backend outlives a single test — one OpenBao instance, one
// KMS account — never collide on a key name.
func newKEKID(t *testing.T) keyring.KEKID {
	t.Helper()
	return keyring.KEKID("keyring-suite-kek-" + randomHex(t))
}

// newKeyID returns a key id unique to this process run.
func newKeyID(t *testing.T) keyring.KeyID {
	t.Helper()
	return keyring.KeyID("keyring-suite-key-" + randomHex(t))
}

// randomHex returns 16 hex characters of cryptographically random text.
// crypto/rand is used rather than math/rand even for test labels, matching
// this codebase's convention and avoiding a weak-RNG lint finding.
func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		t.Fatalf("read random bytes for a test identifier: %v", err)
	}
	return hex.EncodeToString(b)
}
