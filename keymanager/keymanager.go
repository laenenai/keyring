// Package keymanager defines the envelope-encryption port every keyring
// adapter implements: a data encryption key goes in, its wrapped form comes
// back, and the key encryption key that did the wrapping — and the
// deployment root key above it — never enter the caller's address space.
// That shape, rather than a "give me the key" accessor, is what lets a
// deployment keep its root key in OpenBao or a cloud KMS and still use the
// same code path as the single-binary default (see the local adapter in
// ./local, and CAS design §8.3).
//
// Every adapter — local here, openbao-transit alongside it, and an adapter a
// consumer writes against its own KMS — must pass
// keyringtest.RunKeyManagerSuite unchanged; that suite, not this file, is the
// authoritative description of the contract's edge-case behavior, including
// what fails closed, what is idempotent, and what a destroyed KEK does to
// the DEKs wrapped under it. The suite lives in a sibling package rather than
// beside this one so that importing the port does not drag testing into a
// consumer's production import graph (see CONVENTIONS.md and keyringtest's
// own package comment).
//
// The port and the adapters live together under keymanager/ so that each
// adapter package reads as one of the key managers rather than as a
// free-floating package; a consumer names the interface as keyring.KeyManager
// and the adapter it wires by that adapter's Open.
//
// No error returned by any KeyManager method, and no message logged by an
// adapter, may contain key material in any encoding — raw, hex, or base64.
// Identifiers (a KEK id, a key id, a version) are not secret and may appear;
// the material never may. See keyringtest's NoKeyMaterialLeaksInErrors
// subtest, which every adapter exercises, and domain.DEK's redacted
// renderings, which
// make the common mistake impossible rather than merely forbidden.
package keymanager

import (
	"context"

	"github.com/laenenai/keyring/internal/domain"
)

// KeyManager is the port every key manager adapter implements. See the
// package doc comment and keyringtest.RunKeyManagerSuite for the full
// contract.
//
// Three levels of key exist (CAS design §8.3): a deployment root key, a KEK
// per unit of isolation, and a DEK per encrypted object. Only the third ever
// crosses this interface. A caller mints a DEK with domain.NewDEK, encrypts
// with it, wraps it here, stores the WrappedDEK next to the ciphertext, and
// destroys its copy of the DEK; to read, it unwraps and destroys again.
//
// Errors are the sentinels in domain (re-exported from the root keyring
// package): ErrKEKNotFound, ErrKEKDestroyed, ErrUnwrapFailed,
// ErrInvalidKeyMaterial, ErrInvalidIdentifier, ErrInvalidWrappedDEK. An
// adapter maps its backend's own signals onto these and adds context with
// %w, so a caller never branches on an adapter-specific shape.
//
// Every method must return a context error when ctx is already cancelled,
// including for an adapter that would otherwise do no I/O.
type KeyManager interface {
	// WrapDEK encrypts dek under the current version of the KEK named by
	// kekID and returns the record to persist. The returned WrappedDEK
	// records that version, which is what makes rotation lazy — see
	// RotateKEK.
	//
	// keyID is bound into the ciphertext as authenticated context: the same
	// keyID must be present on the record at unwrap time, so a wrapped DEK
	// lifted out of one row and stored in another fails closed instead of
	// yielding a usable key for content it does not belong to.
	//
	// If the KEK does not exist yet it is created, at
	// domain.FirstKEKVersion. Creation is implicit because the alternative —
	// a CreateKEK the caller must remember to call first — produces a
	// failure mode (wrap fails for a new tenant) with no security benefit.
	// A *destroyed* KEK is never recreated this way: WrapDEK naming one
	// returns ErrKEKDestroyed, because a shredded key coming back to life
	// under its own name would make a later unwrap of a pre-shredding
	// record indistinguishable from a post-shredding one.
	//
	// WrapDEK does not take ownership of dek: it neither destroys nor
	// modifies it, and the caller remains responsible for calling
	// dek.Destroy.
	WrapDEK(ctx context.Context, kekID domain.KEKID, keyID domain.KeyID, dek domain.DEK) (domain.WrappedDEK, error)

	// GenerateDEK mints a fresh DEK and returns it together with its wrapped
	// form, under the current version of the KEK named by kekID and bound to
	// keyID exactly as WrapDEK would. The caller owns the returned DEK and
	// must Destroy it.
	//
	// It exists because the key manager is the better place to mint a DEK
	// than its caller. OpenBao transit has one endpoint for this
	// (datakey/plaintext): the DEK is generated *inside* the key store, from
	// the key store's entropy, and the plaintext and the ciphertext come back
	// in a single round trip. A caller doing crypto/rand plus WrapDEK instead
	// gets its DEKs from whatever entropy its own process has, and puts the
	// two halves of one operation in two places where only one of them can
	// fail. An adapter with no such endpoint — the local one — generates
	// locally and is indistinguishable here, which is the point of having the
	// method on the port rather than on one adapter.
	//
	// Semantics otherwise match WrapDEK's exactly, including implicit
	// creation of a KEK that does not exist yet and ErrKEKDestroyed for one
	// that has been destroyed: a shredded KEK must not be resurrected through
	// a second door.
	//
	// On any error the returned DEK holds no key material and the returned
	// record carries no ciphertext.
	GenerateDEK(ctx context.Context, kekID domain.KEKID, keyID domain.KeyID) (domain.DEK, domain.WrappedDEK, error)

	// UnwrapDEK decrypts wrapped and returns the DEK it carries. The caller
	// owns the returned DEK and must Destroy it; two unwraps of the same
	// record return two independently-owned DEKs, so destroying one never
	// invalidates the other (an adapter that caches DEKs must hand out
	// copies).
	//
	// It uses the KEK version recorded on the record, not the KEK's current
	// version, which is why a DEK wrapped under version 1 still unwraps
	// after rotation to version 2 and why rotating a KEK never requires
	// re-encrypting content.
	//
	// It returns:
	//   - ErrKEKDestroyed if the named KEK has been destroyed. This is
	//     permanent and is the point of crypto-shredding: the content those
	//     DEKs encrypted is unreadable in every backup, archive tier and
	//     object-store version that still holds it.
	//   - ErrKEKNotFound if the named KEK, or that version of it, never
	//     existed.
	//   - ErrUnwrapFailed if the record does not authenticate under the KEK
	//     and version it names: the wrong KEK, a record relabelled to a
	//     different existing version, a changed keyID, or tampered or
	//     truncated ciphertext. One sentinel covers all of them on purpose
	//     (see its doc comment): the key manager must not become an oracle
	//     that tells an attacker which part of a forged record was wrong.
	//     An adapter whose backend resolves the KEK version from the
	//     ciphertext itself must still compare it against the version the
	//     record claims and fail here on a mismatch.
	// On any error the returned DEK holds no key material.
	UnwrapDEK(ctx context.Context, wrapped domain.WrappedDEK) (domain.DEK, error)

	// RewrapDEK re-encrypts wrapped under the current version of the KEK it
	// names and returns the new record, without ever returning the DEK it
	// carries. The DEK is unchanged, so the content it encrypted is not
	// re-encrypted: this is CAS design §8.3's "KEK rotation is lazy
	// re-wrapping rather than re-encrypting content", as one operation.
	//
	// It is a first-class method and MUST NOT be implemented as unwrap
	// followed by wrap, because the difference is the whole reason it exists.
	// OpenBao transit's rewrap endpoint documents that plaintext is never
	// returned, which is what makes it safe to delegate a rotation sweep to
	// something that is not trusted to read the keys it is migrating: the job
	// needs the rewrap capability and not the decrypt one, and the DEK never
	// enters the process running the sweep. An adapter that unwrapped and
	// wrapped again would satisfy every functional assertion and quietly
	// discard that property. Where an adapter has no such primitive — the
	// local one, whose KEK material is in this process either way — its doc
	// comment says so, because the guarantee is then only as strong as the
	// adapter.
	//
	// Re-wrapping is additive: the record passed in is untouched and still
	// unwraps, so a caller writes the new record and only then forgets the
	// old one. A record already at the KEK's current version is re-wrapped
	// rather than rejected, so a sweep that cannot cheaply tell which records
	// are current converges instead of erroring.
	//
	// It returns the same errors UnwrapDEK does, for the same reasons:
	// ErrKEKDestroyed, ErrKEKNotFound (re-wrapping is not creation, so a KEK
	// that never existed is not minted here either), and ErrUnwrapFailed for
	// a record that does not authenticate under the KEK and version it names.
	// On any error the returned record carries no ciphertext.
	RewrapDEK(ctx context.Context, wrapped domain.WrappedDEK) (domain.WrappedDEK, error)

	// RotateKEK creates the next version of the KEK named by kekID and
	// returns it. Subsequent WrapDEK calls use the new version; every
	// already-wrapped DEK keeps unwrapping under the version it recorded.
	// Re-wrapping those records under the new version is therefore lazy and
	// optional work the caller schedules (unwrap, then wrap again), and
	// content is never re-encrypted.
	//
	// Rotation is not creation: RotateKEK of a KEK that does not exist
	// returns ErrKEKNotFound rather than creating version 1, so a typo in a
	// kekID cannot silently produce a brand-new key that wraps nothing.
	// Versions returned by successive calls strictly increase.
	RotateKEK(ctx context.Context, kekID domain.KEKID) (domain.KEKVersion, error)

	// DestroyKEK destroys every version of the KEK named by kekID,
	// permanently. After it returns, UnwrapDEK of any record naming that
	// KEK returns ErrKEKDestroyed forever, so every byte those DEKs
	// encrypted is unreadable even where the ciphertext still exists.
	//
	// This is the mechanism half of erasure and nothing more: *when* to
	// destroy a key is shredding policy, which CHARTER.md puts outside this
	// module. The port carries it because the invariant "a destroyed KEK
	// makes its DEKs permanently unwrappable" is a property of a key
	// manager, and a contract no adapter can be held to is not a contract.
	//
	// It returns ErrKEKNotFound for a KEK that never existed — an erasure
	// certificate must not be able to claim a key was destroyed when
	// nothing of the sort happened — and nil for a KEK already destroyed,
	// so a retried erasure job converges instead of erroring.
	DestroyKEK(ctx context.Context, kekID domain.KEKID) error
}
