// Package keyring is the public facade for envelope encryption: a caller
// mints a data encryption key, encrypts with it, has this module wrap that
// key under a key encryption key it never sees, and stores the wrapped
// record next to the ciphertext. The key encryption key — and the deployment
// root key above it — can live entirely outside the process, which is the
// whole reason the port is shaped as wrap/unwrap/rotate rather than as "give
// me the key" (see keymanager and CAS design §8.3).
//
// Every value object lives in internal/domain and nowhere else; this file
// re-exports the ones a consumer must name as type aliases, so a
// WrappedDEK an adapter returns and a keyring.WrappedDEK the consumer stores
// are the identical type, not a copy that needs converting at the boundary.
// The sentinel errors are the same values the adapters return and the
// conformance suite asserts on, so a consumer — or a consumer's own adapter,
// which CHARTER.md's definition of adoption anticipates — compares against
// these with errors.Is.
//
// This file declares aliases, sentinels, constants, and the two DEK
// constructors a consumer cannot do without (internal/domain being
// unreachable from outside this module, and domain.DEK deliberately having
// no exported field to build one from). It holds no other behavior: each
// adapter has its own Open, because which key manager a deployment uses is
// a deployment decision and the adapters have genuinely different
// configuration — a root key here, a transit mount and a token there.
//
// Wiring the default, in-process adapter:
//
//	km, err := local.Open(ctx, local.Config{
//		RootKeyFile:     "/run/secrets/root.key",
//		RootKeyEncoding: local.RootKeyEncodingRaw,
//		Store:           store,
//	})
//	if err != nil {
//		return err
//	}
//	dek, err := keyring.NewDEK()
//	if err != nil {
//		return err
//	}
//	defer dek.Destroy()
//	wrapped, err := km.WrapDEK(ctx, keyring.KEKID(tenantID), keyring.KeyID(blobID), dek)
package keyring

import (
	"github.com/laenenai/keyring/internal/domain"
	"github.com/laenenai/keyring/keymanager"
)

type (
	// KeyManager is the port every adapter implements. See
	// keymanager.KeyManager, and keymanager.RunKeyManagerSuite for the
	// authoritative contract.
	KeyManager = keymanager.KeyManager
	// RewrapWithoutPlaintext is the optional capability for adapters whose
	// RewrapDEK never puts the DEK in this process. See
	// keymanager.RewrapWithoutPlaintext.
	RewrapWithoutPlaintext = keymanager.RewrapWithoutPlaintext

	// DEK is one data encryption key, zeroizable and non-rendering. See
	// domain.DEK.
	DEK = domain.DEK
	// WrappedDEK is a DEK encrypted under a KEK, recording which KEK
	// version wrapped it. See domain.WrappedDEK.
	WrappedDEK = domain.WrappedDEK
	// WrappedDEKFormat names the adapter and record format that produced a
	// WrappedDEK. See domain.WrappedDEKFormat.
	WrappedDEKFormat = domain.WrappedDEKFormat
	// KEKID names a key encryption key. See domain.KEKID.
	KEKID = domain.KEKID
	// KeyID names what a DEK protects, and is bound into the wrapped
	// record. See domain.KeyID.
	KeyID = domain.KeyID
	// KEKVersion is one generation of a KEK. See domain.KEKVersion.
	KEKVersion = domain.KEKVersion
)

const (
	// DEKSize is the length in bytes of every DEK. See domain.DEKSize.
	DEKSize = domain.DEKSize
	// FirstKEKVersion is the version a KEK has when it is created. See
	// domain.FirstKEKVersion.
	FirstKEKVersion = domain.FirstKEKVersion
	// Redacted is the placeholder every rendering of key material yields.
	// See domain.Redacted.
	Redacted = domain.Redacted
	// WrappedDEKFormatLegacy is an empty legacy format. New records name
	// their adapter. See domain.WrappedDEKFormatLegacy.
	WrappedDEKFormatLegacy = domain.WrappedDEKFormatLegacy
	// WrappedDEKFormatLocal is the local adapter's record format.
	WrappedDEKFormatLocal = domain.WrappedDEKFormatLocal
	// WrappedDEKFormatOpenBaoTransit is the OpenBao transit record format.
	WrappedDEKFormatOpenBaoTransit = domain.WrappedDEKFormatOpenBaoTransit
)

// Sentinel errors returned across every package boundary in keyring. See
// internal/domain/errors.go for their full documentation, in particular why
// ErrUnwrapFailed is deliberately uninformative and why ErrKEKDestroyed is
// separate from ErrKEKNotFound.
var (
	// ErrInvalidKeyMaterial is domain.ErrInvalidKeyMaterial.
	ErrInvalidKeyMaterial = domain.ErrInvalidKeyMaterial
	// ErrInvalidIdentifier is domain.ErrInvalidIdentifier.
	ErrInvalidIdentifier = domain.ErrInvalidIdentifier
	// ErrInvalidWrappedDEK is domain.ErrInvalidWrappedDEK.
	ErrInvalidWrappedDEK = domain.ErrInvalidWrappedDEK
	// ErrKEKNotFound is domain.ErrKEKNotFound.
	ErrKEKNotFound = domain.ErrKEKNotFound
	// ErrKEKDestroyed is domain.ErrKEKDestroyed.
	ErrKEKDestroyed = domain.ErrKEKDestroyed
	// ErrUnwrapFailed is domain.ErrUnwrapFailed.
	ErrUnwrapFailed = domain.ErrUnwrapFailed
	// ErrInvalidConfig is domain.ErrInvalidConfig.
	ErrInvalidConfig = domain.ErrInvalidConfig
	// ErrPermissionDenied is domain.ErrPermissionDenied.
	ErrPermissionDenied = domain.ErrPermissionDenied
	// ErrRateLimited is domain.ErrRateLimited.
	ErrRateLimited = domain.ErrRateLimited
	// ErrTransient is domain.ErrTransient.
	ErrTransient = domain.ErrTransient
)

// NewDEK returns a fresh DEK read from crypto/rand. See domain.NewDEK.
//
// It delegates rather than being an alias because Go has no alias for a
// function, and a consumer outside this module cannot reach internal/domain
// to call it directly — nor construct a DEK any other way, since its key
// material is unexported on purpose.
func NewDEK() (DEK, error) { return domain.NewDEK() }

// DEKFrom returns a DEK holding a copy of b, or ErrInvalidKeyMaterial if b
// is not usable key material. See domain.DEKFrom. It exists for a caller
// that derives its DEK elsewhere — convergently from a tenant secret, say —
// rather than drawing it from NewDEK.
func DEKFrom(b []byte) (DEK, error) { return domain.DEKFrom(b) }
