// Package openbaotransit is the OpenBao transit adapter: the recommended
// production key manager, in which the root key never exists in this
// process's address space at all. The application sends a DEK to be wrapped
// and receives it back wrapped, every wrap and unwrap lands in OpenBao's
// audit log, rotation is a server-side operation, and destroying a key is
// enforced by something outside the application that is holding it (CAS
// design §8.3). HashiCorp Vault's transit engine is wire-compatible, so the
// same adapter serves both.
//
// # Not implemented in this increment
//
// Open returns domain.ErrNotImplemented. The package exists now, with its
// configuration and its conformance wiring, for three reasons: the shape of
// the configuration is a reviewed part of this module's public surface
// (api.txt), a deployment that wires this adapter must fail at startup
// rather than at its first wrap, and the conformance suite is already
// pointed at it so that implementing the transport is a matter of making a
// green test out of a skipped one.
//
// The transport needs an HTTP client against OpenBao's /v1/<mount>/ API, a
// token source, and — per CONVENTIONS.md — an integration test against the
// real openbao/openbao:2.2.1 image rather than a fake, since what this
// adapter exists to prove (the root key is not here, the audit log recorded
// it, the destroy was server-side) is exactly what a fake cannot prove. That
// test is also where this module acquires its first third-party dependency,
// which is why it is a separate, reviewed increment rather than a quiet
// addition to this one.
//
// Mapping notes already settled by the port's contract, recorded here so the
// next increment does not have to rediscover them:
//   - A transit ciphertext carries its own key version ("vault:v1:..."), so
//     UnwrapDEK must compare that version against the one the WrappedDEK
//     records and return domain.ErrUnwrapFailed on a mismatch rather than
//     letting the server decrypt under whatever version it finds.
//   - Transit's per-request "context" field carries the DEK record's key id,
//     which is what binds a wrapped DEK to the row it belongs to.
//   - A destroyed transit key answers with a 400 whose message names the
//     destruction; that maps to domain.ErrKEKDestroyed, never to
//     ErrKEKNotFound, because an erasure certificate depends on the
//     difference.
package openbaotransit

import (
	"context"
	"fmt"

	"github.com/laenen-ai/keyring/internal/domain"
	"github.com/laenen-ai/keyring/keymanager"
)

// Config configures the OpenBao transit adapter.
type Config struct {
	// Address is the base URL of the OpenBao (or Vault) server, for example
	// "https://openbao.internal:8200".
	Address string

	// Token authenticates this process to OpenBao. It is a secret: it must
	// never be logged, and it never appears in an error returned by this
	// package.
	Token string

	// MountPath is the path the transit engine is mounted at, without
	// leading or trailing slashes. Empty means "transit", which is
	// OpenBao's default mount.
	MountPath string
}

// KeyManager is the OpenBao transit adapter's implementation of
// keymanager.KeyManager. Every method returns domain.ErrNotImplemented in
// this increment; see the package doc comment.
type KeyManager struct{}

// Open returns domain.ErrNotImplemented: this adapter's transport is not
// implemented in this increment, and a deployment that wires it must fail at
// startup rather than discover that at its first wrap.
func Open(_ context.Context, _ Config) (*KeyManager, error) {
	return nil, fmt.Errorf("%w: the openbao-transit adapter's transport", domain.ErrNotImplemented)
}

// WrapDEK implements keymanager.KeyManager.
func (k *KeyManager) WrapDEK(_ context.Context, _ domain.KEKID, _ domain.KeyID, _ domain.DEK) (domain.WrappedDEK, error) {
	return domain.WrappedDEK{}, fmt.Errorf("%w: openbao-transit WrapDEK", domain.ErrNotImplemented)
}

// GenerateDEK implements keymanager.KeyManager.
func (k *KeyManager) GenerateDEK(_ context.Context, _ domain.KEKID, _ domain.KeyID) (domain.DEK, domain.WrappedDEK, error) {
	return domain.DEK{}, domain.WrappedDEK{}, fmt.Errorf("%w: openbao-transit GenerateDEK", domain.ErrNotImplemented)
}

// UnwrapDEK implements keymanager.KeyManager.
func (k *KeyManager) UnwrapDEK(_ context.Context, _ domain.WrappedDEK) (domain.DEK, error) {
	return domain.DEK{}, fmt.Errorf("%w: openbao-transit UnwrapDEK", domain.ErrNotImplemented)
}

// RewrapDEK implements keymanager.KeyManager.
func (k *KeyManager) RewrapDEK(_ context.Context, _ domain.WrappedDEK) (domain.WrappedDEK, error) {
	return domain.WrappedDEK{}, fmt.Errorf("%w: openbao-transit RewrapDEK", domain.ErrNotImplemented)
}

// RotateKEK implements keymanager.KeyManager.
func (k *KeyManager) RotateKEK(_ context.Context, _ domain.KEKID) (domain.KEKVersion, error) {
	return 0, fmt.Errorf("%w: openbao-transit RotateKEK", domain.ErrNotImplemented)
}

// DestroyKEK implements keymanager.KeyManager.
func (k *KeyManager) DestroyKEK(_ context.Context, _ domain.KEKID) error {
	return fmt.Errorf("%w: openbao-transit DestroyKEK", domain.ErrNotImplemented)
}

// The stub is held to the port at compile time, so the increment that adds
// the transport starts from a type that already has to satisfy the
// interface.
var _ keymanager.KeyManager = (*KeyManager)(nil)
