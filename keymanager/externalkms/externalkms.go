// Package externalkms is the external-KMS adapter: AWS KMS, GCP KMS, Azure
// Key Vault, or a tenant's own HSM. It is how a BYOK/HYOK tenant is served
// (CAS design §8.2's tenant-key mode): the KEK lives in *their* key manager,
// every unwrap is their audit record, and revoking it cuts the operator off
// within the DEK cache TTL.
//
// # Not implemented in this increment
//
// Open returns domain.ErrNotImplemented. The package exists now so that the
// configuration shape is a reviewed part of the public surface, so a
// deployment wiring it fails at startup rather than at its first wrap, and so
// the conformance suite is already pointed at it.
//
// Two problems this adapter has to solve that the local and transit adapters
// do not, recorded here because they are the reason it is last of the three:
//
//   - Version numbering. domain.KEKVersion is a monotonically increasing
//     integer, which is what OpenBao transit and this module's local adapter
//     both provide. AWS KMS does not expose one: automatic key rotation
//     replaces the backing key without a caller-visible version, and the
//     thing a caller can name is a key id or alias. So this adapter owns a
//     mapping from its own KEK versions to the external key identities
//     (alias, key ARN, or key-material id) that backed them, and that
//     mapping is state it must persist — in practice the same store the
//     local adapter uses, since without it a record's recorded version
//     cannot be resolved back to a key.
//   - A DEK cache with a bounded TTL. Every unwrap is a network call and a
//     tenant-side audit event, so a cache is not an optimization here but
//     part of the design; its TTL is what bounds how long the operator
//     retains access after the tenant revokes the key (CAS §8.2: default 5
//     minutes, zero allowed). A cache that hands out the same DEK buffer to
//     two callers would violate the port's "two unwraps return
//     independently-owned DEKs" rule, so the cache must store wrapped
//     records or copy on read.
package externalkms

import (
	"context"
	"fmt"

	"github.com/laenen-ai/keyring/internal/domain"
	"github.com/laenen-ai/keyring/keymanager"
)

// Config configures the external-KMS adapter.
type Config struct {
	// Provider names which external key manager to speak to: "aws-kms",
	// "gcp-kms", "azure-key-vault", or "pkcs11" for a tenant's own HSM. It
	// is a string rather than a closed enum because which providers this
	// adapter supports is expected to grow, and a consumer's configuration
	// file should not have to be rewritten when it does.
	Provider string

	// KeyURI identifies the key within that provider, in the provider's own
	// notation: a key ARN or alias for AWS, a resource name for GCP, a key
	// identifier URL for Azure, a PKCS#11 URI for an HSM. It is opaque to
	// this module.
	KeyURI string
}

// KeyManager is the external-KMS adapter's implementation of
// keymanager.KeyManager. Every method returns domain.ErrNotImplemented in
// this increment; see the package doc comment.
type KeyManager struct{}

// Open returns domain.ErrNotImplemented: this adapter's transport is not
// implemented in this increment, and a deployment that wires it must fail at
// startup rather than discover that at its first wrap.
func Open(_ context.Context, _ Config) (*KeyManager, error) {
	return nil, fmt.Errorf("%w: the external-kms adapter's transport", domain.ErrNotImplemented)
}

// WrapDEK implements keymanager.KeyManager.
func (k *KeyManager) WrapDEK(_ context.Context, _ domain.KEKID, _ domain.KeyID, _ domain.DEK) (domain.WrappedDEK, error) {
	return domain.WrappedDEK{}, fmt.Errorf("%w: external-kms WrapDEK", domain.ErrNotImplemented)
}

// UnwrapDEK implements keymanager.KeyManager.
func (k *KeyManager) UnwrapDEK(_ context.Context, _ domain.WrappedDEK) (domain.DEK, error) {
	return domain.DEK{}, fmt.Errorf("%w: external-kms UnwrapDEK", domain.ErrNotImplemented)
}

// RotateKEK implements keymanager.KeyManager.
func (k *KeyManager) RotateKEK(_ context.Context, _ domain.KEKID) (domain.KEKVersion, error) {
	return 0, fmt.Errorf("%w: external-kms RotateKEK", domain.ErrNotImplemented)
}

// DestroyKEK implements keymanager.KeyManager.
func (k *KeyManager) DestroyKEK(_ context.Context, _ domain.KEKID) error {
	return fmt.Errorf("%w: external-kms DestroyKEK", domain.ErrNotImplemented)
}

// The stub is held to the port at compile time, so the increment that adds
// the transport starts from a type that already has to satisfy the
// interface.
var _ keymanager.KeyManager = (*KeyManager)(nil)
