// Package openbaotransit is the OpenBao transit adapter: the recommended
// production key manager, in which the root key never exists in this
// process's address space at all. The application sends a DEK to be wrapped
// and receives it back wrapped, every wrap and unwrap lands in OpenBao's
// audit log, rotation is a server-side operation, and destroying a key is
// enforced by something outside the application that is holding it (CAS
// design §8.3). HashiCorp Vault's transit engine is wire-compatible, so the
// same adapter serves both.
//
// Transit is a plain JSON HTTP API, so this package speaks it with the
// standard library's net/http and no SDK. That is a deliberate choice and
// not an omission: an SDK for a service whose whole surface here is six
// endpoints would add a dependency tree — and a second opinion about
// retries, timeouts and error shapes — to a module whose job is to be
// boring.
//
// # Endpoint mapping
//
//	WrapDEK      -> POST <mount>/encrypt/<key>
//	GenerateDEK  -> POST <mount>/datakey/plaintext/<key>
//	UnwrapDEK    -> POST <mount>/decrypt/<key>
//	RewrapDEK    -> POST <mount>/rewrap/<key>
//	RotateKEK    -> POST <mount>/keys/<key>/rotate
//	DestroyKEK   -> POST <mount>/keys/<key>/config, then DELETE <mount>/keys/<key>
//
// GenerateDEK is one of the two endpoints this adapter exists to have:
// datakey/plaintext generates the DEK inside OpenBao, from OpenBao's
// entropy, and returns the plaintext and the ciphertext in one response.
// RewrapDEK is the other: transit's rewrap never returns plaintext, so a
// lazy rotation sweep can be given a token with rewrap and no decrypt
// capability and the DEKs it migrates never enter the process running it.
// Those two properties are why the port carries both methods rather than
// leaving callers to compose them out of the others.
//
// # Keys are derived, and the key id is the derivation context
//
// Every KEK this adapter creates is an aes256-gcm96 key with derivation
// enabled, and every request carries the DEK record's key id as transit's
// "context". Transit derives the request's actual encryption key from the
// key version and that context, so a wrapped DEK is cryptographically bound
// to the key id it was created for: a record lifted out of one row and
// stored in another fails to decrypt instead of yielding a usable key for
// content it does not belong to. It is the same binding the local adapter
// gets from additional authenticated data, obtained from the one mechanism
// transit offers for it.
//
// # Key names, and why the mount belongs to this adapter
//
// A KEK id does not become a transit key name unchanged. The adapter owns
// two disjoint name spaces inside its mount:
//
//	KeyNamePrefix       + <KEK id>  the key that wraps DEKs
//	TombstoneNamePrefix + <KEK id>  the destruction record, see DestroyKEK
//
// Prefixing both is what keeps them disjoint: a caller whose KEK id happens
// to be "destroyed-kek-x" gets the key "kek-destroyed-kek-x" and so cannot
// forge a tombstone for the KEK "x". The consequence is that the mount is
// this adapter's own, not one shared with keys an operator manages by hand.
//
// # Token policy
//
// The token needs, within the mount: update on encrypt/*,
// datakey/plaintext/*, decrypt/*, rewrap/*, keys/*/rotate and keys/*/config;
// read and create on keys/*; and delete on keys/* for DestroyKEK. A rotation
// sweep is the one caller that needs less: update on rewrap/* and read on
// keys/* is enough for RewrapDEK, with no decrypt capability anywhere.
//
// # Errors
//
// Transit reports almost everything as a 400 with a message, so this adapter
// reads messages rather than statuses — and callers see neither: a missing
// key is domain.ErrKEKNotFound, a destroyed one is domain.ErrKEKDestroyed,
// and every ciphertext that does not authenticate (wrong key, wrong
// derivation context, tampered or truncated bytes, a version the key's policy
// no longer permits) is the one deliberately uninformative
// domain.ErrUnwrapFailed. No error returned by this package contains the
// token or key material.
package openbaotransit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/laenen-ai/keyring/internal/domain"
	"github.com/laenen-ai/keyring/keymanager"
)

// DefaultMountPath is the path transit is mounted at when Config.MountPath is
// empty, and is OpenBao's own default.
const DefaultMountPath = "transit"

// KeyNamePrefix and TombstoneNamePrefix are prepended to a KEK id to form the
// two transit key names this adapter uses for it. See the package doc comment
// for why both are prefixed rather than only one.
const (
	KeyNamePrefix       = "kek-"
	TombstoneNamePrefix = "destroyed-kek-"
)

// DefaultTimeout bounds a single transit request when Config.HTTPClient is not
// supplied. A key manager that hangs forever on a half-open connection takes
// every request that needs a key with it, so there is a timeout by default
// rather than only when a caller remembers a context deadline.
const DefaultTimeout = 30 * time.Second

// transitKeyType is the key type every KEK is created as. It supports both
// encryption and derivation, which this adapter requires: see the package doc
// comment on the key id being the derivation context.
const transitKeyType = "aes256-gcm96"

// maxResponseBytes bounds how much of a response this adapter reads. Every
// response it expects is a few hundred bytes; the limit is what stops a
// misconfigured address pointing at something that streams.
const maxResponseBytes = 1 << 20

// ciphertextPrefixes are the leading field a transit ciphertext may carry
// ("vault:v1:…"). OpenBao still emits Vault's; both are accepted so that a
// record written against one server is readable against the other, which is
// the same wire compatibility that lets one adapter serve both.
var ciphertextPrefixes = []string{"vault", "bao"}

// Config configures the OpenBao transit adapter.
type Config struct {
	// Address is the base URL of the OpenBao (or Vault) server, for example
	// "https://openbao.internal:8200".
	Address string

	// Token authenticates this process to OpenBao. It is a secret: it must
	// never be logged, and it never appears in an error returned by this
	// package. Config redacts it in its own String and LogValue, so logging
	// the configuration — the obvious way for it to escape — does not leak
	// it.
	Token string

	// MountPath is the path the transit engine is mounted at, without
	// leading or trailing slashes. Empty means DefaultMountPath. A nested
	// mount ("platform/transit") is allowed.
	MountPath string

	// HTTPClient, when set, is used for every request, so a deployment can
	// supply its own TLS configuration, proxy, connection pooling or
	// timeout. Nil means a client with DefaultTimeout.
	HTTPClient *http.Client
}

// String renders the configuration with the token redacted.
func (c Config) String() string {
	return fmt.Sprintf("openbaotransit.Config{Address: %q, Token: %s, MountPath: %q}",
		c.Address, domain.Redacted, c.MountPath)
}

// LogValue renders the configuration as a slog group with the token redacted,
// so slog.Any("config", cfg) is safe.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("address", c.Address),
		slog.String("token", domain.Redacted),
		slog.String("mount_path", c.MountPath),
	)
}

// KeyManager is the OpenBao transit adapter's implementation of
// keymanager.KeyManager. Open returns one; it is safe for concurrent use.
type KeyManager struct {
	// base is the server's base URL with no trailing slash.
	base string
	// mount is the mount path, each segment escaped for use in a URL.
	mount string
	// token is the X-Vault-Token header value.
	token string
	// client performs every request.
	client *http.Client
}

// Open validates cfg and returns a key manager over it.
//
// It does not contact the server. A reachability check here would report a
// configuration error and an outage as the same symptom, and a check that
// passed at startup would imply a guarantee that does not survive the first
// network partition; every method reports an unreachable server as the error
// it is.
//
// It returns domain.ErrInvalidConfig for a configuration that cannot produce
// a working manager: no address, an address that is not an absolute http or
// https URL, no token, or a mount path that is not usable as one. The error
// never contains the token.
func Open(ctx context.Context, cfg Config) (*KeyManager, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keyring/openbaotransit: open: %w", err)
	}
	address := strings.TrimSpace(cfg.Address)
	if address == "" {
		return nil, fmt.Errorf("%w: Address is required, for example \"https://openbao.internal:8200\"", domain.ErrInvalidConfig)
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("%w: Address %q is not a URL: %w", domain.ErrInvalidConfig, cfg.Address, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: Address %q must be an absolute http or https URL", domain.ErrInvalidConfig, cfg.Address)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%w: Address %q has no host", domain.ErrInvalidConfig, cfg.Address)
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("%w: Token is required", domain.ErrInvalidConfig)
	}
	mount, err := mountPath(cfg.MountPath)
	if err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	return &KeyManager{
		base:   strings.TrimSuffix(parsed.String(), "/"),
		mount:  mount,
		token:  cfg.Token,
		client: client,
	}, nil
}

// WrapDEK implements keymanager.KeyManager, over transit's encrypt endpoint.
//
// It costs two round trips, and the first one is the destruction record.
// Transit's encrypt endpoint creates a key that does not exist, and a KEK
// this module destroyed is a key that does not exist, so a wrap that did not
// check first would resurrect a shredded KEK as a fresh version 1 — leaving a
// caller unable to tell a pre-shredding record from a post-shredding one.
// Checking first is therefore the fail-closed order, and the answer is
// deliberately not cached: a negative result is exactly the one that must not
// go stale.
func (k *KeyManager) WrapDEK(ctx context.Context, kekID domain.KEKID, keyID domain.KeyID, dek domain.DEK) (domain.WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: wrap DEK: %w", err)
	}
	if err := kekID.Validate(); err != nil {
		return domain.WrappedDEK{}, err
	}
	if err := keyID.Validate(); err != nil {
		return domain.WrappedDEK{}, err
	}
	if err := dek.Validate(); err != nil {
		return domain.WrappedDEK{}, err
	}
	if err := k.refuseIfDestroyed(ctx, kekID); err != nil {
		return domain.WrappedDEK{}, err
	}

	res, err := k.cryptoCall(ctx, kekID, "encrypt", "wrap a DEK under",
		&transitRequest{Plaintext: dek.Bytes(), Context: []byte(keyID)})
	if err != nil {
		return domain.WrappedDEK{}, err
	}
	return record(kekID, keyID, res)
}

// GenerateDEK implements keymanager.KeyManager, over transit's
// datakey/plaintext endpoint: OpenBao mints the DEK and returns it together
// with its wrapped form, so the key material is generated by the key store
// from the key store's entropy rather than by this process.
func (k *KeyManager) GenerateDEK(ctx context.Context, kekID domain.KEKID, keyID domain.KeyID) (domain.DEK, domain.WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: generate DEK: %w", err)
	}
	if err := kekID.Validate(); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	if err := keyID.Validate(); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	if err := k.refuseIfDestroyed(ctx, kekID); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}

	res, err := k.cryptoCall(ctx, kekID, "datakey/plaintext", "generate a DEK under",
		&transitRequest{Context: []byte(keyID), Bits: domain.DEKSize * 8})
	if err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	// The response's copy of the key material is this function's
	// responsibility from here: it is zeroized whatever happens below, so the
	// only copy that outlives the call is the DEK the caller owns.
	defer clear(res.Data.Plaintext)

	wrapped, err := record(kekID, keyID, res)
	if err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	dek, err := domain.DEKFrom(res.Data.Plaintext)
	if err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: generate a DEK under %s: %w", kekID, err)
	}
	return dek, wrapped, nil
}

// UnwrapDEK implements keymanager.KeyManager, over transit's decrypt endpoint.
func (k *KeyManager) UnwrapDEK(ctx context.Context, wrapped domain.WrappedDEK) (domain.DEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.DEK{}, fmt.Errorf("keyring/openbaotransit: unwrap DEK: %w", err)
	}
	ciphertext, err := readableCiphertext(wrapped)
	if err != nil {
		return domain.DEK{}, err
	}

	res, err := k.call(ctx, http.MethodPost, "decrypt/"+keyName(wrapped.KEKID),
		&transitRequest{Ciphertext: ciphertext, Context: []byte(wrapped.KeyID)})
	if err != nil {
		return domain.DEK{}, k.classifyRecord(ctx, wrapped, "unwrap", err)
	}
	defer clear(res.Data.Plaintext)

	dek, err := domain.DEKFrom(res.Data.Plaintext)
	if err != nil {
		// The record authenticated but does not carry a DEK, so it was not
		// written by this module. That is not a trust failure and therefore
		// not ErrUnwrapFailed.
		return domain.DEK{}, fmt.Errorf("keyring/openbaotransit: unwrap DEK under %s %s: %w", wrapped.KEKID, wrapped.KEKVersion, err)
	}
	return dek, nil
}

// RewrapDEK implements keymanager.KeyManager, over transit's rewrap endpoint.
//
// This is the method the adapter is shaped around. Transit rewraps server
// side and its response carries no plaintext field at all, so the DEK does
// not enter this process: a rotation sweep holding a token with rewrap and no
// decrypt capability migrates records it cannot read. There is deliberately
// no unwrap-then-wrap fallback, because a fallback would give that property
// away the first time the endpoint was unavailable, silently and in the one
// situation nobody is watching.
func (k *KeyManager) RewrapDEK(ctx context.Context, wrapped domain.WrappedDEK) (domain.WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: rewrap DEK: %w", err)
	}
	ciphertext, err := readableCiphertext(wrapped)
	if err != nil {
		return domain.WrappedDEK{}, err
	}

	res, err := k.call(ctx, http.MethodPost, "rewrap/"+keyName(wrapped.KEKID),
		&transitRequest{Ciphertext: ciphertext, Context: []byte(wrapped.KeyID)})
	if err != nil {
		return domain.WrappedDEK{}, k.classifyRecord(ctx, wrapped, "rewrap", err)
	}
	return record(wrapped.KEKID, wrapped.KeyID, res)
}

// RotateKEK implements keymanager.KeyManager, over transit's rotate endpoint.
//
// Rotation is not creation, and transit agrees: its rotate endpoint does not
// create a missing key, so a typo in a KEK id is reported rather than minted.
func (k *KeyManager) RotateKEK(ctx context.Context, kekID domain.KEKID) (domain.KEKVersion, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("keyring/openbaotransit: rotate KEK: %w", err)
	}
	if err := kekID.Validate(); err != nil {
		return 0, err
	}

	res, err := k.call(ctx, http.MethodPost, "keys/"+keyName(kekID)+"/rotate", &transitRequest{})
	if err != nil {
		return 0, k.classify(ctx, kekID, "rotate", err)
	}
	version := domain.KEKVersion(res.Data.LatestVersion)
	if err := version.Validate(); err != nil {
		return 0, fmt.Errorf("keyring/openbaotransit: rotate %s: the server reported latest version %d: %w",
			kekID, res.Data.LatestVersion, err)
	}
	return version, nil
}

// DestroyKEK implements keymanager.KeyManager: crypto-shredding, in the only
// form transit can actually promise.
//
// # Which lever, and why it takes both
//
// Transit offers two ways to stop a key's ciphertexts being readable, and
// only one of them erases anything.
//
// min_decryption_version refuses. Raising it makes every ciphertext below it
// fail to decrypt from that instant, it is the fastest lever there is, and it
// needs only the update capability on keys/<name>/config. But it is a policy
// and not an erasure — lowering it again restores those versions from the
// archive — and transit will not let it exceed latest_version, so it can
// never cover the newest version. A KEK "destroyed" by that lever alone would
// still have readable material on the server, which is not what
// ErrKEKDestroyed promises.
//
// Deleting the key erases. DELETE keys/<name> removes every version's
// material, which is what makes the DEKs wrapped under it permanently
// unwrappable and so makes the content those DEKs encrypted permanently
// unreadable in every backup and archive tier that still holds the
// ciphertext. Transit requires deletion_allowed on the key first, which is
// why this method sets it rather than requiring an operator to have done so
// in advance for keys they may never destroy.
//
// So it uses both, in this order: raise min_decryption_version to the latest
// version — every pre-existing record is refused immediately, and that much
// holds even if the delete below is denied by policy — and then delete the
// key, which is the erasure. OpenBao 2.2.1's soft-delete endpoints are
// deliberately not used: a restorable deletion cannot carry a sentinel whose
// documented meaning is permanence.
//
// # The destruction record
//
// Deleting a transit key makes it indistinguishable from one that never
// existed, and the port requires those two to stay distinguishable: an
// erasure certificate must not be able to claim a key was destroyed when
// nothing happened, and a wrap under a destroyed KEK must fail instead of
// minting a fresh version 1. Transit has nowhere to record that fact except
// another key, so this adapter writes a tombstone key (TombstoneNamePrefix
// plus the KEK id) and reads it wherever the difference matters.
//
// The tombstone is written before the material is destroyed, which is the
// fail-closed order: a crash between the two leaves a KEK that reports
// ErrKEKDestroyed while its material still exists, and a retry finishes the
// job. The other order would leave a destroyed KEK looking like one that
// never existed, and the next wrap would resurrect it.
func (k *KeyManager) DestroyKEK(ctx context.Context, kekID domain.KEKID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring/openbaotransit: destroy KEK: %w", err)
	}
	if err := kekID.Validate(); err != nil {
		return err
	}

	key, err := k.readKey(ctx, keyName(kekID))
	if err != nil {
		if !errors.Is(err, domain.ErrKEKNotFound) {
			return fmt.Errorf("keyring/openbaotransit: destroy %s: %w", kekID, err)
		}
		// There is no material left to destroy. Either this is a retry of a
		// destruction that already completed, which must converge, or the KEK
		// never existed, which must not be reported as an erasure.
		destroyed, tombErr := k.isDestroyed(ctx, kekID)
		if tombErr != nil {
			return fmt.Errorf("keyring/openbaotransit: destroy %s: %w", kekID, tombErr)
		}
		if destroyed {
			return nil
		}
		return fmt.Errorf("%w: %s", domain.ErrKEKNotFound, kekID)
	}

	if err := k.writeTombstone(ctx, kekID); err != nil {
		return fmt.Errorf("keyring/openbaotransit: destroy %s: %w", kekID, err)
	}

	allowed := true
	latest := key.Data.LatestVersion
	config := &transitRequest{MinDecryptionVersion: &latest, DeletionAllowed: &allowed}
	if _, err := k.call(ctx, http.MethodPost, "keys/"+keyName(kekID)+"/config", config); err != nil {
		return fmt.Errorf("keyring/openbaotransit: destroy %s: disallow the key's earlier versions: %w", kekID, err)
	}
	if _, err := k.call(ctx, http.MethodDelete, "keys/"+keyName(kekID), nil); err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.says("not found") {
			// Another process completed the same destruction in between.
			return nil
		}
		return fmt.Errorf("keyring/openbaotransit: destroy %s: delete the key: %w", kekID, err)
	}
	return nil
}

// cryptoCall performs one key-using call — encrypt or datakey/plaintext —
// creating the KEK and retrying once if it does not exist yet.
//
// Transit's encrypt and datakey endpoints create a missing key themselves,
// with derivation enabled because the request carries a context, so the
// common path is a single call. The explicit creation is for a mount
// configured with disable_upsert, where that does not happen; without it this
// adapter would work until an operator tightened the mount.
func (k *KeyManager) cryptoCall(ctx context.Context, kekID domain.KEKID, endpoint, operation string, req *transitRequest) (*transitResponse, error) {
	path := endpoint + "/" + keyName(kekID)

	res, err := k.call(ctx, http.MethodPost, path, req)
	if err == nil {
		return res, nil
	}
	created, createErr := k.createKEKIfMissing(ctx, kekID, err)
	if createErr != nil {
		return nil, createErr
	}
	if !created {
		return nil, k.classify(ctx, kekID, operation, err)
	}
	res, err = k.call(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, k.classify(ctx, kekID, operation, err)
	}
	return res, nil
}

// createKEKIfMissing creates the KEK when cause says it does not exist,
// reporting whether it did. Any other cause is left for the caller to
// classify.
func (k *KeyManager) createKEKIfMissing(ctx context.Context, kekID domain.KEKID, cause error) (bool, error) {
	var apiErr *apiError
	if !errors.As(cause, &apiErr) || !apiErr.says("key not found") {
		return false, nil
	}

	derived := true
	create := &transitRequest{Type: transitKeyType, Derived: &derived}
	if _, err := k.call(ctx, http.MethodPost, "keys/"+keyName(kekID), create); err != nil {
		return false, fmt.Errorf("keyring/openbaotransit: create the KEK %s: %w", kekID, err)
	}
	return true, nil
}

// classify maps a failed call naming a KEK onto this module's sentinels. The
// only message that needs the server consulted again is a missing key, which
// may mean destroyed; everything else is decided from the response in hand.
func (k *KeyManager) classify(ctx context.Context, kekID domain.KEKID, operation string, cause error) error {
	var apiErr *apiError
	if errors.As(cause, &apiErr) && apiErr.says("key not found") {
		destroyed, err := k.isDestroyed(ctx, kekID)
		if err != nil {
			return fmt.Errorf("keyring/openbaotransit: %s %s: %w", operation, kekID, err)
		}
		if destroyed {
			return fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, kekID)
		}
		return fmt.Errorf("%w: %s", domain.ErrKEKNotFound, kekID)
	}
	return fmt.Errorf("keyring/openbaotransit: %s %s: %w", operation, kekID, cause)
}

// classifyRecord maps a failed decrypt or rewrap onto this module's
// sentinels. Every cryptographic refusal becomes the single ErrUnwrapFailed
// with no hint of which one it was: a key manager that distinguishes a wrong
// key from a wrong derivation context from a flipped byte is an oracle for
// whoever is holding a record they should not have (see
// domain.ErrUnwrapFailed).
func (k *KeyManager) classifyRecord(ctx context.Context, wrapped domain.WrappedDEK, operation string, cause error) error {
	var apiErr *apiError
	if !errors.As(cause, &apiErr) {
		return fmt.Errorf("keyring/openbaotransit: %s a DEK under %s %s: %w",
			operation, wrapped.KEKID, wrapped.KEKVersion, cause)
	}
	switch {
	case apiErr.says("key not found"):
		return k.classify(ctx, wrapped.KEKID, operation+" a DEK under", cause)
	case apiErr.saysAny(
		"message authentication failed",
		"invalid ciphertext",
		"disallowed by policy",
		"missing ciphertext",
		"could not decode",
		"key derivation",
	):
		return fmt.Errorf("%w: %s %s key %s", domain.ErrUnwrapFailed, wrapped.KEKID, wrapped.KEKVersion, wrapped.KeyID)
	default:
		return fmt.Errorf("keyring/openbaotransit: %s a DEK under %s %s: %w",
			operation, wrapped.KEKID, wrapped.KEKVersion, cause)
	}
}

// refuseIfDestroyed returns domain.ErrKEKDestroyed if the KEK has been
// destroyed. It is the check every write goes through before it writes.
func (k *KeyManager) refuseIfDestroyed(ctx context.Context, kekID domain.KEKID) error {
	destroyed, err := k.isDestroyed(ctx, kekID)
	if err != nil {
		return fmt.Errorf("keyring/openbaotransit: check whether %s was destroyed: %w", kekID, err)
	}
	if destroyed {
		return fmt.Errorf("%w: %s", domain.ErrKEKDestroyed, kekID)
	}
	return nil
}

// isDestroyed reports whether this KEK's tombstone exists.
func (k *KeyManager) isDestroyed(ctx context.Context, kekID domain.KEKID) (bool, error) {
	_, err := k.readKey(ctx, tombstoneName(kekID))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, domain.ErrKEKNotFound):
		return false, nil
	default:
		return false, err
	}
}

// writeTombstone records this KEK's destruction, idempotently: creating a
// transit key that already exists is a no-op, so a retried erasure does not
// fail on its own earlier success.
func (k *KeyManager) writeTombstone(ctx context.Context, kekID domain.KEKID) error {
	if _, err := k.call(ctx, http.MethodPost, "keys/"+tombstoneName(kekID), &transitRequest{Type: transitKeyType}); err != nil {
		return fmt.Errorf("record the destruction of %s: %w", kekID, err)
	}
	return nil
}

// readKey reads one transit key's configuration, mapping "no such key" onto
// domain.ErrKEKNotFound. It is the one GET this adapter makes, and the
// authoritative answer to whether a key exists: a read is a 404, where the
// crypto endpoints answer the same fact with a 400 and a message.
func (k *KeyManager) readKey(ctx context.Context, name string) (*transitResponse, error) {
	res, err := k.call(ctx, http.MethodGet, "keys/"+name, nil)
	if err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && (apiErr.status == http.StatusNotFound || apiErr.says("key not found")) {
			return nil, domain.ErrKEKNotFound
		}
		return nil, err
	}
	return res, nil
}

// call performs one transit request and decodes its response.
//
// The request and response buffers are this package's own and are zeroized
// before returning, so the base64 of a DEK does not sit in a heap buffer
// after the call. Decoding into a []byte field — which encoding/json
// base64-decodes from the response bytes directly — rather than into a string
// is deliberate for the same reason: a Go string holding key material cannot
// be cleared.
func (k *KeyManager) call(ctx context.Context, method, path string, body *transitRequest) (*transitResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			// Deliberately rendered without the body: a marshalling failure
			// on a request carrying a DEK must not print the request.
			return nil, fmt.Errorf("keyring/openbaotransit: encode a %s request: %w", method, err)
		}
		defer clear(encoded)
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, k.base+"/v1/"+k.mount+"/"+path, reader)
	if err != nil {
		return nil, fmt.Errorf("keyring/openbaotransit: build a %s request: %w", method, err)
	}
	req.Header.Set("X-Vault-Token", k.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := k.client.Do(req)
	if err != nil {
		// A *url.Error wraps the context's error, so errors.Is sees a
		// cancellation or a deadline through this.
		return nil, fmt.Errorf("keyring/openbaotransit: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("keyring/openbaotransit: read the response to %s: %w", method, err)
	}
	defer clear(raw)

	ok := resp.StatusCode >= 200 && resp.StatusCode <= 299
	var decoded transitResponse
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			if !ok {
				// A non-2xx whose body is not the usual JSON: a proxy, or a
				// server that is not OpenBao. The status is all there is.
				return nil, &apiError{status: resp.StatusCode}
			}
			return nil, fmt.Errorf("keyring/openbaotransit: decode the response to %s: %w", method, err)
		}
	}
	if !ok {
		return nil, &apiError{status: resp.StatusCode, messages: decoded.Errors}
	}
	return &decoded, nil
}

// transitRequest is the union of the fields this adapter sends. Every field is
// omitted when unset, so one type serves six endpoints without any of them
// receiving a field it would reject.
//
// Plaintext and Context are []byte rather than string because encoding/json
// writes a []byte as standard base64, which is transit's encoding for both —
// so key material is never turned into a string on the way out either.
type transitRequest struct {
	Plaintext            []byte  `json:"plaintext,omitempty"`
	Ciphertext           string  `json:"ciphertext,omitempty"`
	Context              []byte  `json:"context,omitempty"`
	Bits                 int     `json:"bits,omitempty"`
	Type                 string  `json:"type,omitempty"`
	Derived              *bool   `json:"derived,omitempty"`
	MinDecryptionVersion *uint32 `json:"min_decryption_version,omitempty"`
	DeletionAllowed      *bool   `json:"deletion_allowed,omitempty"`
}

// transitResponse is the union of the fields this adapter reads. Plaintext is
// []byte so that encoding/json base64-decodes it into a buffer this package
// owns and can zeroize.
type transitResponse struct {
	Data struct {
		Ciphertext    string `json:"ciphertext"`
		Plaintext     []byte `json:"plaintext"`
		KeyVersion    uint32 `json:"key_version"`
		LatestVersion uint32 `json:"latest_version"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// apiError is a non-2xx transit response: its status and the messages the
// server returned. It deliberately does not carry the request, so a request
// that contained a DEK cannot be rendered through it, and it never carries
// the token.
type apiError struct {
	status   int
	messages []string
}

// Error renders the status and the server's messages.
func (e *apiError) Error() string {
	if len(e.messages) == 0 {
		return "openbao transit returned HTTP " + strconv.Itoa(e.status)
	}
	return "openbao transit returned HTTP " + strconv.Itoa(e.status) + ": " + strings.Join(e.messages, "; ")
}

// says reports whether any of the server's messages contains substring.
// Transit answers almost everything with a 400, so its message is the only
// thing that distinguishes a missing key from a forged ciphertext; the
// reading happens here, once, rather than at every call site.
func (e *apiError) says(substring string) bool {
	for _, message := range e.messages {
		if strings.Contains(message, substring) {
			return true
		}
	}
	return false
}

// saysAny reports whether any of the server's messages contains any of the
// substrings.
func (e *apiError) saysAny(substrings ...string) bool {
	for _, substring := range substrings {
		if e.says(substring) {
			return true
		}
	}
	return false
}

// record turns a transit response into the record a caller persists.
//
// The version recorded is the one the ciphertext itself carries. The two must
// agree for the record to be readable later — readableCiphertext refuses a
// record whose claimed version differs — so taking the version from anywhere
// else would be writing a record that fails its own check.
func record(kekID domain.KEKID, keyID domain.KeyID, res *transitResponse) (domain.WrappedDEK, error) {
	if res.Data.Ciphertext == "" {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: %s returned no ciphertext", kekID)
	}
	version, ok := ciphertextVersion(res.Data.Ciphertext)
	if !ok {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: %s returned a ciphertext with no key version", kekID)
	}
	if res.Data.KeyVersion != 0 && domain.KEKVersion(res.Data.KeyVersion) != version {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: %s reported key version %d for a %s ciphertext",
			kekID, res.Data.KeyVersion, version)
	}
	wrapped := domain.WrappedDEK{
		KEKID:      kekID,
		KEKVersion: version,
		KeyID:      keyID,
		Ciphertext: []byte(res.Data.Ciphertext),
	}
	if err := wrapped.Validate(); err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/openbaotransit: %s produced an unusable record: %w", kekID, err)
	}
	return wrapped, nil
}

// readableCiphertext validates a record this adapter is being asked to read
// and returns its ciphertext as the string the API takes.
//
// The version the record claims is checked against the version the ciphertext
// carries, before any request is made. A transit ciphertext names its own key
// version, so without this check the server would decrypt under whichever
// version the bytes name while the record claimed another, and a caller
// relabelling records would never find out. The port requires that mismatch
// to fail; this is where it fails.
func readableCiphertext(wrapped domain.WrappedDEK) (string, error) {
	if err := wrapped.Validate(); err != nil {
		return "", err
	}
	// Deliberately uninformative, exactly like a failed decrypt: which part
	// of a forged record was wrong is not a caller's business (see
	// domain.ErrUnwrapFailed).
	unwrapFailed := fmt.Errorf("%w: %s %s key %s",
		domain.ErrUnwrapFailed, wrapped.KEKID, wrapped.KEKVersion, wrapped.KeyID)

	if !isPrintableASCII(wrapped.Ciphertext) {
		// Not a transit ciphertext at all. Refused here rather than sent,
		// because JSON cannot carry these bytes faithfully and the server
		// would then be judging something other than what the record holds.
		return "", unwrapFailed
	}
	ciphertext := string(wrapped.Ciphertext)
	version, ok := ciphertextVersion(ciphertext)
	if !ok || version != wrapped.KEKVersion {
		return "", unwrapFailed
	}
	return ciphertext, nil
}

// keyName is the transit key name for a KEK id, escaped for use in a URL
// path. A KEK id is validated to be a single path component with no
// separators or control characters, but it may still contain a character that
// means something in a URL ("?" or "#"), so it is escaped rather than
// trusted.
func keyName(kekID domain.KEKID) string {
	return url.PathEscape(KeyNamePrefix + string(kekID))
}

// tombstoneName is the transit key name of a KEK's destruction record.
func tombstoneName(kekID domain.KEKID) string {
	return url.PathEscape(TombstoneNamePrefix + string(kekID))
}

// mountPath validates and escapes a mount path, defaulting to
// DefaultMountPath. A nested mount is allowed; an empty segment, a relative
// element and a control character are not.
func mountPath(configured string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(configured), "/")
	if trimmed == "" {
		trimmed = DefaultMountPath
	}
	segments := strings.Split(trimmed, "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("%w: MountPath %q is not a usable mount path", domain.ErrInvalidConfig, configured)
		}
		for _, r := range segment {
			if r < 0x20 || r == 0x7F {
				return "", fmt.Errorf("%w: MountPath %q contains a control character", domain.ErrInvalidConfig, configured)
			}
		}
		escaped = append(escaped, url.PathEscape(segment))
	}
	return strings.Join(escaped, "/"), nil
}

// ciphertextVersion reads the key version out of a transit ciphertext
// ("vault:v3:…"), which is the version that will be used to decrypt it
// whatever a record claims.
func ciphertextVersion(ciphertext string) (domain.KEKVersion, bool) {
	prefix, rest, ok := strings.Cut(ciphertext, ":")
	if !ok || !slices.Contains(ciphertextPrefixes, prefix) {
		return 0, false
	}
	field, payload, ok := strings.Cut(rest, ":")
	if !ok || payload == "" {
		return 0, false
	}
	digits, ok := strings.CutPrefix(field, "v")
	if !ok {
		return 0, false
	}
	version, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0, false
	}
	parsed := domain.KEKVersion(version)
	if parsed.Validate() != nil {
		return 0, false
	}
	return parsed, true
}

// isPrintableASCII reports whether b is entirely printable, non-space ASCII,
// which every transit ciphertext is. Anything else cannot survive a JSON
// round trip unchanged, so it is not sent.
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x21 || c > 0x7E {
			return false
		}
	}
	return true
}

// The adapter is held to the port at compile time.
var _ keymanager.KeyManager = (*KeyManager)(nil)
