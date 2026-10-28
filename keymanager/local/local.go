// Package local is the default key manager adapter: KEK material lives in a
// KEKStore, each version wrapped under a deployment root key that comes from
// configuration or a file, and DEKs are wrapped with AES-256-GCM using
// nothing but the standard library. It is the only adapter a single binary
// needs, and it is deliberately the one with no external service in its
// startup path — CAS design §8.3 forbids making a secrets service a
// requirement to boot.
//
// What it does not give you is the one thing openbao-transit does: the root
// key is in this process's address space, so an operator who can read the
// process (or the file, or the environment) can read it. Everything else —
// per-object DEKs, per-tenant KEKs, lazy rotation, crypto-shredding — is
// identical, which is why swapping adapters later is a configuration change
// and not a migration.
//
// # Wire format
//
// A wrapped DEK's ciphertext, and the wrapped KEK material in the store, are
// both this layout, which is committed: a record written by one build must
// be readable by the next.
//
//	byte 0        format version (WrapFormatVersion)
//	bytes 1..16   salt, random per record
//	bytes 17..28  AES-GCM nonce, random per record
//	bytes 29..    AES-256-GCM ciphertext and 16-byte tag
//
// The encryption key for each record is derived per record:
// HKDF-SHA256(wrapping key, salt, info), so no two records are sealed under
// the same AES key and the nonce-reuse bound that otherwise limits how many
// DEKs one KEK may wrap does not apply. The random nonce on top of a
// single-use derived key is belt and braces, not a requirement.
//
// The additional authenticated data binds each record to the identifiers it
// was created for — a DEK record to its KEK id, KEK version and key id; a
// KEK record to its KEK id and version — so a record moved to another row,
// or relabelled with a different version, fails to authenticate instead of
// yielding a key for content it does not belong to. Identifiers cannot
// contain a null byte (domain validates that), so the null-separated
// encoding below is unambiguous.
package local

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/laenenai/keyring/internal/domain"
)

// WrapFormatVersion is the first byte of every record this adapter writes.
// An unknown version is an unwrap failure, not a best-effort parse: a record
// this build does not understand must never be guessed at.
const WrapFormatVersion = 0x01

// MinRootKeyLen is the shortest deployment root key Open accepts, in bytes.
// It is the AES-256 key length because the root key is the single secret the
// whole key hierarchy rests on; a shorter one would make the rest of the
// scheme's 256-bit keys decorative.
const MinRootKeyLen = 32

const (
	// saltLen is the per-record HKDF salt length.
	saltLen = 16
	// nonceLen is the AES-GCM standard nonce length.
	nonceLen = 12
	// kekMaterialLen is the length of the AES-256 key that is a KEK.
	kekMaterialLen = 32
	// headerLen is the fixed prefix of every record: format version, salt,
	// nonce.
	headerLen = 1 + saltLen + nonceLen
)

// Info strings for the three HKDF derivations this adapter performs. They
// are distinct so that material derived for one purpose can never be used
// for another, even if the same input key material were somehow reused.
const (
	rootWrapInfo = "keyring/local/root-wrap/v1"
	recordInfo   = "keyring/local/record/v1"
)

// Domain-separation prefixes for the additional authenticated data of the
// two record kinds. A DEK record and a KEK record can never be swapped for
// one another even if their identifiers coincide.
const (
	dekAADPrefix = "keyring/local/dek/v1"
	kekAADPrefix = "keyring/local/kek/v1"
)

// RootKeyEncoding names how a RootKeyFile's contents are encoded. It is
// required whenever RootKeyFile is set; there is no auto-detection, because a
// truncated or mis-encoded key that silently decodes to different bytes is
// indistinguishable from a correct deployment until records fail to unwrap.
type RootKeyEncoding string

const (
	// RootKeyEncodingRaw uses the file byte-for-byte. A trailing newline is
	// part of the key; use printf, not echo, when writing a raw key file.
	RootKeyEncodingRaw RootKeyEncoding = "raw"
	// RootKeyEncodingHex decodes hexadecimal text (case-insensitive).
	RootKeyEncodingHex RootKeyEncoding = "hex"
	// RootKeyEncodingBase64 decodes standard or URL base64, padded or raw.
	RootKeyEncodingBase64 RootKeyEncoding = "base64"
)

// Config configures the local adapter. Exactly one of RootKey and
// RootKeyFile must be set, Store is required, and RootKeyEncoding is required
// when RootKeyFile is used.
type Config struct {
	// RootKey is the deployment root key as raw bytes, at least
	// MinRootKeyLen of them. Use it when the key reaches the process as a
	// value the caller has already decoded (an environment variable, a
	// Kubernetes secret, a SOPS-decrypted field).
	RootKey []byte

	// RootKeyFile is a path to read the root key from, as an alternative to
	// RootKey. RootKeyEncoding selects the decoding; there is deliberately
	// no fallback chain, so a malformed file fails at Open instead of
	// silently using a different key.
	//
	// How the file gets there is the operator's business and not this
	// module's: a mounted secret, a SOPS-decrypted file, a tmpfs path
	// written at boot.
	RootKeyFile string

	// RootKeyEncoding is how RootKeyFile is encoded: raw, hex or base64.
	// It is ignored when RootKey is used and required when RootKeyFile is.
	RootKeyEncoding RootKeyEncoding

	// Store is where wrapped KEK material lives. It is required, with no
	// in-memory default, because the default most likely to be reached for
	// by accident is also the one whose failure mode is the permanent loss
	// of every encrypted byte — see MemKEKStore, which a test or a
	// deliberately ephemeral process can pass explicitly.
	Store KEKStore
}

// String renders the configuration with the deployment root key redacted,
// and with the path it may have been read from redacted too: in a container
// that path is a mounted secret, and naming it describes the deployment's
// secret handling to anyone reading the log. The store is named by type,
// which is the part that is worth having in a log line.
//
// This and the three methods below exist because Config is the single most
// likely place for the deployment root key to escape — a caller that logs or
// serializes its configuration at startup is doing the normal thing, and
// before these methods that printed the root key. See CONVENTIONS.md's
// "Rendering a secret".
func (c Config) String() string {
	return fmt.Sprintf("local.Config{RootKey: %s, RootKeyFile: %s, RootKeyEncoding: %q, Store: %T}",
		domain.Redacted, domain.Redacted, c.RootKeyEncoding, c.Store)
}

// Format implements fmt.Formatter, which is the only interface fmt consults
// for every verb. Without it, %#v, %d and %c reflect the struct and print
// RootKey byte by byte, whatever String says.
func (c Config) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }

// MarshalJSON renders the same redacted summary as a JSON string. Without
// it, encoding/json reaches RootKey through its exported field and emits the
// deployment root key as base64 — the one encoding that survives being
// pasted anywhere.
func (c Config) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// MarshalXML renders a redacted configuration. encoding/xml consults neither
// String nor MarshalJSON, so without this method it would reach RootKey
// through its exported field.
func (c Config) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	redacted := struct {
		RootKey         string `xml:"RootKey"`
		RootKeyFile     string `xml:"RootKeyFile"`
		RootKeyEncoding string `xml:"RootKeyEncoding"`
		Store           string `xml:"Store"`
	}{
		RootKey:         domain.Redacted,
		RootKeyFile:     domain.Redacted,
		RootKeyEncoding: string(c.RootKeyEncoding),
		Store:           fmt.Sprintf("%T", c.Store),
	}
	return e.EncodeElement(redacted, start)
}

// GobEncode makes gob encode only the redacted summary. gob does not consult
// String or MarshalJSON and would otherwise encode the exported RootKey.
func (c Config) GobEncode() ([]byte, error) { return []byte(c.String()), nil }

// LogValue renders the configuration as a slog group with the root key and
// its path redacted, so slog.Any("config", cfg) is safe under every handler.
// slog's JSONHandler marshals a non-LogValuer attribute with encoding/json
// and therefore does not consult String at all, which is why this is needed
// in addition to MarshalJSON rather than instead of it.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("root_key", domain.Redacted),
		slog.String("root_key_file", domain.Redacted),
		slog.String("root_key_encoding", string(c.RootKeyEncoding)),
		slog.String("store", fmt.Sprintf("%T", c.Store)),
	)
}

// KeyManager is the local adapter's implementation of
// keymanager.KeyManager. Open returns one; it is safe for concurrent use.
//
// The state is behind a pointer so that a value copy is still a view of the
// same manager and, more importantly, so the redaction methods can have value
// receivers. A pointer-receiver-only redaction method is not in the method set
// of a dereferenced KeyManager, which would let fmt reflect wrapKey.
type KeyManager struct {
	state *keyManagerState
}

type keyManagerState struct {
	// wrapKey is the AES-256 key that wraps KEK material, derived from the
	// deployment root key. The root key itself is not retained: once this
	// is derived there is no operation left that needs it, so keeping it
	// would only widen the window in which a process dump contains it.
	wrapKey []byte

	// store holds wrapped KEK material and destruction records.
	store KEKStore

	// mu serializes the operations that create KEK versions — the implicit
	// creation inside WrapDEK and RotateKEK — so that two goroutines in
	// this process cannot both decide they are creating the same version.
	// Across processes that race is resolved by the store instead, which
	// reports ErrKEKVersionExists to the loser; this mutex just keeps the
	// common single-process case from relying on it.
	mu sync.Mutex
}

// Open validates cfg and returns a key manager over it.
//
// It returns domain.ErrInvalidConfig for anything that cannot produce a
// working manager: no root key, both a key and a key file, a key shorter
// than MinRootKeyLen, an all-zero key (which is a misconfigured secret, not
// a key), an unreadable or undecodable key file, or no store. The error
// never contains the root key.
func Open(ctx context.Context, cfg Config) (*KeyManager, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keyring/local: open: %w", err)
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: Store is required; pass a persistent KEKStore, or local.NewMemKEKStore() for a process whose data need not outlive it", domain.ErrInvalidConfig)
	}

	root, err := rootKeyFrom(cfg)
	if err != nil {
		return nil, err
	}
	// The root key is needed only to derive the wrapping key; zeroize this
	// copy of it as soon as that is done.
	defer clear(root)

	wrapKey, err := hkdf.Key(sha256.New, root, nil, rootWrapInfo, kekMaterialLen)
	if err != nil {
		return nil, fmt.Errorf("keyring/local: derive the KEK wrapping key: %w", err)
	}
	return &KeyManager{state: &keyManagerState{wrapKey: wrapKey, store: cfg.Store}}, nil
}

// WrapDEK implements keymanager.KeyManager.
func (k *KeyManager) WrapDEK(ctx context.Context, kekID domain.KEKID, keyID domain.KeyID, dek domain.DEK) (domain.WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/local: wrap DEK: %w", err)
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

	version, err := k.currentOrCreatedVersion(ctx, kekID)
	if err != nil {
		return domain.WrappedDEK{}, err
	}

	material, err := k.kekMaterial(ctx, kekID, version)
	if err != nil {
		return domain.WrappedDEK{}, err
	}
	defer clear(material)

	ciphertext, err := sealRecord(material, dek.Bytes(), dekAAD(kekID, version, keyID))
	if err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/local: wrap DEK under %s %s: %w", kekID, version, err)
	}
	return domain.WrappedDEK{
		KEKID:      kekID,
		KEKVersion: version,
		KeyID:      keyID,
		Ciphertext: ciphertext,
	}, nil
}

// GenerateDEK implements keymanager.KeyManager.
//
// This adapter has no remote key store to generate inside, so it mints the
// DEK here, from crypto/rand, and wraps it on the same terms as WrapDEK. The
// method exists on the port for the transit adapter's sake, where the DEK is
// generated by the key store itself; an adapter that cannot do that must
// still be usable through the same call, or callers would have to branch on
// which key manager they were configured with.
func (k *KeyManager) GenerateDEK(ctx context.Context, kekID domain.KEKID, keyID domain.KeyID) (domain.DEK, domain.WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, fmt.Errorf("keyring/local: generate DEK: %w", err)
	}
	// Validate before drawing entropy, so a caller's typo does not consume
	// randomness and so the error is the same one WrapDEK would have given.
	if err := kekID.Validate(); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	if err := keyID.Validate(); err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}

	dek, err := domain.NewDEK()
	if err != nil {
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	wrapped, err := k.WrapDEK(ctx, kekID, keyID, dek)
	if err != nil {
		// A DEK that was never wrapped is of no use to anyone, and handing it
		// back alongside an error is how key material escapes.
		dek.Destroy()
		return domain.DEK{}, domain.WrappedDEK{}, err
	}
	return dek, wrapped, nil
}

// UnwrapDEK implements keymanager.KeyManager.
func (k *KeyManager) UnwrapDEK(ctx context.Context, wrapped domain.WrappedDEK) (domain.DEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.DEK{}, fmt.Errorf("keyring/local: unwrap DEK: %w", err)
	}
	if err := wrapped.Validate(); err != nil {
		return domain.DEK{}, err
	}

	material, err := k.kekMaterial(ctx, wrapped.KEKID, wrapped.KEKVersion)
	if err != nil {
		return domain.DEK{}, err
	}
	defer clear(material)

	plaintext, err := openRecord(material, wrapped.Ciphertext, dekAAD(wrapped.KEKID, wrapped.KEKVersion, wrapped.KeyID))
	if err != nil {
		// Deliberately no detail about which part failed, and no mention of
		// the record's contents: see domain.ErrUnwrapFailed.
		return domain.DEK{}, fmt.Errorf("%w: %s %s key %s", domain.ErrUnwrapFailed, wrapped.KEKID, wrapped.KEKVersion, wrapped.KeyID)
	}
	defer clear(plaintext)

	dek, err := domain.DEKFrom(plaintext)
	if err != nil {
		// The record authenticated but does not carry a usable DEK, which
		// means it was written by something that did not respect this
		// format. It is not a trust failure, so it is not ErrUnwrapFailed.
		return domain.DEK{}, fmt.Errorf("keyring/local: unwrap DEK under %s %s: %w", wrapped.KEKID, wrapped.KEKVersion, err)
	}
	return dek, nil
}

// RewrapDEK implements keymanager.KeyManager.
//
// # The DEK is in this process during a re-wrap, and cannot not be
//
// The port says RewrapDEK must not be unwrap-then-wrap because transit's
// rewrap endpoint never returns plaintext, so a rotation sweep there need not
// be trusted with the keys it migrates. This adapter cannot offer that: the
// KEK material lives in this process, so re-encrypting a record means
// decrypting it here. What it does offer is the same *interface* guarantee —
// the DEK is never returned to the caller, and the plaintext is zeroized
// before this function returns — so a caller's rotation code is identical on
// both adapters and gets the stronger property as soon as it is pointed at
// transit. That difference is a property of where the key lives, which is the
// one thing this adapter is documented as not fixing.
func (k *KeyManager) RewrapDEK(ctx context.Context, wrapped domain.WrappedDEK) (domain.WrappedDEK, error) {
	if err := ctx.Err(); err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/local: rewrap DEK: %w", err)
	}
	if err := wrapped.Validate(); err != nil {
		return domain.WrappedDEK{}, err
	}

	// Re-wrapping is not creation: a KEK with no current version is
	// ErrKEKNotFound, and a destroyed one is ErrKEKDestroyed, both reported by
	// the store.
	current, err := k.state.store.CurrentKEKVersion(ctx, wrapped.KEKID)
	if err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/local: rewrap under %s: %w", wrapped.KEKID, err)
	}

	oldMaterial, err := k.kekMaterial(ctx, wrapped.KEKID, wrapped.KEKVersion)
	if err != nil {
		return domain.WrappedDEK{}, err
	}
	defer clear(oldMaterial)

	plaintext, err := openRecord(oldMaterial, wrapped.Ciphertext, dekAAD(wrapped.KEKID, wrapped.KEKVersion, wrapped.KeyID))
	if err != nil {
		// The same deliberately uninformative answer UnwrapDEK gives: a
		// re-wrap of a forged record must not be an oracle either.
		return domain.WrappedDEK{}, fmt.Errorf("%w: %s %s key %s", domain.ErrUnwrapFailed, wrapped.KEKID, wrapped.KEKVersion, wrapped.KeyID)
	}
	defer clear(plaintext)

	// Validated rather than re-sealed blindly: a record that authenticates
	// but does not carry a DEK was written by something that did not respect
	// this format, and re-wrapping it would propagate the damage into a
	// record that looks freshly migrated.
	dek, err := domain.DEKFrom(plaintext)
	if err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/local: rewrap DEK under %s %s: %w", wrapped.KEKID, wrapped.KEKVersion, err)
	}
	defer dek.Destroy()

	newMaterial, err := k.kekMaterial(ctx, wrapped.KEKID, current)
	if err != nil {
		return domain.WrappedDEK{}, err
	}
	defer clear(newMaterial)

	ciphertext, err := sealRecord(newMaterial, dek.Bytes(), dekAAD(wrapped.KEKID, current, wrapped.KeyID))
	if err != nil {
		return domain.WrappedDEK{}, fmt.Errorf("keyring/local: rewrap DEK under %s %s: %w", wrapped.KEKID, current, err)
	}
	return domain.WrappedDEK{
		KEKID:      wrapped.KEKID,
		KEKVersion: current,
		KeyID:      wrapped.KeyID,
		Ciphertext: ciphertext,
	}, nil
}

// RotateKEK implements keymanager.KeyManager.
func (k *KeyManager) RotateKEK(ctx context.Context, kekID domain.KEKID) (domain.KEKVersion, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("keyring/local: rotate KEK: %w", err)
	}
	if err := kekID.Validate(); err != nil {
		return 0, err
	}

	k.state.mu.Lock()
	defer k.state.mu.Unlock()

	// Rotation is not creation: a KEK with no current version is
	// ErrKEKNotFound, so a typo in a KEK id cannot mint a key.
	current, err := k.state.store.CurrentKEKVersion(ctx, kekID)
	if err != nil {
		return 0, fmt.Errorf("keyring/local: rotate %s: %w", kekID, err)
	}

	next := current.Next()
	if err := k.createVersion(ctx, kekID, next); err != nil {
		if errors.Is(err, ErrKEKVersionExists) {
			// Another process rotated the same KEK first. Its version is as
			// good as the one this call would have made, so report that
			// rather than failing a caller whose intent — "there is now a
			// newer version" — has been satisfied.
			rotated, readErr := k.state.store.CurrentKEKVersion(ctx, kekID)
			if readErr != nil {
				return 0, fmt.Errorf("keyring/local: rotate %s: re-read after a concurrent rotation: %w", kekID, readErr)
			}
			return rotated, nil
		}
		return 0, err
	}
	return next, nil
}

// DestroyKEK implements keymanager.KeyManager.
func (k *KeyManager) DestroyKEK(ctx context.Context, kekID domain.KEKID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("keyring/local: destroy KEK: %w", err)
	}
	if err := kekID.Validate(); err != nil {
		return err
	}

	k.state.mu.Lock()
	defer k.state.mu.Unlock()

	if err := k.state.store.DestroyKEK(ctx, kekID); err != nil {
		return fmt.Errorf("keyring/local: destroy %s: %w", kekID, err)
	}
	return nil
}

// currentOrCreatedVersion returns the KEK's current version, creating the
// KEK at domain.FirstKEKVersion if it does not exist yet. A destroyed KEK is
// never created again: the store reports domain.ErrKEKDestroyed and that is
// propagated unchanged.
func (k *KeyManager) currentOrCreatedVersion(ctx context.Context, kekID domain.KEKID) (domain.KEKVersion, error) {
	current, err := k.state.store.CurrentKEKVersion(ctx, kekID)
	switch {
	case err == nil:
		return current, nil
	case !errors.Is(err, domain.ErrKEKNotFound):
		return 0, fmt.Errorf("keyring/local: read the current version of %s: %w", kekID, err)
	}

	k.state.mu.Lock()
	defer k.state.mu.Unlock()

	// Re-read under the lock: another goroutine may have created the KEK
	// between the read above and here.
	if current, err := k.state.store.CurrentKEKVersion(ctx, kekID); err == nil {
		return current, nil
	} else if !errors.Is(err, domain.ErrKEKNotFound) {
		return 0, fmt.Errorf("keyring/local: read the current version of %s: %w", kekID, err)
	}

	if err := k.createVersion(ctx, kekID, domain.FirstKEKVersion); err != nil {
		if errors.Is(err, ErrKEKVersionExists) {
			// Another process won the race; its version 1 is the KEK now.
			current, readErr := k.state.store.CurrentKEKVersion(ctx, kekID)
			if readErr != nil {
				return 0, fmt.Errorf("keyring/local: read %s after a concurrent creation: %w", kekID, readErr)
			}
			return current, nil
		}
		return 0, err
	}
	return domain.FirstKEKVersion, nil
}

// createVersion mints fresh random KEK material, wraps it under the root
// wrapping key, and stores it as the named version. Callers hold the state mutex.
func (k *KeyManager) createVersion(ctx context.Context, kekID domain.KEKID, version domain.KEKVersion) error {
	material := make([]byte, kekMaterialLen)
	if _, err := rand.Read(material); err != nil {
		return fmt.Errorf("keyring/local: read entropy for %s %s: %w", kekID, version, err)
	}
	defer clear(material)

	wrapped, err := sealRecord(k.state.wrapKey, material, kekAAD(kekID, version))
	if err != nil {
		return fmt.Errorf("keyring/local: wrap %s %s under the root key: %w", kekID, version, err)
	}
	if err := k.state.store.CreateKEKVersion(ctx, kekID, version, wrapped); err != nil {
		// ErrKEKVersionExists is handled by callers and must stay
		// recognizable through the wrapping.
		return fmt.Errorf("keyring/local: store %s %s: %w", kekID, version, err)
	}
	return nil
}

// kekMaterial reads one KEK version's wrapped material from the store and
// unwraps it under the root wrapping key. The caller must zeroize the
// returned slice.
//
// A record that does not authenticate here means the store's contents were
// not written under this root key — a swapped key file, the wrong
// deployment's database — and is reported as domain.ErrUnwrapFailed, the
// same opaque answer as a forged DEK record.
func (k *KeyManager) kekMaterial(ctx context.Context, kekID domain.KEKID, version domain.KEKVersion) ([]byte, error) {
	wrapped, err := k.state.store.WrappedKEK(ctx, kekID, version)
	if err != nil {
		return nil, fmt.Errorf("keyring/local: read %s %s: %w", kekID, version, err)
	}
	material, err := openRecord(k.state.wrapKey, wrapped, kekAAD(kekID, version))
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s does not authenticate under this root key", domain.ErrUnwrapFailed, kekID, version)
	}
	return material, nil
}

// sealRecord encrypts plaintext under a key derived from wrappingKey and a
// fresh per-record salt, binding aad, and returns the committed record
// layout documented in the package comment.
func sealRecord(wrappingKey, plaintext, aad []byte) ([]byte, error) {
	record := make([]byte, headerLen, headerLen+len(plaintext)+16)
	record[0] = WrapFormatVersion
	if _, err := rand.Read(record[1:headerLen]); err != nil {
		return nil, fmt.Errorf("read entropy for a record salt and nonce: %w", err)
	}
	salt, nonce := record[1:1+saltLen], record[1+saltLen:headerLen]

	aead, err := recordAEAD(wrappingKey, salt)
	if err != nil {
		return nil, err
	}
	return aead.Seal(record, nonce, plaintext, aad), nil
}

// openRecord reverses sealRecord. Every failure — an unknown format version,
// a short record, a bad tag — returns an error the caller maps onto
// domain.ErrUnwrapFailed without adding detail.
func openRecord(wrappingKey, record, aad []byte) ([]byte, error) {
	if len(record) < headerLen {
		return nil, errors.New("record is shorter than its header")
	}
	if record[0] != WrapFormatVersion {
		return nil, errors.New("unknown record format version")
	}
	salt, nonce, sealed := record[1:1+saltLen], record[1+saltLen:headerLen], record[headerLen:]

	aead, err := recordAEAD(wrappingKey, salt)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, errors.New("record does not authenticate")
	}
	return plaintext, nil
}

// recordAEAD derives this record's own AES-256 key from wrappingKey and the
// record's salt, and returns GCM over it. Deriving per record is what keeps
// one KEK from ever sealing two records under the same AES key.
func recordAEAD(wrappingKey, salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, wrappingKey, salt, recordInfo, kekMaterialLen)
	if err != nil {
		return nil, fmt.Errorf("derive a record key: %w", err)
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-256-GCM: %w", err)
	}
	return aead, nil
}

// dekAAD is the additional authenticated data binding a wrapped DEK to the
// KEK, KEK version and key id it was created for.
func dekAAD(kekID domain.KEKID, version domain.KEKVersion, keyID domain.KeyID) []byte {
	aad := make([]byte, 0, len(dekAADPrefix)+len(kekID)+len(keyID)+8)
	aad = append(aad, dekAADPrefix...)
	aad = append(aad, 0)
	aad = append(aad, kekID...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
	aad = append(aad, 0)
	return binary.BigEndian.AppendUint32(aad, uint32(version))
}

// kekAAD is the additional authenticated data binding wrapped KEK material
// to the KEK id and version it belongs to.
func kekAAD(kekID domain.KEKID, version domain.KEKVersion) []byte {
	aad := make([]byte, 0, len(kekAADPrefix)+len(kekID)+8)
	aad = append(aad, kekAADPrefix...)
	aad = append(aad, 0)
	aad = append(aad, kekID...)
	aad = append(aad, 0)
	return binary.BigEndian.AppendUint32(aad, uint32(version))
}

// rootKeyFrom resolves cfg's root key, returning a copy this package owns.
// Its errors never include key material: a root key that is too short says
// how short, not what it was.
func rootKeyFrom(cfg Config) ([]byte, error) {
	switch {
	case len(cfg.RootKey) > 0 && cfg.RootKeyFile != "":
		return nil, fmt.Errorf("%w: set exactly one of RootKey and RootKeyFile, not both", domain.ErrInvalidConfig)
	case len(cfg.RootKey) > 0:
		root := bytes.Clone(cfg.RootKey)
		if err := validateRootKey(root, "RootKey"); err != nil {
			clear(root)
			return nil, err
		}
		return root, nil
	case cfg.RootKeyFile != "":
		if cfg.RootKeyEncoding == "" {
			return nil, fmt.Errorf("%w: RootKeyFile requires RootKeyEncoding (raw, hex or base64)", domain.ErrInvalidConfig)
		}
		// G304 is expected and intended here: the path is a deployment
		// input, which is the entire purpose of RootKeyFile. How the file
		// gets there is the operator's business (CAS design §8.3).
		contents, err := os.ReadFile(cfg.RootKeyFile) //nolint:gosec
		if err != nil {
			// Drop the *os.PathError wrapper: its Error() includes the path,
			// which Config deliberately treats as secret-handling detail.
			cause := errors.Unwrap(err)
			if cause == nil {
				cause = errors.New("read failed")
			}
			return nil, fmt.Errorf("%w: read RootKeyFile: %w", domain.ErrInvalidConfig, cause)
		}
		defer clear(contents)

		root, err := decodeRootKey(contents, cfg.RootKeyEncoding)
		if err != nil {
			return nil, fmt.Errorf("%w: RootKeyFile: %w", domain.ErrInvalidConfig, err)
		}
		if err := validateRootKey(root, "RootKeyFile"); err != nil {
			clear(root)
			return nil, err
		}
		return root, nil
	default:
		return nil, fmt.Errorf("%w: set one of RootKey and RootKeyFile", domain.ErrInvalidConfig)
	}
}

// decodeRootKey decodes a root key file according to the explicitly selected
// encoding. There is no fallback chain: a malformed hex/base64 file (or a raw
// file that is too short) fails at Open instead of silently becoming a
// different key. Text encodings allow surrounding whitespace but reject
// internal whitespace, which is where a truncated/wrapped file usually hides.
func decodeRootKey(contents []byte, encoding RootKeyEncoding) ([]byte, error) {
	switch encoding {
	case RootKeyEncodingHex:
		trimmed := bytes.TrimSpace(contents)
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("hex contents are empty")
		}
		if bytes.ContainsAny(trimmed, " \t\r\n") {
			return nil, fmt.Errorf("hex contents contain whitespace")
		}
		if len(trimmed)%2 != 0 {
			return nil, fmt.Errorf("hex contents have an odd length")
		}
		decoded := make([]byte, hex.DecodedLen(len(trimmed)))
		if _, err := hex.Decode(decoded, trimmed); err != nil {
			clear(decoded)
			return nil, fmt.Errorf("decode hex: %w", err)
		}
		if len(decoded) < MinRootKeyLen {
			clear(decoded)
			return nil, fmt.Errorf("hex contents decode to %d bytes, need at least %d", len(decoded), MinRootKeyLen)
		}
		return decoded, nil

	case RootKeyEncodingBase64:
		trimmed := bytes.TrimSpace(contents)
		if len(trimmed) == 0 {
			return nil, fmt.Errorf("base64 contents are empty")
		}
		if bytes.ContainsAny(trimmed, " \t\r\n") {
			return nil, fmt.Errorf("base64 contents contain whitespace")
		}
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
		} {
			decoded := make([]byte, enc.DecodedLen(len(trimmed)))
			n, err := enc.Decode(decoded, trimmed)
			if err != nil {
				clear(decoded)
				continue
			}
			decoded = decoded[:n]
			if len(decoded) >= MinRootKeyLen {
				return decoded, nil
			}
			clear(decoded)
		}
		return nil, fmt.Errorf("base64 contents do not decode to at least %d bytes", MinRootKeyLen)

	case RootKeyEncodingRaw:
		if len(contents) < MinRootKeyLen {
			return nil, fmt.Errorf("raw contents are %d bytes, need at least %d", len(contents), MinRootKeyLen)
		}
		return bytes.Clone(contents), nil

	default:
		return nil, fmt.Errorf("unknown root key encoding %q", encoding)
	}
}

// validateRootKey rejects a root key that cannot carry the hierarchy: too
// short, or all-zero. All-zero is a misconfigured secret — an unmounted
// volume, an unset variable expanded to nothing — not a key, and accepting
// it would encrypt a whole deployment under a value an attacker guesses
// first.
func validateRootKey(root []byte, source string) error {
	if len(root) < MinRootKeyLen {
		return fmt.Errorf("%w: %s is %d bytes, need at least %d", domain.ErrInvalidConfig, source, len(root), MinRootKeyLen)
	}
	allZero := true
	for _, c := range root {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: %s is all zero bytes, which is a misconfigured secret rather than a key", domain.ErrInvalidConfig, source)
	}
	return nil
}

// String renders the manager without its derived wrapping key. A KeyManager
// is a plausible thing to log — it is what Open returns, so it is in scope
// wherever the error handling around Open is — and its wrapKey field is
// AES-256 key material derived from the deployment root key. Printing the
// manager must not print the key.
//
// The receiver is a value so the method is in the method set of a dereferenced
// or copied KeyManager as well as the pointer. The mutex and key live behind
// KeyManager.state, so the value copy is safe and cheap.
func (k KeyManager) String() string {
	return fmt.Sprintf("local.KeyManager{wrapKey: %s, store: %s}", domain.Redacted, k.storeDescription())
}

func (k KeyManager) storeDescription() string {
	if k.state == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T", k.state.store)
}

// Format implements fmt.Formatter so that every verb — not only the five fmt
// routes through Stringer — yields the redacted summary.
func (k KeyManager) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, k.String()) }

// MarshalJSON renders the redacted summary. encoding/json skips unexported
// fields, so a KeyManager already marshalled to "{}" — but that is safety by
// accident, and it ends the moment a field is exported.
func (k KeyManager) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// LogValue renders the manager as a slog group with the wrapping key
// redacted.
func (k KeyManager) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("wrap_key", domain.Redacted),
		slog.String("store", k.storeDescription()),
	)
}
