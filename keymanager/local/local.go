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
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/laenen-ai/keyring/internal/domain"
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

// Config configures the local adapter. Exactly one of RootKey and
// RootKeyFile must be set, and Store is required.
type Config struct {
	// RootKey is the deployment root key as raw bytes, at least
	// MinRootKeyLen of them. Use it when the key reaches the process as a
	// value the caller has already decoded (an environment variable, a
	// Kubernetes secret, a SOPS-decrypted field).
	RootKey []byte

	// RootKeyFile is a path to read the root key from, as an alternative to
	// RootKey. Its contents are decoded by a fixed rule, in this order:
	// hex, then base64 (standard or URL alphabet, padded or not), then the
	// raw file bytes — surrounding whitespace ignored for the two text
	// forms. An operator who writes the key with `xxd`, with `base64`, or
	// with `head -c 32 /dev/urandom > key` therefore all get the same
	// deployment, and no single encoding is privileged by accident.
	//
	// How the file gets there is the operator's business and not this
	// module's: a mounted secret, a SOPS-decrypted file, a tmpfs path
	// written at boot.
	RootKeyFile string

	// Store is where wrapped KEK material lives. It is required, with no
	// in-memory default, because the default most likely to be reached for
	// by accident is also the one whose failure mode is the permanent loss
	// of every encrypted byte — see MemKEKStore, which a test or a
	// deliberately ephemeral process can pass explicitly.
	Store KEKStore
}

// KeyManager is the local adapter's implementation of
// keymanager.KeyManager. Open returns one; it is safe for concurrent use.
type KeyManager struct {
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
	return &KeyManager{wrapKey: wrapKey, store: cfg.Store}, nil
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
	current, err := k.store.CurrentKEKVersion(ctx, wrapped.KEKID)
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

	k.mu.Lock()
	defer k.mu.Unlock()

	// Rotation is not creation: a KEK with no current version is
	// ErrKEKNotFound, so a typo in a KEK id cannot mint a key.
	current, err := k.store.CurrentKEKVersion(ctx, kekID)
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
			rotated, readErr := k.store.CurrentKEKVersion(ctx, kekID)
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

	k.mu.Lock()
	defer k.mu.Unlock()

	if err := k.store.DestroyKEK(ctx, kekID); err != nil {
		return fmt.Errorf("keyring/local: destroy %s: %w", kekID, err)
	}
	return nil
}

// currentOrCreatedVersion returns the KEK's current version, creating the
// KEK at domain.FirstKEKVersion if it does not exist yet. A destroyed KEK is
// never created again: the store reports domain.ErrKEKDestroyed and that is
// propagated unchanged.
func (k *KeyManager) currentOrCreatedVersion(ctx context.Context, kekID domain.KEKID) (domain.KEKVersion, error) {
	current, err := k.store.CurrentKEKVersion(ctx, kekID)
	switch {
	case err == nil:
		return current, nil
	case !errors.Is(err, domain.ErrKEKNotFound):
		return 0, fmt.Errorf("keyring/local: read the current version of %s: %w", kekID, err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	// Re-read under the lock: another goroutine may have created the KEK
	// between the read above and here.
	if current, err := k.store.CurrentKEKVersion(ctx, kekID); err == nil {
		return current, nil
	} else if !errors.Is(err, domain.ErrKEKNotFound) {
		return 0, fmt.Errorf("keyring/local: read the current version of %s: %w", kekID, err)
	}

	if err := k.createVersion(ctx, kekID, domain.FirstKEKVersion); err != nil {
		if errors.Is(err, ErrKEKVersionExists) {
			// Another process won the race; its version 1 is the KEK now.
			current, readErr := k.store.CurrentKEKVersion(ctx, kekID)
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
// wrapping key, and stores it as the named version. Callers hold k.mu.
func (k *KeyManager) createVersion(ctx context.Context, kekID domain.KEKID, version domain.KEKVersion) error {
	material := make([]byte, kekMaterialLen)
	if _, err := rand.Read(material); err != nil {
		return fmt.Errorf("keyring/local: read entropy for %s %s: %w", kekID, version, err)
	}
	defer clear(material)

	wrapped, err := sealRecord(k.wrapKey, material, kekAAD(kekID, version))
	if err != nil {
		return fmt.Errorf("keyring/local: wrap %s %s under the root key: %w", kekID, version, err)
	}
	if err := k.store.CreateKEKVersion(ctx, kekID, version, wrapped); err != nil {
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
	wrapped, err := k.store.WrappedKEK(ctx, kekID, version)
	if err != nil {
		return nil, fmt.Errorf("keyring/local: read %s %s: %w", kekID, version, err)
	}
	material, err := openRecord(k.wrapKey, wrapped, kekAAD(kekID, version))
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
			return nil, err
		}
		return root, nil
	case cfg.RootKeyFile != "":
		// G304 is expected and intended here: the path is a deployment
		// input, which is the entire purpose of RootKeyFile. How the file
		// gets there is the operator's business (CAS design §8.3).
		contents, err := os.ReadFile(cfg.RootKeyFile) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("%w: read RootKeyFile %q: %w", domain.ErrInvalidConfig, cfg.RootKeyFile, err)
		}
		defer clear(contents)

		root, err := decodeRootKey(contents)
		if err != nil {
			return nil, fmt.Errorf("%w: RootKeyFile %q: %w", domain.ErrInvalidConfig, cfg.RootKeyFile, err)
		}
		if err := validateRootKey(root, fmt.Sprintf("RootKeyFile %q", cfg.RootKeyFile)); err != nil {
			return nil, err
		}
		return root, nil
	default:
		return nil, fmt.Errorf("%w: set one of RootKey and RootKeyFile", domain.ErrInvalidConfig)
	}
}

// decodeRootKey applies the documented decode rule for a root key file:
// hex, then base64 in any alphabet, then the raw bytes. Only a candidate
// that yields at least MinRootKeyLen bytes is accepted, so a short text file
// is not mistaken for a raw key.
func decodeRootKey(contents []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(contents)

	if decoded, err := hex.DecodeString(string(trimmed)); err == nil && len(decoded) >= MinRootKeyLen {
		return decoded, nil
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(string(trimmed)); err == nil && len(decoded) >= MinRootKeyLen {
			return decoded, nil
		}
	}
	if len(contents) >= MinRootKeyLen {
		return bytes.Clone(contents), nil
	}
	return nil, fmt.Errorf("contents are neither hex, base64, nor at least %d raw bytes", MinRootKeyLen)
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
