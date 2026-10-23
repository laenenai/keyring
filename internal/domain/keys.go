// Package domain is the single home for every value object keyring names:
// the data encryption key (DEK) that some caller's cipher consumes, the
// wrapped form of that DEK which the caller persists, and the identifiers
// that say which key encryption key (KEK) — at which version — did the
// wrapping. Nothing here performs I/O, talks to a key manager, or knows what
// the DEK encrypts; that last part is deliberate and is the charter's line.
//
// Two invariants live in this package rather than in its callers, because a
// caller that has to remember them will eventually forget:
//
//  1. Key material is zeroizable and is zeroized through DEK.Destroy, which
//     clears the one backing array every copy of that DEK shares. A DEK is
//     therefore not an ordinary value: copying it is cheap but does not
//     duplicate the secret.
//  2. Key material never renders. DEK implements fmt.Stringer,
//     fmt.Formatter, fmt.GoStringer, encoding.TextMarshaler, json.Marshaler
//     and slog.LogValuer, all of them yielding Redacted, so the material
//     cannot reach an error string, a log line or a JSON body by way of any
//     fmt verb, a structured log attribute, or a struct that happens to
//     contain a DEK. fmt.Formatter is the load-bearing one and was the one
//     missing: fmt consults Stringer for %v, %s, %q, %x and %X only, so %d
//     printed the whole key until Format existed. See CONVENTIONS.md's
//     "Rendering a secret", and keyringtest's NoSecretLeaksInAnyRendering,
//     which asserts the same invariant against whatever DEK an adapter
//     actually returns.
//
// The root package keyring re-exports what a consumer needs to name as type
// aliases, so a WrappedDEK an adapter returns and a keyring.WrappedDEK the
// consumer stores are the identical type.
package domain

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DEKSize is the length in bytes of every DEK this module wraps: 32, for
// AES-256. It is a fixed size rather than a range because a DEK is minted by
// this module (NewDEK) or handed to it by a caller that minted it the same
// way, and accepting a shorter key would silently weaken content encryption
// for whoever passed one.
const DEKSize = 32

// Redacted is the placeholder every rendering of key material yields. It is
// exported so a consumer's own log scrubbing, and its own tests, can assert
// against the same literal this package writes.
const Redacted = "[REDACTED]"

// maxIdentifierLen bounds a KEKID and a KeyID. It is generous relative to
// any real id (a ULID is 26 bytes) and exists to reject a deliberately
// oversized value before it reaches a remote key manager's API, where the
// limit would be enforced by a 400 at best and by truncation at worst.
const maxIdentifierLen = 256

// KEKID identifies one key encryption key within a key manager: the key that
// wraps DEKs and is never itself handed to a caller. It is an opaque string
// chosen by the caller — a tenant id, in every consumer so far — because
// this module must not know what a tenant is.
//
// Adapters map it onto a key name in their backend (an OpenBao transit key,
// a KMS key alias, a row), so Validate rejects anything that is not safe as
// a single path or name component.
type KEKID string

// Validate reports whether id is safe to use as a key name. See
// ErrInvalidIdentifier.
func (id KEKID) Validate() error { return validateIdentifier("KEK id", string(id)) }

// String returns the id unchanged. A KEK id is not a secret: it names a key
// without describing the key or its material.
func (id KEKID) String() string { return string(id) }

// KeyID identifies the thing a DEK protects, from this module's point of
// view: an opaque label the caller chooses (a blob id, a document id) and
// that the caller passes again at unwrap time.
//
// It exists so that wrapping can bind the ciphertext to the record it
// belongs to: a wrapped DEK lifted out of one row and pasted into another
// fails to unwrap instead of silently yielding a key for the wrong content.
// Like KEKID, it is deliberately not a domain concept — this module never
// learns what the id refers to.
type KeyID string

// Validate reports whether id is safe to use as bound context and as a
// backend-visible label. See ErrInvalidIdentifier.
func (id KeyID) Validate() error { return validateIdentifier("key id", string(id)) }

// String returns the id unchanged. A key id names a record without
// describing its content.
func (id KeyID) String() string { return string(id) }

// KEKVersion is the generation of a KEK: version 1 is the KEK as first
// created, and each RotateKEK adds the next one. Every WrappedDEK records
// the version that wrapped it, which is what makes rotation lazy — see
// WrappedDEK.
//
// Versions start at FirstKEKVersion rather than at zero so that the zero
// value of a WrappedDEK, or a column that was never populated, is detectably
// invalid rather than silently meaning "the first KEK".
type KEKVersion uint32

// FirstKEKVersion is the version a KEK has when it is created.
const FirstKEKVersion KEKVersion = 1

// Validate reports whether v names a real version, i.e. is not zero.
func (v KEKVersion) Validate() error {
	if v < FirstKEKVersion {
		return fmt.Errorf("%w: KEK version %d: numbering starts at %d", ErrInvalidIdentifier, uint32(v), uint32(FirstKEKVersion))
	}
	return nil
}

// Next returns the version that follows v.
func (v KEKVersion) Next() KEKVersion { return v + 1 }

// String renders the version as "v3", the form that appears in logs and
// audit records.
func (v KEKVersion) String() string { return "v" + strconv.FormatUint(uint64(v), 10) }

// DEK is one data encryption key: the key a caller's cipher actually
// consumes, and the only key material this module ever lets into the
// caller's address space. A KEK or a deployment root key never appears as a
// DEK, and there is no type here that carries one — the port's shape (wrap,
// unwrap, rotate) is what keeps them out.
//
// A DEK must be destroyed when the caller is done with it, conventionally
// with defer:
//
//	dek, err := km.UnwrapDEK(ctx, wrapped)
//	if err != nil { return err }
//	defer dek.Destroy()
//
// Destroy clears the backing array, which every copy of the DEK shares; see
// the package doc comment. The zero DEK holds no material and is rejected by
// Validate.
type DEK struct {
	// b is the key material. It is unexported, and reachable only through
	// Bytes, so that no struct literal elsewhere can construct a DEK that
	// skipped Validate, and so that encoding/json cannot reach the material
	// by reflection even without the Marshal methods below.
	b []byte
}

// NewDEK returns a fresh DEK read from crypto/rand.
//
// It returns an error rather than panicking on an entropy failure: a library
// that cannot read randomness must let its caller decide whether to retry,
// fail the request, or shut down, and forbidigo forbids the panic this
// codebase would otherwise be tempted to write (see CONVENTIONS.md).
func NewDEK() (DEK, error) {
	b := make([]byte, DEKSize)
	if _, err := rand.Read(b); err != nil {
		return DEK{}, fmt.Errorf("keyring: read %d bytes of entropy for a DEK: %w", DEKSize, err)
	}
	return DEK{b: b}, nil
}

// DEKFrom returns a DEK holding a copy of b, or ErrInvalidKeyMaterial if b
// is not usable key material. The copy is deliberate: the caller keeps
// ownership of its own buffer (and must zeroize it), and DEK.Destroy
// zeroizes only the copy.
func DEKFrom(b []byte) (DEK, error) {
	if err := validateKeyMaterial(b); err != nil {
		return DEK{}, err
	}
	return DEK{b: bytes.Clone(b)}, nil
}

// Bytes returns the live key material — not a copy, so that a caller can
// hand it straight to a cipher without creating a second buffer that also
// has to be zeroized. It returns nil for a destroyed or zero DEK. The caller
// must not retain the slice past Destroy, and must not modify it.
func (k DEK) Bytes() []byte { return k.b }

// Validate reports whether k holds usable key material: present, exactly
// DEKSize bytes, and not all-zero.
//
// All-zero is rejected rather than treated as an astronomically unlikely
// random key, because every all-zero buffer that actually reaches this
// method is a bug — a DEK used after Destroy, or a make([]byte, 32) that
// was never filled. Failing closed on it turns "everything was encrypted
// under a key the attacker can guess" into an error at the boundary.
func (k DEK) Validate() error { return validateKeyMaterial(k.b) }

// IsZero reports whether k holds no usable key material, because it is the
// zero value, because it was destroyed, or because its shared backing array
// was zeroized through another copy.
func (k DEK) IsZero() bool {
	for _, c := range k.b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Equal reports whether k and other hold the same key material, in constant
// time with respect to the material. It exists for tests and for an
// adapter's self-check; production code has no reason to compare two DEKs.
func (k DEK) Equal(other DEK) bool {
	return subtle.ConstantTimeCompare(k.b, other.b) == 1
}

// Destroy zeroizes the key material and leaves k holding none. It is
// idempotent, safe on the zero value, and — because the material is one
// shared backing array — it zeroizes the key for every copy of this DEK
// that was taken before the call. That is the behavior key material should
// have: there is one secret, and destroying it destroys it everywhere, not
// just in the variable the caller happened to name.
func (k *DEK) Destroy() {
	clear(k.b)
	k.b = nil
}

// String returns Redacted. See the package doc comment: this is one of the
// renderings that keep key material out of errors and logs.
func (k DEK) String() string { return "DEK(" + Redacted + ")" }

// GoString returns Redacted, so a caller reaching for a Go-syntax dump of a
// DEK gets the placeholder. Format, below, is what fmt actually consults for
// %#v now that it exists; this method is kept because it is exported and a
// consumer may call it directly.
func (k DEK) GoString() string { return "domain.DEK{" + Redacted + "}" }

// Format implements fmt.Formatter, and it is the method that makes this
// type's redaction complete rather than nearly complete.
//
// fmt consults Stringer for %v, %s, %q, %x and %X, and for no other verb.
// Every other verb falls through to reflection and prints the struct's
// fields — so before this method existed, with Stringer, GoStringer,
// MarshalText, MarshalJSON and LogValue all in place, fmt.Sprintf("%d", dek)
// printed every one of the DEKSize key bytes in decimal, and %c, %U, %b and
// %o did the same in their own alphabets. fmt.Formatter is the only interface
// consulted for every verb, which is why CONVENTIONS.md requires it and not
// just the other three.
//
// Every verb, flag, width and precision yields the same placeholder: a verb
// is a request about presentation, and this value has no presentation to
// vary. The one verb no method can cover is %p, whose bad-verb path skips
// every interface and reflects the operand; CONVENTIONS.md records that hole
// and its mitigation.
func (k DEK) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, k.String()) }

// MarshalText returns Redacted. A DEK has no text form on purpose; it is
// persisted only in its wrapped form, as a WrappedDEK.
func (k DEK) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalJSON returns Redacted as a JSON string, so a DEK that ends up
// inside a logged or serialized struct redacts itself rather than being
// refused (an error here would turn a logging mistake into a failed
// request) or, worse, encoded.
func (k DEK) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// LogValue returns Redacted, so slog.Any("dek", dek) and a slog group
// containing one render the placeholder rather than the key.
func (k DEK) LogValue() slog.Value { return slog.StringValue(Redacted) }

// UnmarshalJSON always fails: a DEK cannot be deserialized, because there is
// no form of a DEK on the wire or at rest that this module is willing to
// read back. Accepting one would mean accepting plaintext key material from
// whatever produced the document.
func (k *DEK) UnmarshalJSON([]byte) error {
	return fmt.Errorf("%w: a DEK cannot be deserialized; unwrap a WrappedDEK instead", ErrInvalidKeyMaterial)
}

// WrappedDEK is a DEK encrypted under a KEK, in the form a caller persists
// next to the content that DEK encrypted. Every field is safe to store and
// to log; none of them is key material.
//
// KEKVersion is the field that makes KEK rotation cheap, and it is a hard
// requirement rather than a convenience: because each wrapped DEK records
// the version that wrapped it, rotating a KEK is adding a new version and
// (at most, lazily) re-wrapping these small records. The content itself is
// never re-encrypted — which matters when a single KEK covers terabytes of
// blobs that would otherwise all have to be read, decrypted and written back
// to rotate a key.
type WrappedDEK struct {
	// KEKID names the KEK that can unwrap this record.
	KEKID KEKID
	// KEKVersion names which version of that KEK did the wrapping. A
	// wrapped DEK remains unwrappable at its own version after the KEK has
	// rotated past it.
	KEKVersion KEKVersion
	// KeyID is the label the DEK was wrapped against, and it is bound into
	// the ciphertext: unwrapping a record whose KeyID has been changed
	// fails with ErrUnwrapFailed rather than returning a key.
	KeyID KeyID
	// Ciphertext is the adapter's opaque wrapped-key blob. Its layout is an
	// adapter's business (the local adapter documents its own), so a record
	// written by one adapter is not portable to another, and callers must
	// not parse it.
	Ciphertext []byte
}

// Validate reports whether w is structurally usable: its identifiers are
// valid and it carries ciphertext. It says nothing about whether the
// ciphertext will authenticate — that is UnwrapDEK's answer, and it is
// ErrUnwrapFailed.
func (w WrappedDEK) Validate() error {
	if err := w.KEKID.Validate(); err != nil {
		return err
	}
	if err := w.KEKVersion.Validate(); err != nil {
		return err
	}
	if err := w.KeyID.Validate(); err != nil {
		return err
	}
	if len(w.Ciphertext) == 0 {
		return fmt.Errorf("%w: no ciphertext", ErrInvalidWrappedDEK)
	}
	return nil
}

// String names the KEK, version and key id — which is the whole point of
// recording them — and reports the ciphertext only as a length. The
// ciphertext is not a secret, but it is also never useful in a log line, and
// a type that prints a key-shaped blob invites a reader to assume the other
// one does too.
func (w WrappedDEK) String() string {
	return fmt.Sprintf("WrappedDEK(kek=%s %s key=%s ciphertext=%d bytes)",
		w.KEKID, w.KEKVersion, w.KeyID, len(w.Ciphertext))
}

// LogValue renders the same fields as String as a slog group, so an adapter
// can log a wrapped DEK structurally without reaching for its fields.
func (w WrappedDEK) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("kek_id", string(w.KEKID)),
		slog.Uint64("kek_version", uint64(w.KEKVersion)),
		slog.String("key_id", string(w.KeyID)),
		slog.Int("ciphertext_bytes", len(w.Ciphertext)),
	)
}

// validateKeyMaterial is the one definition of "usable key material" this
// package has: present, exactly DEKSize bytes, not all-zero.
func validateKeyMaterial(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("%w: empty", ErrInvalidKeyMaterial)
	}
	if len(b) != DEKSize {
		return fmt.Errorf("%w: %d bytes, want %d", ErrInvalidKeyMaterial, len(b), DEKSize)
	}
	allZero := true
	for _, c := range b {
		if c != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: all-zero (a destroyed or uninitialized buffer, not a key)", ErrInvalidKeyMaterial)
	}
	return nil
}

// validateIdentifier reports whether s is safe to use as a key name: a
// single non-empty component, no longer than maxIdentifierLen, valid UTF-8,
// free of path separators, null bytes, control characters, and surrounding
// whitespace, and not a relative path element.
//
// The rules are deliberately stricter than any one backend needs. An
// identifier reaching this module becomes an OpenBao transit key name, a KMS
// alias, a URL path segment and an audit-log field, so the safe set is the
// intersection of what all of them accept, not the union; widening it later
// is a reviewed change to this one function rather than a surprise in one
// adapter.
func validateIdentifier(label, s string) error {
	if s == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidIdentifier, label)
	}
	if len(s) > maxIdentifierLen {
		return fmt.Errorf("%w: %s is %d bytes, maximum %d", ErrInvalidIdentifier, label, len(s), maxIdentifierLen)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidIdentifier, label)
	}
	if s == "." || strings.Contains(s, "..") {
		return fmt.Errorf("%w: %s is a relative path element", ErrInvalidIdentifier, label)
	}
	if strings.ContainsAny(s, "/\\\x00") {
		return fmt.Errorf("%w: %s contains a path separator or null byte", ErrInvalidIdentifier, label)
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("%w: %s has leading or trailing whitespace", ErrInvalidIdentifier, label)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%w: %s contains a control or whitespace character", ErrInvalidIdentifier, label)
		}
	}
	return nil
}
