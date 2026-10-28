package domain

import "errors"

// This file declares every sentinel error keyring returns across a package
// boundary (see the package doc comment in keys.go). They are declared here,
// once, and re-exported from the root facade (keyring.go) so that an adapter
// written outside this module — a consumer wiring its own KMS, which the
// charter's definition of adoption anticipates — returns the identical
// values the conformance suite asserts on.
//
// No sentinel here wraps another. In particular ErrUnwrapFailed is
// deliberately uninformative: see its doc comment.
var (
	// ErrInvalidKeyMaterial is returned when a buffer offered as key
	// material cannot be one: the wrong length, empty, or all-zero (which
	// in practice means a zeroized or never-initialized buffer, not a
	// legitimately random key — see DEK.Validate).
	ErrInvalidKeyMaterial = errors.New("keyring: invalid key material")

	// ErrInvalidIdentifier is returned when a KEKID, KeyID or KEKVersion
	// cannot safely be used to name a key: empty, over-long, carrying a
	// path separator, a control character or invalid UTF-8, or a version of
	// zero. Adapters turn these identifiers into remote key names, API path
	// segments and audit-log fields, so they are validated at this boundary
	// rather than sanitized downstream.
	ErrInvalidIdentifier = errors.New("keyring: invalid identifier")

	// ErrInvalidWrappedDEK is returned when a WrappedDEK record is
	// structurally unusable — no ciphertext — independently of whether its
	// ciphertext would authenticate. A caller that reconstructs the record
	// from its own storage can hand an adapter a partially-populated value;
	// every adapter rejects it here rather than passing an empty buffer to
	// a cipher.
	ErrInvalidWrappedDEK = errors.New("keyring: invalid wrapped DEK")

	// ErrKEKNotFound is returned when the named KEK, or the named version
	// of it, does not exist: an UnwrapDEK of a record whose KEK was never
	// created, or a RotateKEK of a KEK that does not yet exist. Adapters map
	// their own signal (a missing row, OpenBao's 404, a KMS
	// NotFoundException) onto this sentinel so callers never branch on
	// adapter-specific shapes.
	ErrKEKNotFound = errors.New("keyring: KEK not found")

	// ErrKEKDestroyed is returned by every operation naming a KEK that has
	// been destroyed, and is the signal that crypto-shredding has taken
	// effect: every DEK wrapped under that KEK is permanently unwrappable,
	// so every byte those DEKs encrypted is permanently unreadable.
	//
	// It is separate from ErrKEKNotFound because "never existed" and
	// "existed and was deliberately destroyed" are different operational
	// facts: only the second one means the content is irrecoverable by
	// design rather than by accident, and an erasure certificate has to be
	// able to tell them apart. It is also why WrapDEK under a destroyed KEK
	// fails instead of quietly creating a fresh version 1 — a shredded key
	// is never resurrected under its own name.
	ErrKEKDestroyed = errors.New("keyring: KEK destroyed")

	// ErrUnwrapFailed is returned when a wrapped DEK does not authenticate
	// under the KEK it names: the wrong KEK, the wrong KEK version, a
	// wrapped DEK moved to a different key id, flipped ciphertext bytes, or
	// a truncated record.
	//
	// It is deliberately one sentinel for all of those causes, and its
	// message deliberately says nothing about which applies. An unwrap
	// failure is the one place where a caller is, by construction, holding
	// data it may not be entitled to; a specific error ("bad version", "bad
	// key binding", "bad tag") turns the key manager into an oracle that
	// distinguishes a wrong guess from a malformed one. Adapters MUST NOT
	// add that detail to the wrapped message either.
	ErrUnwrapFailed = errors.New("keyring: unwrap failed")

	// ErrPermissionDenied is returned when a backend rejects the
	// credentials or policy for an otherwise valid request. It is
	// permanent until the deployment's access is fixed, so adapters do not
	// retry it.
	ErrPermissionDenied = errors.New("keyring: permission denied")

	// ErrRateLimited is returned when a backend asks the caller to slow
	// down. Adapters may retry it with their bounded policy; callers can
	// use errors.Is to distinguish it from a permanent failure.
	ErrRateLimited = errors.New("keyring: rate limited")

	// ErrTransient is returned when a backend failed in a way that may
	// succeed on retry: a 5xx response or a transport error. A mutation
	// that is not safe to repeat (RotateKEK) still reports this error
	// without an automatic retry, so the caller can decide.
	ErrTransient = errors.New("keyring: transient backend error")

	// ErrClosed is returned after an adapter's Close has released its
	// secrets and connections. Further operations are refused instead of
	// using zeroized material.
	ErrClosed = errors.New("keyring: key manager closed")

	// ErrInvalidConfig is returned by an adapter's Open when its
	// configuration cannot produce a working key manager: no root key, a
	// root key that is too short, both a key and a key file given, an
	// unreadable key file, no backing store.
	ErrInvalidConfig = errors.New("keyring: invalid configuration")
)
