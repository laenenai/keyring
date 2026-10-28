// Package domain keeps the historical internal import path for the public
// value objects now defined in github.com/laenenai/keyring/value. The aliases
// preserve type identity for adapters and tests; new code should import the
// public value package directly.
package domain

import "github.com/laenenai/keyring/value"

// Exported constants are aliases for value's constants.
const (
	DEKSize         = value.DEKSize
	Redacted        = value.Redacted
	FirstKEKVersion = value.FirstKEKVersion
)

type (
	// KEKID aliases value.KEKID.
	KEKID = value.KEKID
	// KeyID aliases value.KeyID.
	KeyID = value.KeyID
	// KEKVersion aliases value.KEKVersion.
	KEKVersion = value.KEKVersion
	// DEK aliases value.DEK.
	DEK = value.DEK
	// WrappedDEKFormat aliases value.WrappedDEKFormat.
	WrappedDEKFormat = value.WrappedDEKFormat
	// WrappedDEK aliases value.WrappedDEK.
	WrappedDEK = value.WrappedDEK
)

// Record-format constants are aliases for value's constants.
const (
	WrappedDEKFormatLegacy         = value.WrappedDEKFormatLegacy
	WrappedDEKFormatLocal          = value.WrappedDEKFormatLocal
	WrappedDEKFormatOpenBaoTransit = value.WrappedDEKFormatOpenBaoTransit
)

// Sentinel errors are aliases for value's sentinels.
var (
	ErrInvalidKeyMaterial = value.ErrInvalidKeyMaterial
	ErrInvalidIdentifier  = value.ErrInvalidIdentifier
	ErrInvalidWrappedDEK  = value.ErrInvalidWrappedDEK
	ErrKEKNotFound        = value.ErrKEKNotFound
	ErrKEKDestroyed       = value.ErrKEKDestroyed
	ErrUnwrapFailed       = value.ErrUnwrapFailed
	ErrPermissionDenied   = value.ErrPermissionDenied
	ErrRateLimited        = value.ErrRateLimited
	ErrTransient          = value.ErrTransient
	ErrClosed             = value.ErrClosed
	ErrInvalidConfig      = value.ErrInvalidConfig
)

// NewDEK is an alias for value.NewDEK.
func NewDEK() (DEK, error) { return value.NewDEK() }

// DEKFrom is an alias for value.DEKFrom.
func DEKFrom(b []byte) (DEK, error) { return value.DEKFrom(b) }
