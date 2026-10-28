# Upgrading

`keyring` is pre-1.0: a minor release may break the API. This file records the
steps for the breaking changes in the unreleased change set.

## From v0.2.x to the unreleased API

### 1. Replace the external-KMS stub

`keymanager/externalkms` and `keyring.ErrNotImplemented` are removed. Remove
imports of the stub and wire `local` or `openbaotransit` instead. If you need a
cloud KMS, keep the adapter outside this module until a real transport exists;
do not depend on a package that always returns “not implemented”.

### 2. Set `RootKeyEncoding` for a root-key file

`RootKeyFile` no longer auto-detects its encoding:

```go
// Before: the file might be hex, base64 or raw, chosen by fallback.
local.Config{RootKeyFile: "/run/secrets/root.key"}

// After: state the encoding explicitly.
local.Config{
    RootKeyFile:     "/run/secrets/root.key",
    RootKeyEncoding: local.RootKeyEncodingRaw, // or Hex / Base64
}
```

Raw files are used byte-for-byte. A raw key written with `echo` includes a
trailing newline and is therefore a different key; use `printf` or a text
encoding. Truncated hex/base64, internal whitespace, and missing encodings now
fail at `Open` with `ErrInvalidConfig`.

### 3. Update OpenBao transport configuration

- Plain `http://` is allowed only for loopback. For a remote OpenBao use
  `https://`; set `AllowInsecureHTTP: true` only on a trusted network.
- Remove userinfo, paths, queries and fragments from `Address`; use `Token`.
- Redirects are refused. If you supplied a custom `HTTPClient`, the adapter
  clones it and replaces `CheckRedirect`; do not rely on a custom redirect
  policy to forward key-manager requests.

### 4. Handle `ErrKEKDestroyed` on reads and races

A tombstone is now authoritative. If `DestroyKEK` races a wrap, generate,
unwrap, rewrap or rotate, the operation can return `ErrKEKDestroyed` even
though it started before destruction completed. Treat that as the intended
fail-closed result and do not retry a destroyed KEK. Backups and the root key
are still outside the live-system guarantee; see `SECURITY.md`.

### 5. Review configuration serialization and value copies

`Config` now redacts XML and gob in addition to `fmt`, JSON and `slog`;
`KeyManager` redaction works on values as well as pointers. If a custom
serializer relied on reading the exported `RootKey`/`Token` fields, it must
use the redacted representation instead. `%p` remains a known exception; see
`CONVENTIONS.md`.

### 6. Handle typed OpenBao failures and retry policy

OpenBao calls now classify permanent and transient failures:

```go
switch {
case errors.Is(err, keyring.ErrPermissionDenied):
    // Fix the token policy; retrying will not help.
case errors.Is(err, keyring.ErrRateLimited), errors.Is(err, keyring.ErrTransient):
    // Safe to retry within your own budget; the adapter also retries
    // bounded transient failures for non-ambiguous operations.
}
```

`openbaotransit.Config.Retry` controls attempts/backoff; the zero value is
three attempts with jittered exponential backoff. `RotateKEK` is deliberately
not retried automatically: a lost response may already have created a new
version. Retry it yourself only if an extra version is acceptable.

### 7. Move store imports to the neutral package

The persistence port now lives in `keymanager/kekstore`:

```go
import "github.com/laenenai/keyring/keymanager/kekstore"

store := kekstore.NewMemKEKStore() // tests only
// or: store, err := keyringpostgres.Open(ctx, dsn)
```

`local.KEKStore`, `local.MemKEKStore`, `local.NewMemKEKStore` and
`local.ErrKEKVersionExists` are aliases, so existing code keeps compiling.
`keyringtest.RunKEKStoreSuite` now accepts `kekstore.KEKStore`; callers passing
a `local.KEKStore` function value need no change because the type is an alias.

The public value objects now also live at `github.com/laenenai/keyring/value`.
`internal/domain` aliases that package for existing internal code, and the
root `keyring` aliases are unchanged.

### 8. Persist records with the versioned format

New wrapped records carry `Format`. JSON encoding uses stable field names
(`kek_id`, `kek_version`, `key_id`, `format`, `ciphertext`); decoding accepts
both those and the old Go field names, so existing JSON records remain
readable. Prefer `WrappedDEK.MarshalBinary`/`UnmarshalBinary` for new storage.
An empty `Format` is treated as a legacy record and remains readable; an
adapter rejects a record whose non-empty format belongs to another adapter
with `ErrInvalidWrappedDEK`.

### 9. Use the optional rewrap capability

If a rotation worker requires that the DEK never enters its process, assert
`keyring.RewrapWithoutPlaintext` on the manager and use
`RewrapDEKWithoutPlaintext`. `openbaotransit.KeyManager` implements it; the
local adapter does not. `RewrapDEK` keeps its existing semantics and remains
the portable method.

### 10. Install the Postgres companion module

The durable store is no longer part of the root module:

```bash
go get github.com/laenenai/keyring/postgres
```

```go
store, err := keyringpostgres.Open(ctx, dsn)
if err != nil { return err }
defer store.Close()
if err := store.Migrate(ctx); err != nil { return err }
```

The first release is `postgres/v0.1.0`; it requires root keyring v0.3.0.
Run this module's schema migration before serving traffic. The root module
still has no database dependency.

### 11. Replace the API golden-file workflow

The API golden file and its regeneration task are gone. Use:

```bash
mise run api-diff       # apidiff against the last root tag; report-only pre-1.0
mise run release-check  # gorelease from a clean tree, at release time
mise run check          # the full local gate
```

`api-diff` reports incompatible changes against the base tag. Pre-1.0 they are
allowed, but every one must be documented here and in `CHANGELOG.md`. After
1.0, set `API_DIFF_STRICT=1` and use a new major module path for incompatible
changes. The Postgres companion has its own `postgres/vX.Y.Z` tags and uses
the same policy.

## Release policy

- `v0.x.0` may break; `v0.x.y` is a fix.
- Every breaking change gets a changelog entry and an upgrade section.
- `main` is tagged only after `mise run check` passes.
- `gorelease` runs on the clean tagged commit; integration/test-only modules
  are not published and are not tagged. The published modules are the root
  module and `github.com/laenenai/keyring/postgres`.
