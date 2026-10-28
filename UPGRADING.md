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

### 6. Replace the API golden-file workflow

The API golden file and its regeneration task are gone. Use:

```bash
mise run api-diff       # apidiff against the last root tag; report-only pre-1.0
mise run release-check  # gorelease from a clean tree, at release time
mise run check          # the full local gate
```

`api-diff` reports incompatible changes against the base tag. Pre-1.0 they are
allowed, but every one must be documented here and in `CHANGELOG.md`. After
1.0, set `API_DIFF_STRICT=1` and use a new major module path for incompatible
changes.

## Release policy

- `v0.x.0` may break; `v0.x.y` is a fix.
- Every breaking change gets a changelog entry and an upgrade section.
- `main` is tagged only after `mise run check` passes.
- `gorelease` runs on the clean tagged commit; integration/test-only modules
  are not published and are not tagged.
