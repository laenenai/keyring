# Changelog

All notable changes to `keyring` are recorded here. The format is
human-readable; versions follow SemVer with the pre-1.0 rule that a minor
release may break the API. See `UPGRADING.md` for migration steps.

## Unreleased

### Breaking changes

- **The AST-generated API golden file and its test are removed.** API
  compatibility is now checked with `apidiff` against the previous root tag
  (`mise run api-diff`) and `gorelease` on a clean release. The old API-golden
  task no longer exists; `internal/...` is no longer part of the compatibility
  snapshot.
- **The `keymanager/externalkms` package and `ErrNotImplemented` are removed.**
  The package was a public stub that could never open a key manager. External
  KMS support will return only with a real transport, tests and a reviewed
  configuration.
- **`local.Config.RootKeyFile` requires an explicit `RootKeyEncoding`.**
  Auto-detection of hex/base64/raw is gone. Truncated or ambiguous text files
  now fail at `Open` instead of silently selecting different key material.
  Raw files are byte-for-byte; use `printf`, not `echo`, for a raw key.
- **`openbaotransit.Open` rejects non-loopback plain HTTP by default.**
  Set `AllowInsecureHTTP` only for a trusted network. URL userinfo, paths,
  queries and fragments are rejected; redirects are never followed.
- **Destroyed KEKs are authoritative on reads.** `UnwrapDEK`, `RewrapDEK`,
  `RotateKEK` and `WrapDEK`/`GenerateDEK` re-check the tombstone after the
  server call. A concurrent destroy can now make a wrap or read return
  `ErrKEKDestroyed` instead of a record or DEK.
- **`local.Config` and `openbaotransit.Config` now redact XML and gob too.**
  `KeyManager` redaction is value-safe, so dereferencing or copying a manager
  no longer exposes the wrapping key or token. `%p` remains a documented
  exception.

- **The store port moved to `keymanager/kekstore`.** `local.KEKStore`,
  `local.MemKEKStore`, `local.NewMemKEKStore` and `local.ErrKEKVersionExists`
  remain aliases for compatibility, but `keyringtest.RunKEKStoreSuite` now
  takes the neutral type. This removes the test suite's dependency on the
  local adapter.
- **`WrappedDEK` has a persistence contract.** Records now carry a `Format`
  (`local/v1` or `openbao-transit/v1`), stable JSON field names and a
  versioned `MarshalBinary`/`UnmarshalBinary` encoding. Records written before
  the field existed have an empty format and remain readable; new records
  from either adapter name their format.
- **`RewrapWithoutPlaintext` is an optional capability.** The OpenBao adapter
  implements it; the local adapter does not claim it, because a local rewrap
  necessarily decrypts in-process.
- **`github.com/laenenai/keyring/postgres` is the durable reference store.**
  It is a separately versioned companion module, applies its schema with
  `Migrate`, and runs the full `kekstore` conformance suite against Postgres.

- **OpenBao failures are typed and transient errors are retried.** 5xx and
  transport failures surface as `ErrTransient`, 429 as `ErrRateLimited`, and
  401/403 as `ErrPermissionDenied`. `Config.Retry` bounds attempts, backoff and
  `Retry-After`; `RotateKEK` is never retried automatically because a lost
  response may have created a version.

- Adapter operations now take a per-KEK lock: a destroy cannot interleave
  with an in-flight wrap or read in the same process, and a post-destroy wrap
  sees the tombstone instead of resurrecting a key. Cross-process ordering
  still relies on the backend/store transactions and is documented in
  `SECURITY.md`.

### Security and correctness

- OpenBao redirects are refused, preventing `X-Vault-Token` and plaintext DEKs
  from being forwarded to another origin.
- A wrap/datakey call racing `DestroyKEK` cannot leave a usable record under a
  resurrected key; the adapter re-checks the tombstone and best-effort deletes
  a key recreated by transit's upsert.
- `RootKeyFile` decoding no longer copies key bytes into immutable strings and
  no longer includes the key path in errors.
- Config XML/gob serialization is redacted for both adapters.

### Tooling and docs

- `mise run check` now includes `generate-check`, `vuln` and `api-diff`.
- `generate-check` verifies that this repository has no generator config and no
  generated Go files, rather than invoking a generator that cannot run.
- CI checks out full tags (`fetch-depth: 0`) so `api-diff` can find the base
  tag, and uses `mise run check` as the only gate.
- Added a release workflow that runs the gate and `gorelease` on a clean tag,
  and creates the GitHub release from this changelog.
- Actions are pinned by commit SHA; the OpenBao test image is pinned by digest.
- Added this changelog and `UPGRADING.md`.

## v0.2.0 — 2026-10-23

- Fixed `%d` rendering of a `DEK` and root key/token leaks from adapter
  configuration values.
- Added the redaction convention and the OpenBao transit conformance coverage.

## v0.1.0 — 2026-10-23

- First published version: envelope-encryption facade, local and OpenBao
  transit adapters, conformance suites, and the initial build/test tooling.
