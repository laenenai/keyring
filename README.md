# keyring

[![ci](https://github.com/laenenai/keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/keyring/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/keyring.svg)](https://pkg.go.dev/github.com/laenenai/keyring)

Envelope encryption with the root key outside the process when the key manager
is OpenBao/Vault. The local adapter keeps the root key in the process.

Wrap and unwrap data encryption keys against a key manager that may be a local
root key or an OpenBao/Vault transit engine — behind one interface, with one
conformance suite every adapter must pass unchanged.

> **Status: pre-1.0.** The `local` and `openbao-transit` adapters are
> implemented and tested, the latter against a real OpenBao container. The
> local adapter requires a durable `KEKStore`; `MemKEKStore` is test-only and
> loses every KEK on process exit. The API may change before v1.

## Install

```
go get github.com/laenenai/keyring
```

Requires Go 1.27.3 or later. No cgo. The only direct dependency is
`testcontainers-go`, and it is test-only; its transitive modules remain in the
module graph.

## Example

```go
km, err := local.Open(ctx, local.Config{
	RootKey: rootKey, // at least keyring.DEKSize bytes, from your secret store
	Store:   store,   // a durable local.KEKStore, NOT local.NewMemKEKStore()
})
if err != nil {
	return err
}

// The key manager mints the DEK, so no plaintext key is generated here.
dek, wrapped, err := km.GenerateDEK(ctx, keyring.KEKID("tenant-42"), keyring.KeyID("doc-7"))
if err != nil {
	return err
}
defer dek.Destroy()

// Store `wrapped` next to the ciphertext; it records which KEK version
// wrapped it, so rotation is lazy re-wrapping and never re-encryption.
back, err := km.UnwrapDEK(ctx, wrapped)
if err != nil {
	return err
}
defer back.Destroy()
```

`MemKEKStore` is for tests and deliberately ephemeral processes only. A
deployment that stores content must provide a durable `local.KEKStore`; using
the in-memory store is crypto-shredding by accident.

Swapping `local` for `openbaotransit` keeps the same call sites, but existing
records are adapter-specific and require a side-by-side rewrap migration (old
adapter unwraps, new adapter wraps). The conformance suite runs against both
adapters unchanged; the deployment threat model does not: `local` keeps the
root key in-process, while transit keeps it outside.

## What it does

- `GenerateDEK`, `WrapDEK`, `UnwrapDEK`, `RewrapDEK`, `RotateKEK`, `DestroyKEK`.
- A wrapped DEK records **which KEK version wrapped it**, so rotating a KEK is
  lazy re-wrapping rather than re-encrypting content.
- `RewrapDEK` moves a record to the current KEK version **without decrypting
  it** on the transit adapter — the plaintext key never enters this process.
  It is a first-class operation, not unwrap-then-wrap.
- A `DEK` is zeroizable and redacted through the controllable rendering paths:
  `Format` (which covers every `fmt` verb except the documented `%p`/`%T`
  holes), `String`, `GoString`, `MarshalText`, `MarshalJSON` and
  `slog.LogValuer`. Unmarshalling one from JSON is refused. Both adapters'
  `Config` values redact through `fmt`, JSON, XML, gob and `slog`;
  `KeyManager` values redact through `fmt`, JSON and `slog`. Logging or
  serializing a configuration at startup therefore does not log the deployment
  root key or an OpenBao token. `%p` remains a known exception; see
  `CONVENTIONS.md`.

## Notes on the adapters

**`local`** derives a per-record key from a per-record salt, so no two records
share a key and the GCM nonce-reuse bound never caps how many DEKs one KEK may
wrap. The additional authenticated data binds a record to its KEK id, KEK
version and key id, so a record cannot be lifted onto a different key. The
root key (or its derived wrapping key) is in this process's address space; the
`RootKeyFile` encoding is explicit (`raw`, `hex` or `base64`) and never
auto-detected, so a malformed file fails at startup instead of silently using
different key material.

**`openbao-transit`** keeps the root key out of this process entirely. It
creates derived keys, using the key id as transit's context, which is transit's
counterpart to the local adapter's AAD. `DestroyKEK` writes a tombstone before
deleting the key, because transit's `encrypt` endpoint *creates* missing keys —
without the tombstone, wrapping under a destroyed KEK id would silently
resurrect it as a fresh version, and crypto-shredding would be a lie. Plain
HTTP is accepted only for loopback; a remote address requires HTTPS unless
`AllowInsecureHTTP` is explicitly set. Redirects are never followed.

## What it does not do

What is being encrypted. Shredding policy. Threshold custody of keys. Backups
or snapshot erasure. A durable local store (the local adapter requires a
`KEKStore` implementation). Any domain concept.

## Development

```
mise install
mise run test      # fast inner loop; no containers
mise run test-all  # race detector + OpenBao container; requires Docker
mise run check     # fmt, lint, build, test-all, generate-check, vuln, api-diff
```

Tool versions are pinned in `mise.toml`; CI uses the same file via
`jdx/mise-action`. `mise run generate` is reserved for modules with a
`sqlc.yaml` and currently fails in this repository; it is not part of `check`.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary and the two mechanisms that enforce it
- [`SECURITY.md`](SECURITY.md) — reporting, and what the conformance suite does and does not prove
- [`CONVENTIONS.md`](CONVENTIONS.md) — the shared Go and redaction conventions
- [`CHANGELOG.md`](CHANGELOG.md) — human-readable release notes
- [`UPGRADING.md`](UPGRADING.md) — migration steps for breaking changes
- [`docs/review/20261028_review.md`](docs/review/20261028_review.md) — the production-readiness review and decisions

## License

Apache-2.0. See [`LICENSE`](LICENSE).
