# keyring

[![ci](https://github.com/laenenai/keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/keyring/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/keyring.svg)](https://pkg.go.dev/github.com/laenenai/keyring)

Envelope encryption with the root key outside the process.

Wrap and unwrap data encryption keys against a key manager that may be a local
root key, an OpenBao/Vault transit engine, or an external KMS — behind one
interface, with one conformance suite every adapter must pass unchanged.

> **Status: pre-1.0.** The `local` and `openbao-transit` adapters are
> implemented and tested, the latter against a real OpenBao container. The
> `external-kms` adapter is a stub. The API may change before v1.

## Install

```
go get github.com/laenenai/keyring
```

Requires Go 1.25.6 or later. No cgo. The only dependency is
`testcontainers-go`, and it is test-only.

## Example

```go
km, err := local.Open(ctx, local.Config{
	RootKey: rootKey, // at least keyring.DEKSize bytes, from your secret store
	Store:   local.NewMemKEKStore(),
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
```

Swapping `local` for `openbaotransit` changes the import and the config, and
nothing else: the conformance suite runs against both unchanged.

## What it does

- `GenerateDEK`, `WrapDEK`, `UnwrapDEK`, `RewrapDEK`, `RotateKEK`, `DestroyKEK`.
- A wrapped DEK records **which KEK version wrapped it**, so rotating a KEK is
  lazy re-wrapping rather than re-encrypting content.
- `RewrapDEK` moves a record to the current KEK version **without decrypting
  it** on the transit adapter — the plaintext key never enters this process.
  It is a first-class operation, not unwrap-then-wrap.
- A `DEK` is zeroizable and redacted through every rendering path: `String`,
  `GoString`, `MarshalText`, `MarshalJSON` and `slog.LogValuer`. Unmarshalling
  one from JSON is refused.

## Notes on the adapters

**`local`** derives a per-record key from a per-record salt, so no two records
share a key and the GCM nonce-reuse bound never caps how many DEKs one KEK may
wrap. The additional authenticated data binds a record to its KEK id, KEK
version and key id, so a record cannot be lifted onto a different key.

**`openbao-transit`** keeps the root key out of this process entirely. It
creates derived keys, using the key id as transit's context, which is transit's
counterpart to the local adapter's AAD. `DestroyKEK` writes a tombstone before
deleting the key, because transit's `encrypt` endpoint *creates* missing keys —
without the tombstone, wrapping under a destroyed KEK id would silently
resurrect it as a fresh version, and crypto-shredding would be a lie.

## What it does not do

What is being encrypted. Shredding policy. Threshold custody of keys. Any
domain concept.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary and the two mechanisms that enforce it
- [`SECURITY.md`](SECURITY.md) — reporting, and what the conformance suite does and does not prove
- `api.txt` — the public surface as a golden file, diffed in CI

## License

Apache-2.0. See [`LICENSE`](LICENSE).
