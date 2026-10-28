# Architecture

`keyring` separates three key levels:

1. **Root key** — the deployment secret. With `local` it is read once at
   `Open` and only a derived wrapping key is retained. With
   `openbaotransit` it never enters the process; transit holds the root key.
2. **KEK** — one key-encryption key per isolation unit (for example a
   tenant). It has numbered versions; `RotateKEK` adds a version rather than
   rewriting existing records.
3. **DEK** — one data-encryption key per object. The caller encrypts content
   with it, stores the `WrappedDEK` record returned by the manager, and
   destroys its copy.

## Records

A `WrappedDEK` carries the KEK id, KEK version, key id, adapter format and
opaque ciphertext. The key id is bound into the ciphertext/AAD, so moving a
record to another row fails closed. The format (`local/v1`,
`openbao-transit/v1`) prevents one adapter from treating another adapter's
ciphertext as its own; an empty format is a legacy record from before the
field existed.

The binary form starts with a format version and length-prefixes every field.
The JSON field names are stable. Persisted records are not portable between
adapters: a migration must decrypt/rewrap with the old adapter and write with
the new one.

## Local adapter

KEK material lives in a `kekstore.KEKStore`, wrapped under a root-derived
AES-256 key. Each DEK or KEK record uses HKDF-SHA256 with a fresh salt and
AES-256-GCM; the AAD contains the record kind and identifiers. The local wire
format is pinned by `keymanager/local/wire_golden_test.go`. The companion
module `github.com/laenenai/keyring/postgres` is the durable reference store;
`MemKEKStore` loses every KEK at process exit and is for tests only.

## OpenBao transit adapter

The adapter uses transit keys with derivation enabled and passes the key id as
transit's context. `DestroyKEK` writes a tombstone key, raises
`min_decryption_version`, then deletes the key. Reads and writes re-check the
tombstone after the server call, and per-KEK locks serialize destruction
against wraps inside one adapter instance. Across processes the post-call
check closes the resurrected-key window, but the tombstone is a transit key,
not a server-signed token: split administrative and runtime tokens and keep
the mount private.

Retries are bounded by `Config.Retry` for transport errors, 429 and 5xx.
`RotateKEK` is not automatically retried because a lost response may already
have created a version. The adapter returns `ErrTransient`, `ErrRateLimited`
and `ErrPermissionDenied` so callers can make their own policy.

## Failure boundaries

- A missing KEK is `ErrKEKNotFound`; a destroyed one is `ErrKEKDestroyed`.
- A record that does not authenticate is the deliberately opaque
  `ErrUnwrapFailed`, never an oracle about which field was wrong.
- A `KEKStore` must be durable and transactional enough to enforce
  `CreateKEKVersion` create-only semantics; the Postgres store uses row locks
  and unique constraints.
- Backups, snapshots and the root key are outside the live crypto-shredding
  guarantee. See `SECURITY.md`.
