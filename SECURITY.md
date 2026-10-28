# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

## Supported versions and status

This module is **pre-1.0**. The API may change, and it has not had an external
security review. There is no LTS or support window yet; only the tip of `main`
is supported until a v1 release policy exists. Do not deploy it where a failure
would be material without reading `CHARTER.md` and the threat model below.

## Threat model

The baseline is:

- The application process and its memory are trusted.
- The OpenBao/Vault server and its TLS endpoint are trusted. A compromised or
  malicious key manager is out of scope.
- The `KEKStore` (local adapter) is trusted for availability and integrity; a
  stolen store or database backup must not yield usable keys without the
  deployment root key.
- The network may be hostile: the adapter must not send the token or plaintext
  DEKs over cleartext to a remote host, and must not follow redirects that
  would forward them.
- Caller logs, errors, debug endpoints and configuration serialization are
  in scope. Key material must not be renderable through the supported
  `fmt`/JSON/XML/gob/`slog` paths. `%p` is a documented exception (see
  `CONVENTIONS.md`).

Out of scope: a compromised host/process or core dumps; a compromised OpenBao
server; backup/snapshot erasure; threshold custody; authorization policy
inside OpenBao; and failure of the deployment to supply a durable `KEKStore`.

## Crypto-shredding

`DestroyKEK` is intended to be linearizable in the live system: after it
returns, operations naming that KEK fail rather than returning a DEK. Backups,
snapshots, object-store versions and the root key are **not** erased by
`DestroyKEK`; a restore of the wrapped KEK plus the root key can recover it.
The implementation is being hardened against the destroy/wrap race and
tombstone-present/key-present states; do not treat an erasure certificate as
covering backups.

## What the conformance suite proves, and what it does not

Each port ships a conformance suite that every adapter must pass, and the
suite — not the interface — is the authoritative description of the contract.
Security invariants have their own named subtests, so an adapter cannot quietly
skip one.

The suite proves the *contract*. It cannot prove *enforcement* that belongs to
something outside this process: a database's row-level security, a key
manager's access policy, an operator's privilege separation, a backup's
deletion policy, or TLS configuration. Those are verified by integration tests
against the real dependency where one exists, and are otherwise the
deployment's responsibility.
