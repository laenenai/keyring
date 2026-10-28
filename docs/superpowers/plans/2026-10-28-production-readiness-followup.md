# Production-Readiness Follow-Up Implementation Plan

> **For agentic workers:** Execute inline with `superpowers:executing-plans` and TDD. Steps use checkbox tracking.

**Goal:** close the remaining P0/P1 review findings and merge the result to `main` through a PR.

**Architecture:** move the store port to a neutral package, add a versioned record/capability surface, ship a Postgres companion store, add bounded OpenBao retries and fault tests, make destruction checks linearizable within an adapter, and add optional lifecycle/observability hooks.

**Tech Stack:** Go 1.27.3, apidiff/gorelease, Postgres (`pgx`/testcontainers), OpenBao 2.2.1.

**Spec:** `docs/review/20261028_review.md` (P0/P1) and the maintainer decisions Q1–Q14.

## Global Constraints

- Pre-1.0: incompatible API changes are allowed but must be documented in `CHANGELOG.md` and `UPGRADING.md`.
- Keep the core module dependency-light; the durable Postgres store is a companion module.
- Never put secret material in logs, errors, JSON/XML/gob renderings, or persistence.
- `mise run check` is the gate; it includes fmt, lint, build, test-all, generate-check, vuln and api-diff.
- No commit/push/tag except as explicitly requested; this plan's final step opens a PR and merges after green.

## Tasks

### Task 1: Neutral store port
- Create `keymanager/kekstore` with `KEKStore`, `MemKEKStore`, `ErrKEKVersionExists`.
- Alias them from `local` for compatibility; update `keyringtest` to import the neutral port.
- Tests: `keyringtest.RunKEKStoreSuite` against the neutral `MemKEKStore`; alias compile tests.

### Task 2: Versioned records and rewrap capability
- Add `WrappedDEK.Format`/`Adapter` (or equivalent) and stable binary/JSON tags + `FormatVersion`.
- Add `RewrapCapability` optional interface implemented by `openbaotransit`; local does not claim it.
- Tests: round-trip persistence, unknown format rejection, per-adapter capability assertion.

### Task 3: Postgres companion module
- Create `postgres/go.mod`, schema/migrations, `Store`.
- Run `keyringtest.RunKEKStoreSuite` against a real Postgres container.
- Wire `test-all` and the release workflow for `postgres/v*`; document the companion module.

### Task 4: OpenBao fault injection and retry policy
- Add `httptest` tests for 400/403/404/429/500/502/503, `Retry-After`, malformed/oversized bodies, timeouts, redirects, token headers.
- Add `ErrTransient`/`ErrUnavailable`/`ErrRateLimited` and bounded retry/backoff for safe operations; document `RotateKEK` ambiguity.
- Tests: attempt counts, no retry on 4xx, context cancellation, retry budget.

### Task 5: Destruction linearizability and concurrency
- Add per-KEK locks in both adapters so destroy/wrap/read cannot interleave inside one adapter instance.
- Split the conformance concurrency test; require rotation; add destroy-vs-wrap/read barrier tests.
- Tests: `-race -count=25` for the fake and real suites.

### Task 6: Lifecycle, observability, wire golden and fuzz
- Add optional `Close` and observer/logger hooks without changing `KeyManager`.
- Add a fixed local wire-format fixture and fuzz targets for record/ciphertext parsers.
- Tests: close zeroizes/releases; golden unwrap; seeds execute.

### Task 7: Docs, release and merge
- Update README/CHANGELOG/UPGRADING/SECURITY/architecture docs for the new API and companion module.
- Final `mise run check`; open a PR, wait for CI, merge to `main`.

## Review Focus

- A destroyed KEK must never return a DEK or accept a new wrap, including under concurrent calls.
- A consumer must be able to read a record written by an older build with the same format version.
- A Postgres outage, retry, or cancelled context must not leave a half-created KEK version.
- No error, log, serialization, or lifecycle method may expose root-key/KEK/token material.
- Pre-1.0 API changes must be documented before merge.
