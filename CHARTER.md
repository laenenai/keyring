# Charter: `keyring`

**It does this one thing:** Envelope encryption with WrapDEK / GenerateDEK / UnwrapDEK / RewrapDEK / RotateKEK / DestroyKEK, with local and openbao-transit adapters. The root key is outside the process only with transit; the local adapter keeps it in-process and requires a durable `KEKStore` for persisted content. External-KMS adapters are out of the public surface until a real transport exists.

**It must not contain:** What is being encrypted. Shredding policy. Any domain concept. (cas/internal/crypto is a blob stream cipher and stays in cas.)

## Why this file exists

A shared module with no stated boundary accretes until it is the dependency
every project has and nobody can reason about. This charter is the boundary.
Two mechanisms enforce it rather than merely stating it:

1. **Go compatibility tooling.** `mise run api-diff` compares the importable
   API with the last root tag using `apidiff`; the release workflow runs
   `gorelease` on the clean tagged commit. Pre-1.0 incompatible changes are
   reported and documented in `CHANGELOG.md`/`UPGRADING.md`; from 1.0 they
   fail the gate. `internal/...` is not part of the public contract.
2. **The conformance suite** (`keyringtest/suite.go` and
   `keyringtest/kekstore.go`) is the contract. A consumer counts as
   *adopted* when this module's suite runs green in that consumer's CI against
   its own wiring — not when someone says it is adopted.

A change that does not fit the charter belongs in a different module. A module
is created when a **second** consumer needs it, not in anticipation.

## Adoption

| Consumer | State |
|---|---|
| cas | greenfield (nothing built) |
| kgs | pending (phase 0) |
| acre | pending (no code yet; adopts from birth) |

## Provenance

Extracted per `kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md`
§6.1 (the six-module decomposition) and §6.2 (authority and projections).
