# keyring

Envelope encryption with the root key outside the process: WrapDEK / UnwrapDEK / RotateKEK, with local, openbao-transit and external-kms adapters.

**Not in scope:** What is being encrypted. Shredding policy. Any domain concept. (cas/internal/crypto is a blob stream cipher and stays in cas.)

See [CHARTER.md](CHARTER.md) for the boundary and how it is enforced, and
`api.txt` for the public surface.
