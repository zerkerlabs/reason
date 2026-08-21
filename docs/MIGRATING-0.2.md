# Migrating from Reason 0.1 to 0.2

Reason 0.2 preserves the `zerker.reason.action.v1`, `zerker.reason.authorization.v1`, and `zerker.reason.authorization-bundle.v1` semantic contracts. Existing valid requests and certificates still replay. The release tightens input handling and adds compatibility discovery.

## Required integration changes

1. Run `reason --format json capabilities` at installation or startup and require the schema identifiers and command your adapter uses.
2. Pass request and certificate together to `verify-authorization-bundle` over one bounded stream.
3. Use `--require-authorized` at enforcement boundaries. Exit 0 plus `verified` and `authorized` is the only proceed result.
4. Treat CLI usage errors as exit 1. Exit 2 is reserved for unknown or insufficient evidence.
5. Remove duplicate JSON members and undeclared typed fields. Reason 0.2 rejects both recursively rather than selecting or ignoring them.
6. Keep adapter input/output limits below Reason's declared 67,108,864-byte ceiling and fail closed on timeout or verifier failure.

## Additive contracts

Reason 0.2 adds:

- machine-readable JSON Schemas under `schemas/`;
- `zerker.reason.capabilities.v1`;
- `zerker.reason.release-authorization.v1` and `zerker.reason.release-init.v1`;
- the portable `zerker.reason.conformance-manifest.v1` fixture corpus;
- documented Gateway, Rakhshak, Treeship, and ZMem integration profiles.

JSON Schema checks wire shape only. Continue to run Reason for digest recomputation, proof replay, and status mapping.

## Release-safety starter behavior

`reason release init` writes an empty-evidence starter. Running `reason release authorize` on that unchanged file returns `insufficient_evidence` with exit 2. Populate evidence only from authenticated or governed sources; authority strings are policy labels, not identity proof.

## Compatibility test

```bash
reason --format json capabilities
python3 scripts/check-conformance.py --reason "$(command -v reason)"
```

The corpus contains public deterministic fixtures, not production authorization evidence.
