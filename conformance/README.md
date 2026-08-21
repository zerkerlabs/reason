# Reason authorization conformance corpus

`v1/manifest.json` is a portable, deterministic set of exact-action authorization verifier vectors. It covers all four verified authorization outcomes, expiry, request/policy/certificate mutation, malformed and ambiguous JSON, unsupported schemas, and the Gateway and Rakhshak integration profiles.

Run the reference replay from a source checkout:

```bash
cargo build --locked --bin reason
python3 scripts/check-conformance.py --reason "$PWD/target/debug/reason"
```

From an unpacked release archive, run:

```bash
python3 scripts/check-conformance.py --reason "$PWD/reason"
```

The manifest commits each input's SHA-256, command arguments, expected exit code, output schema and status, and—when verification succeeds—the exact authorization status, request digest, and reasoning-result digest. The replay does not regenerate expected values from the binary under test.

A cross-language integration can consume the same manifest and raw input bytes. It must preserve those bytes, run the listed atomic verifier command, require the exact committed outcome, and fail closed on every mismatch. Error text is intentionally not stable; error schema, status, shape, and exit code are stable here.

These are public fixtures, not live authorizations or production evidence.
