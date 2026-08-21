# Changelog

## [Unreleased]

## [0.2.0] - 2026-08-21

### Added

- Publish Draft 2020-12 schemas for stable action, authorization, bundle, verification, error, and release-safety wire values.
- Report deterministic supported schemas, commands, statuses, exit codes, and limits with `reason --format json capabilities`.
- Ship a portable authorization conformance corpus with committed request and reasoning-result digests.
- Exercise every serialized request, certificate, and release-input leaf through deterministic mutation-security tests.
- Define explicit Gateway, Rakhshak, Treeship, and ZMem integration profiles without adding downstream semantics to Reason core.
- Compile a product-level release-safety input into an exact deployment authorization with `reason release init` and `reason release authorize`.
- Emit the compiled request, certificate, and atomic Gateway-ready bundle from one release command.
- Verify an action request and authorization certificate atomically from one versioned JSON bundle, including standard input for subprocess integrations.
- Optionally preserve fail-closed authorization exit codes after successful bundle verification.
- Build release archives for Linux arm64 in addition to Linux x86_64 and macOS arm64/x86_64.

### Changed

- Cap every CLI JSON input at 64 MiB.
- Reject duplicate JSON object members recursively instead of accepting last-value-wins map entries.
- Reject unrecognized members in versioned CLI JSON schemas instead of silently discarding unsigned semantics.
- Return exit code 1 for invalid CLI usage so it cannot collide with exit code 2 for unknown or insufficient evidence.
- Keep `reason release init` starters empty of positive evidence so unchanged starters fail closed.
- Stage and verify every release archive before publishing a draft GitHub release.

## [0.1.0] - 2026-08-17

### Added

- Derive deterministic proof DAGs from typed facts and Horn rules, then verify them independently.
- Preserve proved, disproved, inconsistent, and unknown outcomes without treating missing evidence as false.
- Enforce authority policies, explicit negation, temporal validity, and authority-aware supersession.
- Authorize exact agent actions bound to missions, tools, arguments, effects, policy, evidence, and evaluation time.
- Verify authorization certificates independently and fail closed on missing, denied, stale, or conflicting evidence.
- Preserve verified authorization certificates in Treeship receipts with exact certificate-file digest binding.
- Exercise release-safety behavior with authorized, insufficient-evidence, denied, conflicted, stale, superseded, and wrong-commit fixtures.
- Run the certificate-backed product demo as a standalone website with four independently replayable outcomes.
- Build and test on macOS and Linux, with tagged release archives and SHA-256 checksums.
