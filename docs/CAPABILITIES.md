# Capability discovery

A client can inspect a Reason binary before sending policy or authorization material:

```bash
reason --format json capabilities
```

The command emits `zerker.reason.capabilities.v1` and exits with code 0. It does not read standard input, inspect files, consult an ambient clock, access the network, or report host and build-machine details.

The response declares:

- the binary package version;
- supported program, result, action, authorization, organization-policy source/template/bundle/authorization/verification, validation, verification, and error schema identifiers;
- supported top-level command names, including the additive `policy` workflow;
- reasoning, authorization, validation, verification, and error status values;
- exit-code meanings, including command-usage failure;
- the fixed maximum JSON input size in bytes; and
- fixed organization-policy source count, path, file, aggregate, manifest, template, bundle, authorization input/output, and independent-verification input limits.

Use the identifiers as compatibility data, not as proof that an input is semantically valid. JSON wire validation can reject a malformed shape. Reason's validator, evaluator, and verifier remain authoritative for policy semantics, source and bundle digest recomputation, proof replay, status mapping, and authorization. Advertising the organization-policy contracts does not advertise a Markdown compiler or claim that source prose was read or understood.

Consumers should reject an unsupported capabilities schema or a missing required command, schema, status, or exit-code meaning. Command-line usage errors share code 1 with invalid input and verifier or engine failure; they never reuse the fail-closed outcome codes 2 through 4. `policy authorize` and `policy verify-authorization --require-authorized` preserve exits 2, 3, and 4 for insufficient evidence, denial, and conflict. They should not infer support from a newer binary version alone.

Human-readable discovery is available without `--format json`:

```bash
reason capabilities
```

Both formats are generated from the same constants. Tests compare the machine document exactly, verify command inventory against Clap, and replay the command from different directories and environments to prevent accidental host-state leakage.

## Compatibility policy

`zerker.reason.capabilities.v1` is additive within v1: existing fields and meanings stay stable, and new supported values may be added. Removing or redefining a declared value requires a new capabilities schema identifier. Consumers should ignore additive values they do not need while failing closed when a required value is absent.
