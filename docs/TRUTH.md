# Four-state truth

Zerker Reason uses explicit negation and preserves contradictions. It does not infer falsity from missing evidence and does not allow a contradiction to entail arbitrary conclusions.

For a query `Q`, the engine checks support for both `Q` and its explicit complement `not Q`:

| Support for Q | Support for not Q | Status |
|---|---|---|
| yes | no | `proved` |
| no | yes | `disproved` |
| yes | yes | `inconsistent` |
| no | no | `unknown` |

## Explicit negation

A negative fact or rule conclusion sets `negated: true`:

```json
{
  "id": "fact_release_blocked_140",
  "predicate": "release_ready",
  "arguments": ["1.4.0", "commit_abc"],
  "negated": true,
  "authority": "human-authorized"
}
```

Negation is part of the atom identity, proof node ID, program digest, authority decision, and proof verification.

## Disproved

`disproved` requires a derivation for the explicit complement. The engine never returns it merely because the query lacks support.

```text
DISPROVED  release_ready(1.4.0, commit_abc)
            opposing support: 1 nodes
            disproof sha256:...
```

## Inconsistent

When both sides have support, the engine returns both proofs and a deterministic conflict witness:

```text
INCONSISTENT  release_ready(1.4.0, commit_abc)
              support: 4 nodes
              proof sha256:...
              opposing support: 1 nodes
              disproof sha256:...
              conflict facts: fact_approval_140, ..., fact_release_blocked_140
```

The witness contains the union of leaf fact IDs from the selected deterministic proof and disproof. It is irreducible for those selected derivations, but it is not yet claimed to be the globally smallest witness across every possible derivation.

An inconsistent result must fail closed at an authorization boundary. The reasoning kernel preserves the conflict; Guard or a human decides how it may be resolved.

## No explosion

A contradiction about `release_ready` does not prove an unrelated predicate such as `deployment_allowed`. Rules still require their stated premises. This is the core paraconsistent behavior required for real agent knowledge, where sources can disagree without making the entire knowledge base useless.

## Exit codes

| Code | Status |
|---:|---|
| 0 | proved |
| 2 | unknown |
| 3 | disproved |
| 4 | inconsistent |

Code 1 remains reserved for invalid input, engine failure, or failed verification.
