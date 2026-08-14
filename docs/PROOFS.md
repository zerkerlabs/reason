# Proof contract

A `zerker.reason.result.v1` or `result.v2` document may contain a proof of the query, a disproof that proves its explicit complement, or both. Each DAG is verified against the exact corresponding program document that supplied its ontology, authority policy, evaluation snapshot, facts, rules, and query.

## Verification command

```bash
reason verify program.json result.json
```

A successful human response begins with `VERIFIED` and includes the verified result status. JSON mode returns the matching `zerker.reason.verification.v1` or `verification.v2` schema. An `unknown` result has no derivation certificate and cannot be independently verified without rerunning the check.

## What verification checks

The verifier fails closed unless all checks pass:

1. Program validation succeeds.
2. Result schema is recognized and status matches the presence of proof and disproof.
3. Result query exactly matches the program query.
4. The complete program digest matches, including facts, authorities, temporal fields, rules, ontology, and query.
5. Ontology ID, version, and digest match.
6. The authority-policy report recomputes exactly.
7. For v2, evaluation time, temporal eligibility, supersession, and withheld-fact report recompute exactly.
8. Every proof and disproof digest recomputes from its root and ordered nodes.
9. A proof root concludes the query and a disproof root concludes its explicit complement.
10. Node IDs recompute from their complete atoms.
11. Node IDs are unique and canonically ordered within each DAG.
12. Every root exists.
13. Every fact node maps to the exact program fact ID, atom, and authority.
14. Every fact node is admitted for its predicate by the authority policy.
15. Every v2 fact node's temporal certificate matches its source and is eligible at evaluation time.
16. Every derived node maps to an existing rule.
17. Premises match the rule body in order under one consistent variable substitution.
18. The instantiated rule head equals the claimed conclusion.
19. The derivation has no cycle.
20. Every included node is reachable from its root.
21. An inconsistent result's conflict witness recomputes from both verified DAGs.

Changing an authority label is proof tampering even when the logical atom stays unchanged.

## Action authorization certificates

`zerker.reason.authorization.v1` binds the complete reasoning result to exact mission, action, and request digests. `reason verify-authorization` reconstructs the system-bound action facts, recomputes the reasoning result, replays any proof DAGs, and verifies the authorization status and issue list. Recomputing the result also makes `insufficient_evidence` certificates checkable even though unknown itself has no positive derivation proof.

Changing a tool argument, declared effect, mission constraint, or instruction digest invalidates the certificate before an action can be treated as authorized.

## What verification does not prove

Verification does not establish that a premise was true in the external world. It establishes that:

- the proof is structurally intact;
- its facts match the supplied program;
- its derivations follow the supplied rules;
- its conclusion matches the supplied query.

External truth requires an authority boundary such as an observed tool result, human authorization, Guard decision, Gateway observation, or Treeship countersignature. Those integrations will bind their evidence to fact IDs and digests in later slices.

## Current canonicalization boundary

The current Rust implementation hashes deterministic `serde_json` output over typed structures. This is stable inside the implementation and covered by determinism tests. It is not yet a cross-language canonical encoding specification. Do not label current proof digests cross-language portable until a canonical encoding and test vectors ship.
