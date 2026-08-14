# Security policy

Zerker Reason is pre-release software. Do not treat it as the sole control protecting a production action until an enforcement layer independently verifies its authorization certificate and binds execution to the exact certified action.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Email `security@zerker.ai` with:

- the affected version or commit;
- a minimal reproducer;
- the expected and observed result;
- the security impact.

We will acknowledge the report, coordinate remediation, and publish details after a fix is available.

## Security model

Reason assumes an attacker may control:

- the neural agent proposing an action;
- untrusted facts and memories;
- action arguments submitted for authorization;
- a solver result or certificate presented for verification;
- the order of otherwise equivalent JSON inputs.

Reason therefore:

- admits facts only through predicate-specific authority policies;
- reserves action and mission bindings as system-bound facts;
- binds certificates to complete program, request, action, mission, policy, ontology, evidence, and evaluation-time digests;
- preserves unknown, negative, and contradictory evidence as distinct fail-closed outcomes;
- independently verifies proof structure rather than trusting the original solver result;
- does not read ambient wall-clock time during a check.

## Trust boundaries

- ZMem is responsible for premise governance and human promotion.
- Reason is responsible for deterministic derivation and certificate verification.
- Guard is responsible for enforcing only the exact verified action.
- Treeship is responsible for signer, byte commitment, and artifact-chain verification.
- Gateway is responsible for caller authentication, tenant isolation, and routing.

A Treeship signature does not prove Reason semantics. A valid Reason certificate does not prove that Guard enforced it. Production systems must run the relevant verifiers at each boundary.

## Out of scope for v0.1

- solver completeness outside the documented typed Horn-rule kernel;
- confidentiality of facts embedded in complete certificates;
- key management or signer identity for external receipt systems;
- revocation and distributed policy discovery;
- sandboxing or execution of authorized tools;
- protection against a compromised enforcement layer.
