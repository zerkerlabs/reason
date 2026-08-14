# Product contract

## End result

Zerker Reason is the reasoning coprocessor for neural agents. It converts candidate goals, facts, and constraints into deterministic decisions with inspectable derivations. It never turns an LLM assertion into an authoritative fact by itself.

The complete loop is:

```text
ZMem governed premises
  -> neural compiler proposes typed ZIR
  -> Zerker Reason checks, solves, or plans
  -> Guard authorizes the concrete action
  -> agent executes
  -> Treeship records commitments and outcome
  -> Gateway joins external invocation identity
```

## First user

The first user is a developer leaving a Prime Agent to prepare a release. They need a direct answer to:

> Is this exact version and commit ready to publish, and if not, what is missing?

The first domain pack is software release safety because its constraints are comprehensible, consequential, and objectively testable.

## Product principles

1. **Decision first.** Human output starts with `PROVED`, `UNKNOWN`, `DISPROVED`, or `INCONSISTENT`.
2. **Unknown is not false.** Missing evidence never becomes denial or success by accident.
3. **No hidden premises.** Every derivation names its facts, rules, assumptions, scopes, and versions.
4. **Neural proposals have low authority.** They require governed promotion or external observation.
5. **Proofs are checked independently.** Solver output alone is not a kernel-verified proof.
6. **Local first.** The kernel works without an account, network, Gateway, or hosted model.
7. **Stable machine contracts.** Agents receive versioned JSON and meaningful exit codes.
8. **Domain packs deliver value.** Generic solver capability is not the product by itself.
9. **Abstention is success when evidence is insufficient.** The system must fail legibly.
10. **Time is input, never ambient state.** Evaluation snapshots are explicit and digest-bound.
11. **Components keep narrow responsibilities.** Reasoning, memory, routing, enforcement, and evidence remain separate.

## Current slice

The current implementation is intentionally narrow:

- typed predicate declarations;
- ground facts with declared authority;
- explicit authority classes and per-predicate admission allow-lists;
- withheld-premise reporting;
- positive Horn rules with positive or explicitly negated atoms;
- deterministic, paraconsistent forward chaining;
- proved, disproved, inconsistent, or unknown outcomes;
- proof and disproof DAGs;
- deterministic conflict witnesses;
- explicit evaluation snapshots with observed and valid time;
- authority-aware fact supersession;
- deterministic temporal withholding reports;
- exact mission and proposed-action bindings;
- four-state action authorization with fail-closed status mapping;
- independently verifiable authorization certificates;
- missing-premise explanation for grounded rules;
- deterministic proof DAG digest;
- independent verification of facts, authority, temporal eligibility, supersession, substitutions, rules, reachability, and cycles;
- text and JSON interfaces.

It does not yet claim:

- complete Datalog semantics;
- negation-as-failure or non-stratified negation;
- globally minimal conflict witnesses across alternate derivations;
- interval propagation through derived conclusions;
- event-stream or incremental truth maintenance;
- a separately packaged minimal/WASM proof kernel;
- cross-language canonical proof encoding;
- SMT or ASP support;
- verification of external evidence behind local authority labels;
- Guard consumption and action-policy enforcement;
- Treeship authorization and denial receipt integration;
- natural-language mission or policy compilation.
