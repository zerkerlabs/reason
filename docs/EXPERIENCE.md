# Experience contract

User experience, developer experience, and agent experience are acceptance criteria, not polish added after the solver works.

## User experience

A person should be able to answer one consequential question without learning theorem-prover terminology.

Requirements:

- lead with the decision;
- show the exact subject of the decision;
- list missing requirements in domain language;
- explain that unknown does not mean false;
- never print raw internal traces by default;
- provide a next action;
- distinguish invalid input, engine failure, unknown, disproved, inconsistent, and proved;
- show both sides of a contradiction without silently resolving it;
- distinguish missing evidence from supplied but untrusted evidence;
- show which authority class would be accepted;
- show the exact evaluation time and why stale or superseded evidence was withheld;
- recommend refreshing evidence rather than relabeling or guessing;
- keep local checks fast and offline.

## Developer experience

A developer should be able to install, validate, call, test, and extend the engine without operating infrastructure.

Requirements:

- one local binary;
- one versioned program file;
- explicit schema, ontology, and authority-policy versions or digests;
- explicit evaluation time rather than wall-clock dependence;
- canonical timestamp validation and half-open interval semantics;
- per-predicate authority allow-lists rather than implicit trust rankings;
- precise validation paths such as `$.rules[1].then`;
- deterministic output suitable for golden tests;
- no mandatory code generation;
- domain packs as ordinary versioned files;
- a small embeddable Rust library;
- stable exit codes and JSON schemas;
- exact action and mission digest bindings;
- fixtures for proved, unknown, denied, inconsistent, and invalid cases.

## Agent experience

An agent needs stronger contracts than a human CLI user.

Requirements:

- JSON input through files or stdin;
- JSON output on stdout with no mixed logs;
- bounded execution and explicit resource-limit errors;
- no interactive prompts;
- four-state status values that cannot confuse unknown, disproved, and inconsistent;
- separate proof and disproof objects;
- conflict witnesses an agent can escalate rather than resolve inventively;
- authorization statuses that fail closed for unknown, denial, and conflict;
- deterministic issues explaining missing, stale, superseded, or untrusted requirements;
- missing premises the agent can act on;
- ontology and ruleset digests for cache and evidence binding;
- proof references rather than generated chain-of-thought;
- independently verifiable proof files;
- declared authority and provenance for every premise;
- temporal certificates for v2 fact proof nodes;
- machine-readable authority and temporal premise decisions;
- deterministic ordering;
- safe retries through idempotent inputs.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Query proved, or validation passed |
| 1 | Invalid input or engine failure |
| 2 | Query is unknown with current premises |
| 3 | Query is disproved by explicit opposing support |
| 4 | Query and its explicit negation are both supported |

## Experience test

Every release must pass three checks:

1. A new user can run the release example and understand why it passed or stopped.
2. A developer can diagnose an invalid predicate from the reported JSON path.
3. An agent can call the binary over stdin, branch on the exit code, and parse one versioned JSON document from stdout.
4. A second process can verify a saved proof and reject changed facts, authority, time, rules, query, or proof structure.
5. A user can distinguish expired, future, and superseded evidence from absent or untrusted evidence.
6. Changing any authorized tool argument causes independent certificate verification to fail.
