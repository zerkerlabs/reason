# Zerker Reason

A trustworthy neuro-symbolic reasoning coprocessor for agents.

> **Developer preview:** explore the [live certificate demo](https://zerker-reason.vercel.app) or start with the [deployment quickstart](docs/QUICKSTART.md).

LLMs propose. Zerker Reason checks what follows from explicit facts and rules, identifies what is missing, and returns a deterministic proof object an independent checker can verify.

## First useful workflow

Check whether a release is ready:

```bash
cargo run -- check examples/release-ready.json
```

```text
PROVED  release_ready(1.4.0, commit_abc)
        4 proof nodes
        proof sha256:...
```

Now remove the approval:

```bash
cargo run -- check examples/release-blocked.json
```

```text
UNKNOWN  release_ready(1.4.0, commit_abc)
         missing:
         - approved(1.4.0, release-manager)

Unknown does not mean false. Add an observed fact or an applicable rule.
```

`unknown` exits with code 2 so agents and scripts cannot confuse missing evidence with success or engine failure.

## Truth has four states

Zerker Reason checks support for both a query and its explicit negation:

- `proved`: only the query has support;
- `disproved`: only its explicit negation has support;
- `inconsistent`: both have support;
- `unknown`: neither has support.

```bash
cargo run -- check examples/release-disproved.json     # exit 3
cargo run -- check examples/release-inconsistent.json # exit 4
```

Inconsistency returns both proofs and a conflict witness. It does not silently choose a source or allow the contradiction to prove unrelated claims. See [`docs/TRUTH.md`](docs/TRUTH.md).

## Time is explicit

`zerker.reason.program.v2` adds deterministic evidence snapshots:

- a required `evaluation_time`;
- required `observed_at` on facts;
- optional half-open validity intervals;
- explicit, authority-aware supersession;
- temporal certificates in independently verified proof nodes.

```bash
cargo run -- check examples/release-expired.json
cargo run -- check examples/release-superseded.json
cargo run -- check examples/release-wrong-commit.json
cargo run -- check examples/release-overlap.json
```

V1 remains non-temporal and rejects temporal fields instead of ignoring them. See [`docs/TEMPORAL.md`](docs/TEMPORAL.md).

## Authority is enforced

A fact does not enter inference just because an agent supplied it. Programs declare accepted authority classes per predicate. The release example accepts `tool-reported` evidence for tests and `human-authorized` evidence for approval.

```bash
cargo run -- check examples/release-untrusted.json
```

An agent-proposed approval is withheld and the result remains `UNKNOWN`, with the accepted authority shown as the next requirement. See [`docs/AUTHORITY.md`](docs/AUTHORITY.md).

## Authorize a release without writing policy JSON

Generate an editable release file, then compile tests, review, artifact, and approval evidence into an exact deployment authorization:

```bash
cargo run -- release init release.json
cargo run -- release authorize release.json \
  --request-out action-request.json \
  --certificate-out authorization.json \
  --bundle-out authorization-bundle.json
cargo run -- --format json verify-authorization-bundle \
  authorization-bundle.json --require-authorized
```

Evidence for another commit, a mismatched artifact, a stale approval, or an untrusted authority cannot authorize the deployment. See [`docs/RELEASE-SAFETY.md`](docs/RELEASE-SAFETY.md).

## Authorize an exact action

Check any production action against its governed mission, exact tool arguments, declared effects, temporal evidence, and policy:

```bash
cargo run -- authorize examples/authorize-deploy.json \
  --certificate-out authorization.json
cargo run -- verify-authorization examples/authorize-deploy.json authorization.json

# Enforcement integrations can verify both values from one atomic input.
cargo run -- --format json verify-authorization-bundle bundle.json \
  --require-authorized
```

```text
AUTHORIZED  action_deploy_140 via mission_release_140
            action sha256:...
            mission sha256:...
            evaluated at 2026-08-14T12:00:00Z
            all authorization requirements are proved
```

Changed arguments invalidate the certificate. Unknown, denied, and conflicted results fail closed with actionable issues. Reason produces evidence; Gateway or another trusted boundary must compare and enforce the exact call. See [`docs/ACTIONS.md`](docs/ACTIONS.md).

## Preserve an authorization with Treeship

Reason verifies the certificate semantics. Treeship separately verifies the signature, signer key, and artifact chain:

```bash
TREESHIP_BIN=../treeship/target/debug/treeship \
  ./scripts/reason-treeship-e2e.sh
```

The integration check binds the exact certificate-file digest into the signed receipt and confirms that the receipt carries the same certificate value. See [`docs/TREESHIP.md`](docs/TREESHIP.md).

## Save and independently verify a proof

```bash
cargo run -- check examples/release-ready.json --proof-out release-proof.json
cargo run -- verify examples/release-ready.json release-proof.json
```

```text
VERIFIED  release_ready(1.4.0, commit_abc)
          4 proof nodes
          proof sha256:...
```

Verification does not rerun forward chaining or trust the original check result. It independently checks the ontology digest, query, proof and disproof digests, node identities, fact sources and authorities, rule substitutions, conclusions, conflict witness, reachability, and absence of derivation cycles.

## For agents

Use deterministic JSON over stdin:

```bash
cat examples/release-ready.json | cargo run -- --format json check -
```

The response uses `zerker.reason.result.v1` for non-temporal programs and `zerker.reason.result.v2` for temporal programs. It includes:

- `status`: `proved`, `disproved`, `inconsistent`, or `unknown`;
- the exact query;
- complete program digest;
- ontology identity and digest;
- proof and disproof DAGs when supported;
- deterministic conflict witness when both are supported;
- enforced authority-policy report;
- v2 temporal eligibility and supersession report;
- premise authority and v2 temporal certificates in fact proof nodes;
- action authorization schemas binding missions, exact tool calls, and reasoning certificates;
- admitted and withheld fact IDs;
- missing premises when known;
- explicit assumptions;
- execution metrics.

No network, account, daemon, or LLM is required for the symbolic check.

## Security status

Zerker Reason is pre-release software. Read [`SECURITY.md`](SECURITY.md) before using it near production actions. A valid authorization certificate still requires an independent enforcement layer to bind execution to the exact certified action.

## For developers

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

The current kernel implements typed Horn rules, four-state paraconsistent truth, deterministic temporal evidence lifecycle, and independent proof verification. It establishes stable product contracts before adding Datalog, SMT, ASP, neural compilation, or remote services.

## Product boundaries

Zerker Reason is an independent reasoning service:

- **ZMem** supplies governed premises.
- **Gateway** authenticates and routes reasoning requests.
- **Guard** enforces actions after reasoning.
- **Treeship** records premise, ruleset, result, and proof commitments.

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md), [`docs/PRODUCT.md`](docs/PRODUCT.md), [`docs/EXPERIENCE.md`](docs/EXPERIENCE.md), [`docs/AUTHORITY.md`](docs/AUTHORITY.md), [`docs/TRUTH.md`](docs/TRUTH.md), [`docs/TEMPORAL.md`](docs/TEMPORAL.md), [`docs/ACTIONS.md`](docs/ACTIONS.md), [`docs/PROOFS.md`](docs/PROOFS.md), and [`docs/TREESHIP.md`](docs/TREESHIP.md).
