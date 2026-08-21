# Action authorization

Zerker Reason can authorize an exact proposed action against a governed mission and a deterministic temporal policy.

```bash
reason authorize examples/authorize-deploy.json \
  --certificate-out authorization.json
reason verify-authorization examples/authorize-deploy.json authorization.json
```

The contract is local, deterministic, and does not require an LLM, account, daemon, or network.

## Statuses

| Authorization status | Reasoning status | Boundary behavior | Exit |
|---|---|---|---:|
| `authorized` | `proved` | Eligible for Guard enforcement | 0 |
| `insufficient_evidence` | `unknown` | Fail closed; obtain governed evidence | 2 |
| `denied` | `disproved` | Fail closed; explicit denial is proved | 3 |
| `conflicted` | `inconsistent` | Fail closed; escalate conflicting evidence | 4 |

An authorization result does not execute anything. Guard remains responsible for enforcing whether the action may run.

## Machine-readable wire schemas

Draft 2020-12 schemas for the request, certificate, atomic bundle, verification result, and CLI error are committed in [`schemas/`](../schemas/README.md). They validate JSON wire shape, closed typed objects, status vocabularies, and digest/timestamp encoding. They do not recompute a digest, replay a proof, establish premise truth, or decide authorization; the Reason verifier remains authoritative.

Keep `zerker.reason.contracts.v1.schema.json` beside an entry schema so its relative `$ref` resolves.

## Request schema

`zerker.reason.action.v1` binds three objects:

```json
{
  "schema": "zerker.reason.action.v1",
  "mission": {
    "id": "mission_release_140",
    "principal": "user:release-owner",
    "instruction_digest": "sha256:...",
    "issued_at": "2026-08-14T10:00:00Z",
    "valid_until": "2026-08-14T18:00:00Z",
    "constraints": {
      "environment": "production",
      "version": "1.4.0",
      "commit": "commit_abc"
    }
  },
  "action": {
    "id": "action_deploy_140",
    "tool": "deploy_release",
    "proposed_at": "2026-08-14T12:00:00Z",
    "arguments": {
      "environment": "production",
      "version": "1.4.0",
      "commit": "commit_abc"
    },
    "effects": [
      {
        "kind": "deploy",
        "resource": "release:1.4.0",
        "value": "production"
      }
    ]
  },
  "policy": { "schema": "zerker.reason.program.v2" }
}
```

The instruction digest commits to the original instruction but does not establish that an LLM-generated mission faithfully represents it. Agent-authored mission frames must remain quarantined until promoted by a governed authority.

## Deterministic request bindings

The action checker constructs an effective temporal reasoning program by injecting facts that are derived directly from the request—not supplied by the policy author:

- `mission_active(mission)`
- `mission_action(mission, action)`
- `mission_principal(mission, principal)`
- `mission_instruction(mission, instruction_digest)`
- `mission_constraint(mission, key, value)`
- `action_tool(action, tool)`
- `action_argument(action, key, value)`
- `action_effect(action, kind, resource, value)`

These facts use the reserved `system-bound` authority. Policies cannot declare that authority, supply reserved facts, override their admission rules, or derive reserved binding predicates. They may derive only `action_authorized(action)` or its explicit negation.

String values remain strings. Numbers, booleans, nulls, arrays, and objects receive deterministic type-prefixed encodings in reserved binding atoms. The complete typed mission and action are independently digest-bound regardless of their logical projection.

The action policy must use `program.v2`, and its query must be the exact action ID:

```json
{
  "predicate": "action_authorized",
  "arguments": ["action_deploy_140"]
}
```

## Policy example

A production deployment rule can require that the mission, action arguments, declared effects, tests, review, and approval all agree:

```json
{
  "id": "rule_authorize_production_deploy",
  "when": [
    { "predicate": "mission_active", "arguments": ["$mission"] },
    { "predicate": "mission_action", "arguments": ["$mission", "$action"] },
    { "predicate": "action_tool", "arguments": ["$action", "deploy_release"] },
    { "predicate": "action_argument", "arguments": ["$action", "commit", "$commit"] },
    { "predicate": "tests_passed", "arguments": ["$commit"] },
    { "predicate": "security_reviewed", "arguments": ["$commit"] },
    { "predicate": "approved", "arguments": ["1.4.0", "release-manager"] }
  ],
  "then": {
    "predicate": "action_authorized",
    "arguments": ["$action"]
  }
}
```

Explicit negative evidence can derive `not action_authorized(action)`. If positive and negative authorization are both derivable, the result is `conflicted`, never authorized.

## Authorization certificate

`zerker.reason.authorization.v1` contains:

- request digest;
- mission ID and digest;
- action ID and digest;
- mapped authorization status;
- complete temporal reasoning result;
- independently checkable proof and disproof DAGs when present;
- deterministic, actionable issues.

Issues distinguish missing requirements, explicit denial, conflicting authorization, untrusted evidence, stale evidence, and supersession.

## Independent verification

`verify-authorization` reconstructs the effective program from the original request and then:

1. verifies request, mission, and action digests;
2. recomputes the entire reasoning result;
3. independently replays proof and disproof DAGs when present;
4. checks the four-state authorization mapping;
5. recomputes all authorization issues.

Recomputation is necessary for `insufficient_evidence`, because absence has no positive proof certificate. Changing a tool argument, effect, mission constraint, policy, premise, authority, timestamp, result status, or issue invalidates the certificate.

## Atomic verification for enforcement points

Gateways and signing adapters should not load the request and certificate from two mutable paths. Supply both values in one versioned bundle instead:

```json
{
  "schema": "zerker.reason.authorization-bundle.v1",
  "request": { "schema": "zerker.reason.action.v1" },
  "certificate": { "schema": "zerker.reason.authorization.v1" }
}
```

```bash
reason --format json verify-authorization-bundle bundle.json \
  --require-authorized

# The same contract can be delivered without temporary files.
cat bundle.json | reason --format json \
  verify-authorization-bundle - --require-authorized
```

Without `--require-authorized`, a semantically valid denial, conflict, or insufficient-evidence certificate exits successfully because the certificate verified. With the flag, verification still produces `status: "verified"`, but the process returns the authorization status exit code: 0 only for `authorized`, 2 for `insufficient_evidence`, 3 for `denied`, and 4 for `conflicted`. Verifier errors return 1.

Reason caps every JSON input, including standard input, at 64 MiB. It also rejects duplicate object members and fields outside the selected versioned schema at every typed depth; keys inside declared maps such as `action.arguments` and `mission.constraints` remain application-defined. Integrations should set a smaller deployment-specific limit and a subprocess timeout rather than relying on the CLI cap alone.

This bundle proves that the certificate matches the bundled request. An enforcement point must also reconstruct the concrete call it is about to execute and compare its tool and normalized arguments with `request.action`. A verified certificate must never authorize a different call.

## Component boundaries

- **ZMem** supplies promoted, governed premises.
- **Reason** derives authorization and independently verifies its certificate.
- **Gateway** compares the verified action with the exact application call before payment and forwarding.
- **Guard/Rakhshak** enforces destination-bound local network policy as defense in depth.
- **Treeship** records mission, action, program, result, proof, and enforcement commitments—including denials.

See [Integration profiles](INTEGRATION_PROFILES.md) for the exact adapter-owned fields and checks. Profile keys remain application-defined and are not universal Reason requirements.
