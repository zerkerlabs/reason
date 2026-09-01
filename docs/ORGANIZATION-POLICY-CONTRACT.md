# Organization policy bundle architecture contract

Status: implemented end to end for the portable Reason contract and Gateway's opt-in local tenant/agent pin seam. Reason provides lock, source verification, authorize-from-policy, and independent policy-authorization verification; Gateway provides exact request construction, bounded execution, enforcement ordering, and digest-only invocation evidence. Existing Reason 0.2 contracts and commands remain unchanged.

## Failure-first acceptance criteria

Implementation must be rejected, rather than made permissive, if any of these criteria cannot be met:

1. Every existing `zerker.reason.action.v1`, `zerker.reason.authorization.v1`, `zerker.reason.authorization-bundle.v1`, digest, verifier, status, and CLI behavior remains byte- and meaning-compatible with 0.2 fixtures.
2. A source manifest or locked bundle with a duplicate JSON member, unknown member, unsupported schema, invalid normalized path, duplicate path or file identity, symlink, non-regular file, changing file, or exceeded limit is rejected before a usable bundle is emitted.
3. Source inclusion records byte commitments only. It never becomes a fact, authority admission, proof that a model read a file, or proof that prose agrees with the reviewed typed policy.
4. A changed source byte, source metadata field, source order after canonical locking, or typed policy changes or invalidates the locked bundle commitment. Verification against changed source bytes fails.
5. Authorization never reads policy source paths. It consumes one bounded locked bundle plus boundary-owned context and an explicit evaluation time.
6. Reason, not an adapter, expands the policy template, creates the exact `action_authorized(action_id)` query, injects reserved action bindings, evaluates four-state truth, and maps the authorization status.
7. The authorizing boundary, not an untrusted caller or policy document, supplies the authenticated principal and concrete mission/action context. Gateway additionally derives tenant, routed agent, tool, and arguments from authenticated request state and the concrete MCP call.
8. Only exit 0 plus strict `authorized` output with exact returned bindings may continue. Missing policy, drift, unknown, denial, conflict, malformed input/output, mismatch, resource exhaustion, timeout, or subprocess failure cannot execute an action.
9. Source count and bytes, manifest/template/bundle/input/output bytes, rule rounds, and adapter runtime are bounded and covered by boundary-value and over-limit tests.
10. The new authorizer is separately opt-in. Disabling it leaves the existing caller-supplied authorization verifier available and unchanged; an error while it is enabled never falls back to an unverified mode.

These are failure-first criteria: tests should demonstrate each rejection before an authorized end-to-end fixture is accepted.

## Trust and ownership boundaries

### Human organization policy owner

A human-controlled review process owns two inputs:

- a manifest identifying policy source files; and
- a typed policy template whose facts, rules, ontology, and authority admissions have been reviewed.

The review process, signatures, repository permissions, and promotion workflow are outside Reason v1. A file being named `AGENTS.md`, `CLAUDE.md`, or `SKILL.md` gives it no special authority. The manifest is an inventory of source commitments, not a Markdown compiler.

### Reason

Reason owns:

- strict parsing and semantic validation of the new contract family;
- safe, bounded source resolution for lock and source verification operations;
- deterministic source and bundle commitments;
- policy-template expansion into `zerker.reason.program.v2`;
- construction and evaluation of the existing exact action request;
- four-state to authorization-status mapping; and
- independently reproducible authorization output.

Reason does not authenticate users, decide which bundle belongs to a deployed agent, infer facts from prose, access a network, execute a tool, or consume a replay token.

### Authorizing boundary

The boundary owns current request truth. It supplies the mission, principal, exact action, and explicit time. It must reject caller attempts to override boundary-owned values.

For Gateway, the existing `zerker.gateway.reason-mcp-call.v1` profile continues to own these bindings:

- `mission.principal`: authenticated principal;
- `mission.constraints["gateway.tenant_id"]`: authenticated tenant;
- `mission.constraints["gateway.agent_id"]`: routed agent;
- `action.tool`: concrete MCP `tools/call` name; and
- `action.arguments`: concrete canonical argument object.

Gateway owns those profile keys, bundle-to-tenant/agent configuration, payment ordering, replay lifecycle, invocation persistence, and forwarding. They are not universal Reason semantics.

### Authority statement

Source prose has no symbolic authority. Only authority classes and per-predicate admissions in the reviewed typed policy govern facts. The operator who pins a reviewed bundle to an agent is responsible for that deployment choice. This separation is deliberate and removes any ambiguous policy-authority transfer from Markdown to Reason.

## Additive contract family

The first slice adds a separate family; it does not add members to or reinterpret any 0.2 object:

| Identifier | Purpose |
|---|---|
| `zerker.reason.policy-source-manifest.v1` | Human-reviewed inventory used only while locking or verifying sources. |
| `zerker.reason.policy-template.v1` | Reviewed `program.v2` material without per-request time or query. |
| `zerker.reason.policy-bundle.v1` | Deterministic source commitments plus the reviewed typed template. |
| `zerker.reason.policy-source-verification.v1` | Successful current-source comparison with bundle digest and verified count. |
| `zerker.reason.policy-authorization-input.v1` | One bounded bundle and boundary-owned mission/action context. |
| `zerker.reason.policy-authorization.v1` | Bundle commitment plus an atomic existing request/certificate pair and strict summary. |
| `zerker.reason.policy-authorization-verification-input.v1` | One bounded bundle/result pair for independent policy-expansion verification. |

Capability discovery will list these identifiers and their commands only when implemented. Consumers must require exact identifiers instead of inferring support from a binary version.

## Human source manifest

The v1 manifest has no ambient root and no globs:

```json
{
  "schema": "zerker.reason.policy-source-manifest.v1",
  "sources": [
    {"path": "AGENTS.md", "kind": "instruction", "scope": "repository"},
    {"path": "CLAUDE.md", "kind": "instruction", "scope": "repository"},
    {"path": ".agents/skills/release/SKILL.md", "kind": "skill", "scope": "organization"}
  ]
}
```

`kind` is one of `instruction`, `skill`, or `context`. `scope` is one of `organization`, `repository`, or `agent`. They are mandatory, digest-bound review metadata. They do not select files, grant authority, bind a deployed agent, alter template expansion, or prove comprehension. There is no mandatory instruction filename.

The operator passes the root separately to lock or source-verification operations. The root is an access boundary and is intentionally absent from the portable bundle commitment. Moving an unchanged tree does not change its bundle digest.

The manifest is strict JSON. Duplicate members, unknown members, an empty source list, duplicate normalized paths, and unsupported enum values fail. Source order is not semantic: lock output is sorted by normalized path before digesting. Reordering only the input manifest therefore produces the same bundle; changing digest-bound entry metadata does not.

All contracts in this additive policy family also require canonical JSON number tokens. A token is accepted only when it already equals Reason's deterministic `serde_json::Number` rendering. For example, `0`, `0.0`, `-0.0`, `1.5`, and `9007199254740993` are accepted, while `-0`, `1e0`, `1.00`, and a floating-point spelling that would round to a different decimal are rejected. The rule applies recursively, including application-defined constraint, argument, and effect values. It prevents Reason from authorizing or committing a numeric value different from the boundary's input. JSON Schema operates on parsed numeric values and cannot express this lexical rule; Reason's bounded parser is authoritative. Existing non-policy v0.2 parsers and digests retain their prior number behavior.

## Portable source path profile

A v1 source path is a portable relative UTF-8 path, not a host-native arbitrary path:

- it is non-empty Unicode normalized to NFC;
- `/` is the only separator;
- it has no leading or trailing `/`, empty segment, `.` segment, or `..` segment;
- it contains no backslash, NUL, ASCII control character, Unicode bidi-control character, drive prefix, or URI-like absolute prefix;
- dot-prefixed ordinary segments such as `.agents` are allowed; and
- identity is the exact, case-sensitive NFC code-point sequence.

Non-UTF-8 filesystem names cannot be manifested in v1. A decomposed Unicode spelling, a host path that aliases another declared spelling through case folding or Unicode folding, or two paths resolving to the same file identity is rejected rather than normalized silently.

### Resolution algorithm

Lock and source verification must use the same resolver:

1. Open the operator-selected root as a directory without following a symlink. Reject a symlink, non-directory, or unsupported no-follow platform.
2. Parse and validate all portable paths and reject duplicate normalized strings before file access.
3. Traverse every component relative to the open root using no-follow, directory-relative operations. Reject a symlink in any component, mount/platform alias that escapes the opened root, and a final object that is not a regular file.
4. Record stable file identity from the opened handle and reject duplicate identities, including hard links and case-folding aliases.
5. Read only from the opened handle with per-file and aggregate byte counters. Hash the exact bytes; do not decode Markdown or normalize line endings.
6. Compare handle identity and metadata before and after reading, and confirm the manifested path still names that same identity. Reject replacement, truncation, growth, or detected concurrent mutation. Implementations should read and hash a second time from the same handle and require identical length and digest so same-size concurrent rewrites also fail closed.
7. Close all handles before publishing the bundle. Any error publishes no output artifact.

A directory controlled by a hostile local administrator is outside the process-isolation guarantee; such an administrator can also replace the Reason binary. The algorithm is intended to prevent accidental drift and untrusted repository content from exploiting traversal, links, aliases, or ordinary file races. It must not be weakened to lexical `canonicalize` followed by an unchecked reopen.

## Reviewed typed policy template

The template reuses the existing typed `Program` components but deliberately has neither a query nor an evaluation time:

```json
{
  "schema": "zerker.reason.policy-template.v1",
  "ontology": {"id": "organization_policy", "version": "1", "predicates": {}},
  "authority": {"classes": [], "default_admit": [], "predicate_admit": {}},
  "facts": [],
  "rules": []
}
```

`ontology`, `authority`, `facts`, and `rules` have exactly their existing `program.v2` wire meanings. V2 fact timestamps remain mandatory. The template may derive `action_authorized($action)` or its explicit negation, but existing action validation still forbids it from declaring `system-bound`, injecting reserved facts, declaring or admitting reserved binding predicates, or deriving reserved bindings other than `action_authorized`.

The omission of `query` is a security boundary, not shorthand. A policy author cannot preselect another action ID. The omission of `evaluation_time` prevents a bundle author from freezing or choosing the request-time evidence snapshot. Reason supplies both fields during authorization.

Locking validates the strict template shape, timestamps, ontology, authority policy, facts, rules, reserved action namespace, and all checks that do not depend on a concrete action. Authorization performs the complete existing `validate_action_request` path after expansion.

## Deterministic locked policy bundle

A locked bundle contains commitments, not private source contents:

```json
{
  "schema": "zerker.reason.policy-bundle.v1",
  "bundle_digest": "sha256:...",
  "sources": [
    {
      "path": "AGENTS.md",
      "kind": "instruction",
      "scope": "repository",
      "size_bytes": 1234,
      "digest": "sha256:..."
    }
  ],
  "policy": {"schema": "zerker.reason.policy-template.v1"}
}
```

Each source digest is lowercase SHA-256 over its exact file bytes. Entries are sorted by normalized path. Sizes are unsigned byte counts. Source contents and absolute host paths are excluded.

`bundle_digest` is lowercase SHA-256 over Reason's deterministic compact typed JSON serialization of this commitment payload:

```json
{
  "schema": "zerker.reason.policy-bundle-commitment.v1",
  "sources": ["the complete sorted locked source entries"],
  "policy": "the complete typed policy-template value"
}
```

The digest field itself is not in the payload. Struct member order is the order above; typed maps use lexicographically sorted keys; arrays retain their declared order except the source list, which lock sorts. Reason is the authoritative digest implementation and will publish fixtures. As with current Reason digests, consumers carry and compare the value but must not claim cross-language canonical JSON portability until a separate canonical-encoding contract ships.

Strict parsing and semantic verification recompute `bundle_digest`. A source-byte change makes source verification fail; relocking changed bytes yields a different digest. A typed-policy or digest-bound metadata change also yields a different digest. The existing locked artifact remains an immutable commitment to the old bytes—it is not silently rewritten when ambient files change.

## Lock and verify workflows

The CLI/library operations are:

```text
reason policy lock --root ROOT --manifest MANIFEST --policy TEMPLATE --output BUNDLE
reason policy verify-sources --root ROOT BUNDLE
reason --format json policy authorize INPUT
reason --format json policy verify-authorization VERIFICATION_INPUT --require-authorized
```

`INPUT` and `VERIFICATION_INPUT` may be `-` for bounded stdin. The lock inputs are each read under their contract-specific bound before strict parsing. Authorization output is compact deterministic JSON under the 2 MiB output ceiling.

`lock` stages a complete bundle, verifies it, syncs it, and publishes it with create-new/atomic output behavior. It does not partially replace an existing bundle. `verify-sources` strictly loads one bundle, recomputes its commitment, resolves the bundle's locked paths through the same safe resolver, and compares exact path metadata, size, and byte digest. It returns success only when all sources match.

Verification never updates a bundle. An operator must review and relock changed sources, observe the new digest, and deliberately update a deployment pin.

## Exact authorization construction

The authorizer consumes one strict, bounded value. It does not accept a source root or source path:

```json
{
  "schema": "zerker.reason.policy-authorization-input.v1",
  "policy_bundle": {"schema": "zerker.reason.policy-bundle.v1"},
  "evaluation_time": "2026-08-29T12:00:00Z",
  "mission": {
    "id": "mission_agent_support",
    "principal": "user:123",
    "instruction_digest": "sha256:...",
    "issued_at": "2026-08-01T00:00:00Z",
    "valid_until": "2026-09-01T00:00:00Z",
    "constraints": {
      "gateway.tenant_id": "tenant_123",
      "gateway.agent_id": "agent_456"
    }
  },
  "action": {
    "id": "invocation_789",
    "tool": "lookup_ticket",
    "proposed_at": "2026-08-29T12:00:00Z",
    "arguments": {"ticket_id": "T-42"},
    "effects": []
  }
}
```

The mission and action objects reuse the exact `zerker.reason.action.v1` shapes. Their provenance is boundary-owned; schema validity is not proof of authentication. Time is canonical UTC RFC 3339 seconds and never read from Reason's ambient clock.

Reason performs this deterministic expansion:

1. Strictly parse and verify the locked bundle and input.
2. Create a `zerker.reason.program.v2` from the template's ontology, authority, facts, and rules.
3. Set `program.evaluation_time` to the input's explicit `evaluation_time`.
4. Set `program.query` to positive `action_authorized(input.action.id)`; the input has no query field.
5. Create an otherwise ordinary `zerker.reason.action.v1` from the exact input mission, exact input action, and expanded program.
6. Run the existing action validator and authorizer unchanged. This injects existing reserved mission/action facts and preserves current typed canonical argument projection, temporal checks, status mapping, certificates, and digests.
7. Package the exact generated request and certificate atomically.

An action proposed after evaluation time does not gain authorization: existing temporal eligibility withholds its future system-bound facts. Boundaries should normally set `proposed_at` to their captured request time and pass a deliberate evaluation snapshot at or after it. Reason never substitutes a current time.

## Authorization output for Gateway and independent verification

Machine output is one strict object:

```json
{
  "schema": "zerker.reason.policy-authorization.v1",
  "policy_bundle_digest": "sha256:...",
  "authorization_status": "authorized",
  "request_digest": "sha256:...",
  "reasoning_result_digest": "sha256:...",
  "authorization": {
    "schema": "zerker.reason.authorization-bundle.v1",
    "request": {"schema": "zerker.reason.action.v1"},
    "certificate": {"schema": "zerker.reason.authorization.v1"}
  }
}
```

The summary is generated by Reason and must exactly match the nested certificate and recomputed reasoning result. It exists so a bounded adapter does not duplicate Reason's status mapping or digest procedure. The nested existing bundle remains consumable by the unchanged `verify-authorization-bundle` operation.

The `zerker.reason.policy-authorization-verification-input.v1` verifier input atomically contains the locked policy bundle and this output. Reason recomputes the bundle commitment, repeats template expansion from `authorization.request`'s mission/action and its policy evaluation time, requires the generated action request to match by deterministic typed digest, invokes existing authorization verification, and checks every summary field. It does not need source files. Optional source verification is a separate operator operation.

Gateway accepts server-created authorization only when all of the following hold:

- subprocess exit is 0;
- stdout is exactly one bounded `zerker.reason.policy-authorization.v1` JSON value with no duplicate or unknown members;
- status is `authorized` and all digests are valid;
- `policy_bundle_digest` equals the digest pinned for the authenticated tenant and routed agent;
- returned principal, tenant constraint, agent constraint, action ID, tool, canonical arguments, and any Gateway-owned effects match the concrete request again; and
- authorization occurs before payment, invocation creation/reservation, dispatch, or forwarding.

Unknown/insufficient evidence exits 2, denied exits 3, conflicted exits 4, and malformed input, unsupported contract, failed verification, or engine/resource failure exits 1, preserving existing meaningful status codes. An adapter treats every nonzero code as no authorization. A zero exit with malformed, oversized, mismatched, or non-authorized output also fails closed.

## Pinning, drift, and hot-path behavior

Gateway configuration must map an authenticated tenant plus routed agent to one expected bundle digest and one already loaded, strictly verified bundle value. A single implicit global policy is not the target architecture. A local configuration file may be the first implementation seam, but its records must be per-agent and tenant-qualified and must state the expected digest.

Bundle/source paths are resolved while loading configuration or running operator verification, never per tool call. The request hot path uses the in-memory bounded bundle value and passes it with context over stdin to a directly executed Reason binary. Gateway uses fixed argv, no shell, a cleared environment, bounded stdout/stderr, and a timeout.

Changing ambient source files does not mutate an in-memory pin. `policy verify-sources` detects that the old bundle no longer matches; relocking creates a different digest; and Gateway uses it only after an explicit configuration update/reload. A configured bundle that cannot be loaded, parsed, digest-verified, or matched to its expected pin prevents that binding from authorizing.

## Resource limits

V1 implementations use fixed discoverable ceilings and test exact-limit and one-over-limit behavior. Initial ceilings are:

| Resource | Ceiling |
|---|---:|
| source entries | 256 |
| one portable source path | 4 KiB UTF-8 |
| one source file | 1 MiB |
| aggregate source bytes per lock/verification | 16 MiB |
| source manifest JSON | 256 KiB |
| policy template JSON | 1 MiB |
| locked bundle JSON | 2 MiB |
| policy-authorization input | 2 MiB |
| policy-authorization stdout | 2 MiB |
| policy-authorization verification input | 4 MiB |
| Reason rule rounds | existing 1,024 |
| Gateway Reason subprocess runtime | existing default 2 seconds |

The implementation may choose smaller deployment limits but not silently larger contract limits. Gateway may expose operator configuration only within compiled hard maxima. Stdin, stdout, and stderr are independently bounded. Overflow, timeout, non-convergence, allocation/parse failure, or an inability to enforce a bound fails closed.

These limits complement, and do not raise or change, the existing 64 MiB generic Reason CLI input ceiling or existing 0.2 behavior.

## Threat model

| Threat | Required behavior |
|---|---|
| `../`, absolute, drive, separator, or Unicode path confusion | Reject under the portable path profile before filesystem access. |
| Symlink in root, directory component, or final file | Reject with descriptor-relative no-follow traversal. |
| Duplicate spelling, case/Unicode alias, or hard link | Reject duplicate normalized paths and duplicate opened file identities. |
| Source replacement or mutation while hashing | Hash opened handles with bounds; compare identity/metadata/path and repeated reads; publish nothing on change. |
| Oversized or special file blocks/crashes lock | Require regular files and enforce per-file/aggregate read bounds. |
| Malicious manifest/template JSON | Reject duplicate members recursively, unknown members, trailing values, invalid UTF-8, and unsupported schemas. |
| Markdown prompt injection | No parser or model consumes source prose in the authorization path; bytes create commitments only. |
| Policy injects request facts or query | Template has no query/time and existing reserved namespace checks run after Reason-owned expansion. |
| Caller spoofs principal, tenant, agent, tool, or arguments | Boundary reconstructs them from authenticated context/concrete call and compares returned request bindings. |
| Ambient policy changes after deployment | Loaded bundle is immutable and digest-pinned; source drift requires separate verification and deliberate relock/reload. |
| Unknown, explicit denial, or conflicting evidence | Reason maps to non-authorized status and nonzero exit; Gateway does not forward. |
| Reason hangs, exits, floods output, or emits malformed JSON | Direct bounded subprocess, timeout, cleared environment, strict one-value output, fail closed. |
| Streaming bypass | Gateway rejects Reason-enforced MCP streaming; only a fully buffered transactional exact call is eligible. |
| Replay | Gateway applies lifecycle-specific replay rules; server-created request IDs are unique and invocation evidence records the decision. Caller-supplied one-shot behavior is not silently reused. |
| Bundle disclosure | Bundle contains policy and source metadata/digests, not source contents; access control is still required because policy itself may be sensitive. |
| Compromised local operator or Reason binary | Outside this slice; deployment integrity and signatures are separate controls. |

## Compatibility and independent evidence

The generated action request is an ordinary `zerker.reason.action.v1`; its certificate is an ordinary `zerker.reason.authorization.v1`; and the nested pair is an ordinary `zerker.reason.authorization-bundle.v1`. Existing independent verification remains authoritative for those values. No field is added to them, no digest procedure changes, and no old command is repurposed.

Invocation evidence stores at least:

- pinned policy-bundle digest;
- generated Reason request digest;
- reasoning-result digest;
- authorization status; and
- existing tenant, agent, tool, and invocation identity.

Private source contents need not be stored. Reconstructing the complete decision requires retaining the exact locked bundle and policy-authorization artifact under appropriate access controls.

## Rollback and feature disable

The server-side policy authorizer is a separate opt-in mode from the existing caller-supplied verifier:

1. With only the existing Reason verifier configured, current pre-authorized envelope behavior is unchanged.
2. Enabling server authorization requires valid per-tenant/per-agent bundle pins at startup or reload. A configured invalid binding fails closed; it does not fall through to caller-supplied or unenforced forwarding.
3. Rollback disables only the new server-authorizer configuration and removes its agent bindings. The existing verifier path can remain enabled.
4. Deployments that deliberately disable both features return to their pre-campaign legacy behavior; this is an explicit operator choice, never an error fallback.
5. A binary downgrade is safe only after removing unsupported new bindings/artifacts from active configuration. Existing 0.2 envelopes continue to verify with the old path.

## Rejected alternatives

- **Compile Markdown with an LLM.** Rejected because source inclusion cannot establish symbolic truth, faithful comprehension, or authority.
- **Add source fields to `action.v1` or change its query semantics.** Rejected because it breaks stable digests and downstream verifiers.
- **Let Gateway expand policy rules or map truth statuses.** Rejected because it duplicates Reason semantics and creates version skew.
- **Read `AGENTS.md` or another conventional filename on every call.** Rejected because filenames are not authority and ambient file reads create drift and traversal risk.
- **Follow symlinks after checking canonical containment.** Rejected because check/open races and filesystem aliases remain.
- **Embed source contents in every authorization.** Rejected because it expands the hot-path attack surface, output size, and private-data exposure without improving symbolic authority.
- **One global Gateway policy path.** Rejected as a final architecture because it cannot express an auditable per-tenant/per-agent pin.
- **Silently fall back when the new authorizer fails.** Rejected because configuration, timeout, drift, and unsupported contracts must fail closed.
- **Reuse caller-supplied one-shot replay semantics unchanged.** Rejected because the two issuance models have different retry and payment behavior; Gateway policy issuance is request-local while caller-supplied bearer authorization remains one-shot.

## Implemented operator lifecycle

1. Review a source manifest and typed policy template; source prose remains a byte commitment only.
2. Run `reason policy lock`, review and record the emitted bundle digest, and retain the immutable bundle.
3. Run `reason policy verify-sources` before promotion and whenever checking the reviewed source tree for drift. Changed sources require review, a new bundle, and a deliberate pin update.
4. Bind the expected bundle digest to one tenant and agent in Gateway's local pin configuration. Gateway strictly loads and structurally validates bundle bytes at startup; Reason recomputes the authoritative bundle commitment during authorization, which performs no source or bundle file reads.
5. Send ordinary fully buffered MCP `tools/call` requests for the bound agent. Gateway derives request truth, Reason expands and evaluates the policy, and only strict authorized exact-match output proceeds.
6. Audit the invocation's policy-bundle, request, and reasoning-result digests. Retain the complete bundle and policy-authorization artifact separately when full offline reconstruction is required.
7. Roll back the opt-in server authorizer by removing `ZERKER_REASON_POLICY_PINS` and restarting Gateway while leaving `ZERKER_REASON_BINARY` configured for the existing caller-supplied verifier.

Gateway's concrete configuration, limits, replay lifecycle, and rollback runbook are documented in `gateway/REASON_POLICY.md` in the Gateway repository.
