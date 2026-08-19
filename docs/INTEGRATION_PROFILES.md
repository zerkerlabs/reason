# Integration profiles

Reason owns deterministic exact-action authorization. Gateway, Rakhshak, Treeship, and ZMem own the checks that depend on authenticated callers, live processes, signing keys, or governed memory state.

Profile identifiers and keys below belong to those adapters. They are examples of values carried inside the application-defined `mission.constraints` and `action.arguments` maps; they are **not universal Reason requirements** and are not Reason capability identifiers. A core `zerker.reason.action.v1` request can omit every profile-specific key.

Reason still digest-binds every supplied constraint and argument. Adding, removing, or changing one invalidates a certificate issued for the old request, even when the Reason policy does not project that field into a rule.

## Reason core: exact-action authorization

The portable core contract is:

1. construct one `zerker.reason.action.v1` request with an explicit evaluation time;
2. authorize it and retain the resulting `zerker.reason.authorization.v1` certificate;
3. transport both values in one `zerker.reason.authorization-bundle.v1` object;
4. at the enforcement boundary, run:

   ```bash
   reason --format json verify-authorization-bundle - --require-authorized
   ```

5. require exit code 0 and an exact `verified` plus `authorized` verification result;
6. compare the concrete action about to run with the verified `request.action`.

Reason validates the typed request, recomputes digests and reasoning, independently replays proofs, and maps all four authorization outcomes. It does not authenticate a caller, inspect a live process, verify a Treeship key, query ZMem, execute a tool, or consume a replay token.

## Gateway: authenticated MCP call

Gateway's downstream envelope is `zerker.gateway.reason-mcp-call.v1`. Its Reason request uses:

- `mission.principal` for the authenticated user;
- `mission.constraints["gateway.tenant_id"]` for the authenticated tenant;
- `mission.constraints["gateway.agent_id"]` for the routed agent;
- `action.tool` and `action.arguments` for the exact MCP `tools/call` name and normalized argument object.

Reason commits those values to the request and certificate. It does not know whether they came from authentication. Gateway must derive principal, tenant, and agent from its request context, compare all three after Reason verification, reject duplicate or malformed JSON, compare the actual MCP call with the certified action, and block before payment or forwarding on every mismatch or verifier failure.

The `gateway.tenant_id` and `gateway.agent_id` keys are Gateway-owned. Other Reason clients do not need them.

## Rakhshak: process-bound, destination-bound grant

Rakhshak's downstream claim is `zerker.rakhshak.network-grant.v1`, carried by action tool `rakhshak.network.connect`. This profile requires the exact argument set:

- `schema`, `nonce`, and `session_id`;
- `transport`, `host`, `remote_ip`, and `port`;
- `not_before` and `expires_at`.

The action has one `network_connect` effect whose resource names the exact transport, remote IP, and port. Reason can prove and bind that action. Rakhshak must additionally:

- resolve the live process into the local session identity;
- require canonical destination values and TCP for this profile version;
- enforce `not_before`, `expires_at`, mission expiry, and a maximum five-minute lifetime at its boundary;
- store and consume the exact session/destination grant once in a protected replay ledger;
- preserve an existing hard deny rather than using a Reason grant to override it.

Process identity, clock freshness, canonical host/IP checks, and one-shot consumption are Rakhshak semantics, not Reason core semantics. Clients that do not enforce network destinations do not need this claim shape.

## Treeship: atomic verify then sign

A conforming Treeship version with the dedicated adapter creates receipt kind `reason.authorization.v1`. Check adapter availability in the installed Treeship version before using this interface:

```bash
treeship attest reason-authorization \
  --bundle-file authorization-bundle.json \
  --reason-bin /opt/zerker/bin/reason
```

The dedicated adapter reads one bounded bundle once, sends those exact bytes to Reason with `--require-authorized`, validates the strict success output and certificate shape, and only then opens key and artifact stores. The receipt commits to the exact bundle bytes and carries Reason's request and reasoning-result digests.

A generic `treeship attest receipt` call after a separate verifier run is not this atomic profile: it does not itself require Reason success, and separately opened paths can change between verification and signing.

Reason proves authorization semantics. Treeship proves which key signed the receipt, the byte commitment, and artifact-chain placement. A Treeship signature cannot make an invalid Reason certificate valid, and the `system://zerker-reason` producer label is not an identity proof without a trusted key binding. The original private bundle must remain available for semantic replay.

## ZMem: governed premise export

ZMem exports `zerker.memory.reason-premises.v1`. Its deterministically ordered `facts` array can populate the fact set of a Reason `zerker.reason.program.v2` policy after the consumer runs ZMem's current-state verifier.

ZMem owns memory lifecycle and provenance. Its exporter admits active policy memories with the `reason:premise:v1` label, requires a verified write-receipt chain, and requires an explicit governed promotion for agent, tool, document, or import sources. It reports withheld memories and fails closed on malformed, duplicate, stale, revoked, or receipt-divergent input.

Reason does not consume ZMem provenance as proof of a predicate. The Reason policy must still declare the ontology, authority classes, per-predicate admission policy, evaluation time, and query, then validate every exported fact. ZMem authority labels must be mapped deliberately rather than copied into a universal ranking. LLM-proposed memories remain quarantined until governed promotion.

## Common fail-closed rules

Every authorization or signing adapter should:

- pin a deliberate Reason binary version and supported core contract set;
- pass one bounded atomic bundle over stdin without a shell;
- clear unrelated environment values and impose tighter input, output, and timeout limits than Reason's CLI ceiling;
- accept only the exact versioned success output and exit code 0;
- treat malformed input, unsupported schemas, unknown fields, duplicate members, denial, conflict, insufficient evidence, timeout, and verifier failure as no authorization.

Premise consumers should verify the ZMem artifact against current governed state before extracting facts. Every profile must record adapter-owned checks separately instead of claiming Reason proved them.

These profiles add boundary checks without changing `zerker.reason.action.v1`, authorization status mapping, digest rules, proof semantics, or v0.1 client behavior.
