# Organization policy layer

## Thesis

Companies need one governed policy layer for every agent and tool, independent of model vendor.

Neural models propose goals, plans, and actions. Zerker Reason evaluates an exact proposed action against typed facts and rules. Zerker Gateway verifies the resulting authorization against the concrete MCP call and blocks a mismatch, denial, conflict, replay, or verifier failure before forwarding.

This is the useful neurosymbolic boundary:

```text
neural proposal
  -> governed evidence and explicit rules
  -> deterministic authorization
  -> exact-call enforcement
```

## Markdown is a source, not a proof

Files such as `AGENTS.md`, `CLAUDE.md`, `.agents/skills/`, security policies, and release procedures are useful human interfaces. They are not automatically authoritative facts or executable symbolic rules.

Reason v0.2 can bind an instruction digest into a mission and evaluate a reviewed `zerker.reason.program.v2` policy. It does not currently:

- host organization Markdown files;
- resolve competing instruction-file conventions;
- compile natural-language policy into Reason programs;
- prove that a model read or understood a file;
- intercept every model request;
- authorize calls that do not pass through an enforcement integration.

A future policy service can resolve source files into a versioned bundle, propose typed rules, require review, and bind the approved bundle digest to each mission. The symbolic layer must enforce the reviewed typed contract, not trust an LLM's interpretation of prose.

## Do not invent another instruction-file standard

The product should accept the files teams already use and produce one organization policy manifest.

```text
AGENTS.md
CLAUDE.md
.agents/skills/**
security-policy.md
release-policy.md
        |
        v
reviewed organization policy bundle
- source file digests
- precedence and scope
- typed facts and rules
- accepted authority classes
- evaluation time and validity
- bundle digest
```

Adapters can continue presenting tool-specific context to Claude Code, Codex, Cursor, or another agent. Enforcement uses the same approved bundle digest and Reason program across those clients.

This addresses split-brain instructions without claiming that every client reads the same filenames. Zerker resolves the sources once and checks actions at the boundary every client must cross.

## Current enforcement path

Gateway's current Reason integration is narrower and concrete:

1. An operator configures `ZERKER_REASON_BINARY`.
2. An MCP `tools/call` reaches the transactional proxy in `zerker.gateway.reason-mcp-call.v1`.
3. Gateway sends the atomic authorization bundle to Reason.
4. Reason independently verifies that the certificate is valid and authorized.
5. Gateway binds the verified mission to the authenticated principal, tenant, and agent.
6. Gateway compares the certified tool and canonical arguments with the actual MCP call.
7. Gateway rejects malformed input, missing authorization, mismatch, insufficient evidence, denial, conflict, verifier failure, or replay.
8. Only the inner verified call can proceed to policy, payment, invocation creation, and forwarding.

Reason-enabled MCP `tools/call` is transactional today. The streaming endpoint rejects it rather than allowing a bypass.

## Target hosted workflow

The hosted product can make this usable for companies without weakening the contract.

### 1. Connect policy sources

- Git repositories
- approved organization handbooks
- security and data-classification policies
- `AGENTS.md`, `CLAUDE.md`, and skill directories
- identity, ticketing, CI, artifact, and approval systems

### 2. Resolve one policy bundle

- explicit source precedence
- repository and path scopes
- source digests
- reviewed typed rules
- authority requirements per predicate
- validity intervals and supersession
- signed or otherwise governed promotion

An LLM may propose a compilation. A human or governed workflow promotes it. Reason never treats the proposal as authoritative merely because a model produced it.

### 3. Normalize the proposed action

Each integration maps a concrete action into:

- principal, tenant, and agent;
- mission and instruction-bundle digest;
- exact tool name;
- canonical arguments;
- declared effects;
- evaluation time;
- relevant governed evidence.

### 4. Derive one of four outcomes

- `authorized`: required support is proved;
- `insufficient_evidence`: a required premise is missing or withheld;
- `denied`: explicit negative support exists;
- `conflicted`: trusted support exists on both sides.

Only `authorized` is eligible for enforcement.

### 5. Enforce and explain

Gateway compares the authorization with the concrete call. Console shows the decision, matched bundle, admitted and withheld evidence, missing requirement, expiration, conflict, and invocation record.

## Coding-agent use case

The Shopify example is an instruction portability problem and an enforcement problem.

Instruction portability asks which files a coding agent loads. Zerker should resolve the organization's accepted sources rather than force every team to duplicate policy into a vendor-specific filename.

Enforcement asks what the coding agent may do. A policy bundle can require, for example:

- the repository's current instruction digest;
- allowed tools for the repository and environment;
- required tests for the exact commit;
- code-owner approval for protected paths;
- a current security review;
- deployment approval from an accepted authority;
- destination and effect constraints;
- a mission that has not expired or been superseded.

Zerker cannot prove that a model semantically understood prose. It can prove which policy bundle the mission commits to and block an exact tool action that lacks the required authorization.

## Company use cases

### Software delivery

Authorize an exact commit, artifact, environment, and deployment tool only when tests, review, artifact identity, and approval agree and remain current.

### MCP and tool access

Authorize a tool name and canonical argument object for an authenticated principal, tenant, and agent. A certificate for `read_customer` cannot authorize `delete_customer` or changed arguments.

### Data handling

Require data classification, purpose, region, destination, retention, and consent evidence before an agent exports or transforms protected data.

### Financial operations

Require amount limits, budget, account, counterparty, approval, and duplicate-payment checks before a refund, purchase, transfer, or price override.

### Customer operations

Require contract state, account ownership, consent, case status, and approval before changing a subscription, issuing a credit, or modifying an account.

### Infrastructure and incident response

Require incident severity, ticket state, affected resource, command scope, approval, and expiration before isolation, key rotation, failover, or destructive remediation.

### Delegated and multi-agent work

Bind a sub-agent action to the parent mission, delegated scope, exact tool, resource, effect, and expiration. A broad planning mission does not become broad execution authority.

### Regulated workflows

Require licensed authority, jurisdiction, current policy, approved source data, and review before an agent performs a regulated action. Reason can express the decision contract; each domain still needs a reviewed domain pack and trustworthy evidence adapters.

## Product work that creates the most value

1. **Policy registry:** host versioned organization policy bundles and source-file digests.
2. **Source resolver:** support existing instruction conventions without creating another mandatory filename.
3. **Reviewed compiler:** propose typed rules from Markdown, show the semantic diff, and require governed promotion.
4. **Evidence connectors:** CI, GitHub, identity, ticketing, approval, data catalog, and finance systems.
5. **Action adapters:** normalize high-value MCP tools and API actions into exact Reason requests.
6. **Console explanations:** show why an action was authorized or blocked and what evidence would change the result.
7. **Bundle rollout:** stage, test, pin, supersede, and roll back policy bundles by repository, agent, team, and environment.
8. **Conformance checks:** prove every supported agent client receives the intended source bundle while keeping enforcement independent of the client's prompt behavior.

## Messaging boundary

Safe current claim:

> Reason checks an exact agent action against governed facts and explicit rules. Gateway can independently verify that authorization, bind it to the authenticated principal, tenant, and agent, and forward only the matching MCP tool call.

Safe product-direction claim:

> Zerker is building an organization policy layer that resolves the instruction files teams already use into reviewed, versioned policy bundles shared across agent clients.

Claims to avoid today:

- every model call already passes through Reason;
- Reason hosts or interprets Markdown policies;
- Reason proves a model read or followed `AGENTS.md`;
- all Gateway traffic is Reason-authorized;
- natural-language policy is automatically safe to enforce;
- every listed company use case ships as a finished domain pack.
