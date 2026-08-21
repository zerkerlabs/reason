# Release safety

The release-safety domain pack turns four common release signals into an exact-action authorization request:

- tests for the target commit;
- security review for the target commit;
- a built artifact whose digest matches the proposed deployment;
- human approval for the target version, commit, artifact, environment, and deployment tool.

It compiles this product-level input into the generic `zerker.reason.action.v1` contract. The generated request still uses the same deterministic Reason engine and independent verifier.

## Start in two commands

```bash
reason release init release.json \
  --evaluation-time 2026-08-18T10:00:00Z
reason release authorize release.json \
  --request-out action-request.json \
  --certificate-out authorization.json \
  --bundle-out authorization-bundle.json
```

Then independently verify the exact request and certificate:

```bash
reason --format json verify-authorization-bundle \
  authorization-bundle.json --require-authorized
```

Only `authorized` exits `0`. Missing or stale evidence exits `2`, explicit failure or denial exits `3`, conflict exits `4`, and malformed or unverifiable material exits `1`.

`release init` requires an explicit evaluation time and uses it for the generated snapshot; it never reads the wall clock. The starter contains no tests, reviews, artifacts, or approvals, so running it unchanged returns `insufficient_evidence`. It refuses to overwrite an existing file unless `--force` is provided. `release authorize` stages every requested output before publishing any of them and refuses duplicate or existing output paths, preventing one artifact from silently replacing another.

## Input contract

The starter uses `zerker.reason.release-authorization.v1` and requires explicit time. Reason never reads the wall clock into authorization material.

```json
{
  "schema": "zerker.reason.release-authorization.v1",
  "evaluation_time": "2026-08-18T10:00:00Z",
  "mission": {
    "id": "mission_release_150",
    "principal": "user:release-owner",
    "instruction_digest": "sha256:...",
    "issued_at": "2026-08-18T08:00:00Z",
    "valid_until": "2026-08-18T18:00:00Z"
  },
  "release": {
    "action_id": "action_deploy_150",
    "tool": "deploy_release",
    "version": "1.5.0",
    "commit": "commit_def",
    "environment": "production",
    "artifact_digest": "sha256:...",
    "required_approver": "release-manager",
    "proposed_at": "2026-08-18T10:00:00Z"
  },
  "evidence": {
    "tests": [{ "commit": "commit_def", "status": "passed", "authority": "tool-reported" }],
    "security_reviews": [{ "commit": "commit_def", "status": "passed", "authority": "human-authorized" }],
    "artifacts": [{ "commit": "commit_def", "digest": "sha256:...", "authority": "tool-reported" }],
    "approvals": [{ "version": "1.5.0", "commit": "commit_def", "environment": "production", "artifact_digest": "sha256:...", "tool": "deploy_release", "approver": "release-manager", "status": "approved", "authority": "human-authorized" }]
  }
}
```

The abbreviated evidence above omits required IDs and timestamps. Use the generated file or [`examples/release-authorization.json`](../examples/release-authorization.json) as the complete contract.

## Fail-closed behavior

| Evidence state | Result |
|---|---|
| All four signals match the exact release | `authorized` |
| Required evidence is absent, stale, untrusted, or for another commit | `insufficient_evidence` |
| Tests fail, security review fails, or approval is denied | `denied` |
| Positive and negative governed evidence both apply | `conflicted` |

Authority labels are policy inputs, not identity proof. A caller cannot make an agent-authored approval trustworthy by renaming it. Production adapters must derive authority from authenticated systems and governed promotion workflows.

## CI pattern

CI should generate the input from pinned job outputs, use an explicit evaluation time, and preserve the bundle as an artifact. A deployment job should consume the verified bundle rather than reinterpreting the individual evidence fields.

```yaml
- name: Authorize exact deployment
  run: |
    reason release authorize release.json \
      --bundle-out authorization-bundle.json
    reason --format json verify-authorization-bundle \
      authorization-bundle.json --require-authorized
```

The deployment boundary must still compare the actual tool call with the certified action. Gateway is the intended application-level enforcement point; Rakhshak provides destination-bound defense in depth.
