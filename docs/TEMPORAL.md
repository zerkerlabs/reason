# Temporal evidence lifecycle

`zerker.reason.program.v2` evaluates governed evidence at one explicit, deterministic snapshot. It adds temporal eligibility and supersession without changing `program.v1` behavior or digests.

## Snapshot contract

Every v2 program requires an evaluation time:

```json
{
  "schema": "zerker.reason.program.v2",
  "evaluation_time": "2026-08-14T12:00:00Z"
}
```

Every v2 fact requires `observed_at` and may declare `valid_from`, `valid_until`, and `supersedes`:

```json
{
  "id": "fact_review_abc_revoked",
  "predicate": "security_reviewed",
  "arguments": ["commit_abc"],
  "negated": true,
  "authority": "human-authorized",
  "observed_at": "2026-08-14T11:30:00Z",
  "valid_from": "2026-08-14T11:30:00Z",
  "valid_until": "2026-08-15T00:00:00Z",
  "supersedes": ["fact_review_abc_original"]
}
```

Timestamps must use canonical UTC RFC 3339 seconds: `YYYY-MM-DDTHH:MM:SSZ`. The kernel accepts no local timezone, fractional-second, or implicit-current-time interpretation.

## Eligibility

A fact participates in inference only when all of the following hold:

1. its authority is admitted for its predicate;
2. `observed_at <= evaluation_time`;
3. `valid_from` is absent or `valid_from <= evaluation_time`;
4. `valid_until` is absent or `evaluation_time < valid_until`;
5. no authority-admitted, temporally eligible fact supersedes it.

Validity intervals are half-open: `[valid_from, valid_until)`. A fact is expired exactly at `valid_until`.

Temporal ineligibility withholds a premise. It does not create support for the premise's negation.

## Supersession

Supersession is explicit and claim-scoped:

- the target fact must exist;
- source and target must have the same predicate and arguments;
- either polarity may supersede the other;
- the superseding fact must have a strictly later `observed_at`;
- a fact cannot supersede itself;
- only an authority-admitted, temporally eligible superseder has effect.

Therefore an agent-proposed revocation cannot hide a human-authorized premise when that authority is not admitted. Supersession chains are deterministic because observation time must increase at every edge.

V2 permits multiple versions of the same atom in the input, but at most one identical atom may remain eligible at the evaluation snapshot. Duplicate active atoms must be resolved with explicit supersession rather than input ordering.

## Result report

A `zerker.reason.result.v2` contains:

```json
{
  "temporal": {
    "evaluation_time": "2026-08-14T12:00:00Z",
    "eligible_fact_ids": ["fact_approval_140"],
    "withheld": [
      {
        "fact_id": "fact_tests_abc",
        "atom": { "predicate": "tests_passed", "arguments": ["commit_abc"] },
        "reason": "valid_until 2026-08-14T12:00:00Z is at or before evaluation_time 2026-08-14T12:00:00Z"
      }
    ]
  }
}
```

The report distinguishes stale, not-yet-valid, future-observed, and superseded evidence from authority rejection.

## Proof verification

Evaluation time and all fact lifecycle fields are covered by the program digest. Every v2 fact proof node also carries its temporal certificate. Independent verification recomputes:

- the temporal report;
- fact eligibility at the bound evaluation time;
- supersession effects;
- each proof node's temporal certificate;
- all existing authority, rule, DAG, and conflict checks.

A changed evaluation time is a different program and invalidates the prior result binding.

## Compatibility

`program.v1`, `result.v1`, and `verification.v1` remain non-temporal. V1 rejects temporal fields rather than silently ignoring them. V2 produces `result.v2` and `verification.v2`.

## Examples

```bash
reason check examples/release-expired.json
reason check examples/release-superseded.json
reason check examples/release-wrong-commit.json
reason check examples/release-overlap.json
```
