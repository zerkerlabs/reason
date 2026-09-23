# Premise authority

Facts do not participate in reasoning merely because they appear in the input. Every program declares authority classes and an explicit admission policy.

```json
{
  "authority": {
    "classes": ["agent-proposed", "tool-reported", "human-authorized"],
    "default_admit": ["tool-reported", "human-authorized"],
    "predicate_admit": {
      "tests_passed": ["tool-reported"],
      "approved": ["human-authorized"]
    }
  }
}
```

`predicate_admit` replaces the default for that predicate. An empty list explicitly withholds every supplied fact for the predicate.

## Why authority is an allow-list

Authority classes are not a universal ranking. A tool observation is appropriate evidence that tests ran, while a human authorization is appropriate evidence that a release was approved. Treating either as globally stronger would allow one type of evidence to impersonate another.

The policy therefore names accepted classes per predicate instead of using a minimum numeric trust score.

## Withheld facts

A fact whose class is declared but not admitted remains visible in the authority report and does not enter the inference graph:

```text
UNKNOWN  release_ready(1.4.0, commit_abc)
        missing:
        - approved(1.4.0, release-manager)

Authority withheld 1 fact(s):
        - approved(1.4.0, release-manager) from agent-proposed (fact_approval_140)
          admitted authority: human-authorized
```

This distinguishes three states:

- no relevant fact was supplied;
- a fact was supplied but its authority was not admitted;
- an admitted fact supported the proof.

Withholding is not the same as proving a fact false.

In program v2, only an authority-admitted and temporally eligible fact can supersede another fact. An untrusted revocation therefore cannot hide a governed premise.

## Model-judged evidence

`model-judged` is the class for a judge's typed answer: a decision model, an LLM prompted to judge, a classifier, or a deterministic rules engine that sits between an agent and an action and answers a question about it. Treeship signs such an answer as a `judgement.v1` receipt (`treeship judge --attest`): the judge's model and kind, whether it is replayable, digests of the state and the questions, the one question by key, the typed answer, the threshold the caller held it to, and the outcome.

A program admits `model-judged` the way it admits any class: by name, per predicate. The convention is:

- The fact's `id` is the receipt's artifact id (`art_…`), so the label is traceable to one signed judgement rather than asserted by whoever wrote the policy input.
- The predicate describes the judgement, not the world: `judged_unsafe(action, "no")` says what the judge answered, and a rule decides what that means. A `model-judged` fact should not stand in for `tests_passed` or `approved`; those predicates keep `tool-reported` and `human-authorized`.
- Admit it for the predicates a judge is allowed to answer, and nowhere else. `examples/authorize-deploy-judged.json` admits it for `judged_unsafe` alone; a model-labelled `security_reviewed` or `approved` is withheld exactly as an `agent-proposed` one is.
- A judge's answer works best as a gate that can only deny: `judged_unsafe(action, "yes")` derives `not action_authorized(action)`, and authorization also requires `judged_unsafe(action, "no")` to have been made. A missing judgement leaves the result `UNKNOWN`; it never authorizes by absence.

Replayability belongs to the receipt, not the class. A rules judge (`judge.kind: rules`, `replayable: true`) can be re-run by a verifier on the receipt's state to get the receipt's answer; a sampled model cannot, and its receipt proves only what the caller committed to before acting. Reason does not verify the Treeship signature or re-run the judge; the [Treeship profile](INTEGRATION_PROFILES.md#treeship-atomic-verify-then-sign) keeps those checks outside the kernel, and `model-judged` is a local label until an adapter derives it from a verified receipt.

## Validation

Authority class names use lowercase letters, digits, and internal hyphens. A program is invalid when:

- no classes are declared;
- a fact uses an undeclared class;
- an admission list references an undeclared class;
- a predicate override references an undeclared predicate;
- in v1, two facts assert the same atom;
- in v2, two identical atoms remain active at the evaluation snapshot without explicit supersession.

## Proof verification

The program digest binds the complete authority policy and every fact authority. The independent verifier also recomputes the authority report and rejects any proof containing a fact withheld by policy.

Reason authority labels are local assertions. The ZMem, Gateway, Rakhshak, and Treeship integration profiles keep external governance, identity, enforcement, and signing checks outside the Reason kernel. Calling a fact `human-authorized` does not by itself prove a human authorized it. See [Integration profiles](INTEGRATION_PROFILES.md).
