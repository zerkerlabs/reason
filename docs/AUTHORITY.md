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
