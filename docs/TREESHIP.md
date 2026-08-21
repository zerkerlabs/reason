# Treeship integration

Zerker Reason proves whether an exact action is authorized. Treeship preserves the resulting certificate as signed evidence.

For an enforcement-grade verify-then-sign boundary, use the dedicated atomic adapter described in [Integration profiles](INTEGRATION_PROFILES.md), when supported by the installed Treeship version. The compatibility flow below invokes the verifiers separately and demonstrates certificate preservation; it is not a substitute for an adapter that consumes one bundle and gates signing on Reason success.

The verifiers answer different questions:

- `reason verify-authorization` checks the reasoning semantics, request binding, proof, authority policy, and temporal snapshot.
- `treeship verify --full` checks the artifact digest, signer key, signature, and chain.

A Treeship signature does not make an invalid Reason certificate valid. Run both verifiers.

## End-to-end check

Build the Treeship CLI, then run the integration script:

```bash
cargo build --manifest-path ../treeship/Cargo.toml -p treeship-cli
TREESHIP_BIN=../treeship/target/debug/treeship \
  ./scripts/reason-treeship-e2e.sh
```

The script:

1. authorizes `examples/authorize-deploy.json`;
2. independently verifies the authorization certificate;
3. computes a SHA-256 digest over the exact certificate file bytes;
4. embeds the parsed certificate and its byte digest in a `reason.authorization.v1` receipt;
5. checks that the signed receipt contains the same JSON value and byte digest;
6. runs full Treeship verification.

The receipt uses `system://zerker-reason` as a producer label. The label is not an identity claim unless a verifier separately trusts the Treeship signing key associated with it.

## Manual compatibility flow

```bash
reason authorize action-request.json --certificate-out authorization.json
reason verify-authorization action-request.json authorization.json

CERTIFICATE_DIGEST="sha256:$(shasum -a 256 authorization.json | awk '{print $1}')"

treeship attest receipt \
  --system system://zerker-reason \
  --kind reason.authorization.v1 \
  --payload-file authorization.json \
  --payload-digest "$CERTIFICATE_DIGEST"

treeship verify last --full
```

The generic receipt command does not invoke Reason. Between separate commands, protect the request and certificate paths from mutation and never present this compatibility flow as atomic verify-before-sign.

Use private artifact storage when certificates contain sensitive facts. Digest-only commitments and selective disclosure are future work; the v1 receipt carries the complete certificate.
