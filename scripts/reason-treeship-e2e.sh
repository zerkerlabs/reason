#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REASON_BIN="${REASON_BIN:-$ROOT/target/debug/reason}"
TREESHIP_BIN="${TREESHIP_BIN:-$ROOT/../treeship/target/debug/treeship}"
REQUEST="${REQUEST:-$ROOT/examples/authorize-deploy.json}"

if [[ ! -x "$REASON_BIN" ]]; then
  cargo build --manifest-path "$ROOT/Cargo.toml" --bin reason
fi

if [[ ! -x "$TREESHIP_BIN" ]]; then
  echo "Treeship binary not found at $TREESHIP_BIN" >&2
  echo "Set TREESHIP_BIN or build it with: cargo build -p treeship-cli" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/reason-treeship-e2e.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

CERTIFICATE="$WORKDIR/authorization.json"
CONFIG="$WORKDIR/treeship.json"

"$REASON_BIN" authorize "$REQUEST" --certificate-out "$CERTIFICATE"
"$REASON_BIN" verify-authorization "$REQUEST" "$CERTIFICATE"

CERTIFICATE_DIGEST="sha256:$(shasum -a 256 "$CERTIFICATE" | awk '{print $1}')"

(
  cd "$WORKDIR"
  "$TREESHIP_BIN" init \
    --config "$CONFIG" \
    --name reason-e2e \
    --format json >/dev/null

  "$TREESHIP_BIN" attest receipt \
    --config "$CONFIG" \
    --format json \
    --system system://zerker-reason \
    --kind reason.authorization.v1 \
    --payload-file "$CERTIFICATE" \
    --payload-digest "$CERTIFICATE_DIGEST" >attest.json
)

ARTIFACT_ID="$(python3 - "$WORKDIR/attest.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["id"])
PY
)"

ARTIFACT_FILE="$(find "$WORKDIR" -name "$ARTIFACT_ID.json" -type f -print -quit)"
if [[ -z "$ARTIFACT_FILE" ]]; then
  echo "Treeship artifact $ARTIFACT_ID was not written" >&2
  exit 1
fi

python3 - "$ARTIFACT_FILE" "$CERTIFICATE" "$CERTIFICATE_DIGEST" <<'PY'
import base64
import json
import sys

artifact_path, certificate_path, expected_digest = sys.argv[1:]
with open(artifact_path, encoding="utf-8") as handle:
    artifact = json.load(handle)
with open(certificate_path, encoding="utf-8") as handle:
    certificate = json.load(handle)

encoded = artifact["envelope"]["payload"]
encoded += "=" * ((4 - len(encoded) % 4) % 4)
receipt = json.loads(base64.urlsafe_b64decode(encoded))

assert receipt["kind"] == "reason.authorization.v1"
assert receipt["system"] == "system://zerker-reason"
assert receipt["payload"] == certificate
assert receipt["payloadDigest"] == expected_digest
PY

"$TREESHIP_BIN" verify \
  --config "$CONFIG" \
  --format json \
  --full "$ARTIFACT_ID" >"$WORKDIR/verification.json"

python3 - "$WORKDIR/verification.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    verification = json.load(handle)
assert verification["outcome"] == "pass"
assert verification["failed"] == 0
PY

printf '\nPASS  Reason authorization verified and preserved by Treeship\n'
printf '      artifact %s\n' "$ARTIFACT_ID"
printf '      payload  %s\n' "$CERTIFICATE_DIGEST"
