#!/usr/bin/env python3
"""Replay the portable Reason authorization conformance corpus."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def fail(vector: str, message: str) -> None:
    raise RuntimeError(f"{vector}: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reason", required=True, help="path to the Reason binary")
    parser.add_argument(
        "--manifest",
        default="conformance/v1/manifest.json",
        help="path to a conformance manifest",
    )
    args = parser.parse_args()

    manifest_path = pathlib.Path(args.manifest).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "zerker.reason.conformance-manifest.v1":
        raise RuntimeError("unsupported conformance manifest schema")

    root = manifest_path.parent
    for vector in manifest["vectors"]:
        vector_id = vector["id"]
        input_path = root / vector["input"]
        payload = input_path.read_bytes()
        actual_input_digest = hashlib.sha256(payload).hexdigest()
        if actual_input_digest != vector["input_sha256"]:
            fail(vector_id, "input SHA-256 does not match the committed manifest")

        result = subprocess.run(
            [args.reason, *vector["command"]],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={},
        )
        expected = vector["expected"]
        if result.returncode != expected["exit_code"]:
            fail(
                vector_id,
                f"exit {result.returncode}, expected {expected['exit_code']}; stderr={result.stderr.decode(errors='replace')!r}",
            )
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            fail(vector_id, f"stdout is not one JSON value: {error}")

        for key, value in expected.items():
            if key != "exit_code" and output.get(key) != value:
                fail(vector_id, f"output {key}={output.get(key)!r}, expected {value!r}")

        if expected["status"] == "verified":
            required = {
                "schema",
                "status",
                "authorization_status",
                "request_digest",
                "reasoning_result_digest",
            }
            if set(output) != required:
                fail(vector_id, f"verification output keys differ: {sorted(output)}")
        else:
            if set(output) != {"schema", "status", "error"}:
                fail(vector_id, f"error output keys differ: {sorted(output)}")
            if not isinstance(output["error"], str) or not output["error"]:
                fail(vector_id, "error output has no non-empty error string")

        print(f"{vector_id:24} exit={result.returncode} {output['status']}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, KeyError, TypeError, ValueError, RuntimeError) as error:
        print(f"conformance: {error}", file=sys.stderr)
        raise SystemExit(1)
