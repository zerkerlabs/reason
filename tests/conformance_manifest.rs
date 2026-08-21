use std::{collections::BTreeSet, fs, path::Path};

use serde_json::Value;
use sha2::{Digest, Sha256};

const MANIFEST_PATH: &str = "conformance/v1/manifest.json";

#[test]
fn conformance_manifest_commits_every_input_and_expected_outcome() {
    let manifest: Value = serde_json::from_slice(&fs::read(MANIFEST_PATH).unwrap()).unwrap();
    assert_eq!(manifest["schema"], "zerker.reason.conformance-manifest.v1");
    let vectors = manifest["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 15);

    let mut ids = BTreeSet::new();
    for vector in vectors {
        let id = vector["id"].as_str().unwrap();
        assert!(ids.insert(id), "duplicate conformance vector {id}");

        let relative = vector["input"].as_str().unwrap();
        assert!(
            relative.starts_with("inputs/") && !relative.contains(".."),
            "unsafe conformance input path {relative}"
        );
        let bytes = fs::read(Path::new("conformance/v1").join(relative)).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(vector["input_sha256"], digest, "input drift for {id}");

        assert_eq!(
            vector["command"],
            serde_json::json!([
                "--format",
                "json",
                "verify-authorization-bundle",
                "-",
                "--require-authorized"
            ])
        );
        let expected = vector["expected"].as_object().unwrap();
        assert!(expected["exit_code"].as_u64().is_some());
        assert!(expected["schema"].as_str().is_some());
        assert!(expected["status"].as_str().is_some());
        if expected["status"] == "verified" {
            for field in [
                "authorization_status",
                "request_digest",
                "reasoning_result_digest",
            ] {
                assert!(expected[field].as_str().is_some(), "{id} omits {field}");
            }
        }
    }
}

#[test]
fn conformance_covers_fail_closed_outcomes_and_profile_bindings() {
    let manifest: Value = serde_json::from_slice(&fs::read(MANIFEST_PATH).unwrap()).unwrap();
    let ids = manifest["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| vector["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    for required in [
        "authorized",
        "unknown",
        "denied",
        "conflict",
        "expired",
        "gateway-bound",
        "rakhshak-bound",
        "modified-request",
        "modified-policy",
        "modified-certificate",
        "wrong-schema",
        "malformed-certificate",
        "unknown-member",
        "duplicate-member",
        "malformed-json",
    ] {
        assert!(
            ids.contains(required),
            "missing conformance vector {required}"
        );
    }
}
