use std::collections::BTreeSet;

use assert_cmd::Command;
use serde::de::DeserializeOwned;
use serde_json::{Number, Value, json};
use zerker_reason::{
    action::{
        ActionRequest, AuthorizationBundle, AuthorizationResult, authorize, verify_authorization,
    },
    release::{ReleaseAuthorizationInput, compile_release_authorization},
};

fn bundle(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(format!("conformance/v1/inputs/{name}.bundle.json")).unwrap(),
    )
    .unwrap()
}

fn leaf_paths(value: &Value) -> Vec<String> {
    fn visit(value: &Value, path: &str, paths: &mut Vec<String>) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    visit(value, &format!("{path}/{}", escape(key)), paths);
                }
            }
            Value::Array(array) => {
                for (index, value) in array.iter().enumerate() {
                    visit(value, &format!("{path}/{index}"), paths);
                }
            }
            _ => paths.push(path.to_owned()),
        }
    }
    let mut paths = Vec::new();
    visit(value, "", &mut paths);
    paths
}

fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn changed_leaf(value: &Value) -> Value {
    match value {
        Value::Null => json!("mutation:null-was-present"),
        Value::Bool(value) => json!(!value),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                Value::Number(Number::from(integer.saturating_add(1)))
            } else if let Some(integer) = value.as_u64() {
                Value::Number(Number::from(integer.saturating_add(1)))
            } else {
                json!("mutation:number-was-present")
            }
        }
        Value::String(value) => json!(format!("{value}__mutated")),
        Value::Array(_) | Value::Object(_) => unreachable!("only leaves are mutated"),
    }
}

fn mutate_at(value: &Value, pointer: &str) -> Value {
    let mut changed = value.clone();
    let target = changed.pointer_mut(pointer).unwrap();
    *target = changed_leaf(target);
    changed
}

fn parses<T: DeserializeOwned>(value: Value) -> Option<T> {
    serde_json::from_value(value).ok()
}

#[test]
fn every_serialized_request_leaf_is_rejected_or_invalidates_its_certificate() {
    let mut exercised = 0;
    let mut sections = BTreeSet::new();

    for name in ["authorized", "expired", "gateway-bound", "rakhshak-bound"] {
        let bundle = bundle(name);
        let certificate: AuthorizationResult =
            serde_json::from_value(bundle["certificate"].clone()).unwrap();
        let request = &bundle["request"];

        for path in leaf_paths(request) {
            exercised += 1;
            sections.insert(path.split('/').nth(1).unwrap_or_default().to_owned());
            if let Some(changed) = parses::<ActionRequest>(mutate_at(request, &path)) {
                assert!(
                    verify_authorization(&changed, &certificate).is_err(),
                    "request mutation at {name}{path} retained the prior certificate"
                );
            }
        }
    }

    assert!(
        exercised > 450,
        "request mutation coverage unexpectedly shrank: {exercised} leaves"
    );
    assert_eq!(
        sections,
        BTreeSet::from([
            "action".to_owned(),
            "mission".to_owned(),
            "policy".to_owned(),
            "schema".to_owned()
        ])
    );
}

#[test]
fn every_release_domain_input_leaf_is_rejected_or_invalidates_the_compiled_certificate() {
    let value: Value =
        serde_json::from_slice(&std::fs::read("examples/release-authorization.json").unwrap())
            .unwrap();
    let input: ReleaseAuthorizationInput = serde_json::from_value(value.clone()).unwrap();
    let request = compile_release_authorization(&input).unwrap();
    let certificate = authorize(&request).unwrap();
    let mut exercised = 0;

    for path in leaf_paths(&value) {
        exercised += 1;
        if let Some(changed) = parses::<ReleaseAuthorizationInput>(mutate_at(&value, &path))
            && let Ok(changed_request) = compile_release_authorization(&changed)
        {
            assert!(
                verify_authorization(&changed_request, &certificate).is_err(),
                "release input mutation at {path} retained the prior compiled certificate"
            );
        }
    }

    assert!(
        exercised > 35,
        "release input mutation coverage unexpectedly shrank: {exercised} leaves"
    );
}

#[test]
fn every_serialized_certificate_leaf_is_rejected_or_fails_independent_replay() {
    let mut exercised = 0;
    let mut reasoning_sections = BTreeSet::new();

    for name in ["authorized", "unknown", "denied", "conflict", "expired"] {
        let bundle = bundle(name);
        let request: ActionRequest = serde_json::from_value(bundle["request"].clone()).unwrap();
        let certificate = &bundle["certificate"];

        for path in leaf_paths(certificate) {
            exercised += 1;
            if let Some(section) = path
                .strip_prefix("/reasoning/")
                .and_then(|rest| rest.split('/').next())
            {
                reasoning_sections.insert(section.to_owned());
            }
            if let Some(changed) = parses::<AuthorizationResult>(mutate_at(certificate, &path)) {
                assert!(
                    verify_authorization(&request, &changed).is_err(),
                    "certificate mutation at {name}{path} passed replay"
                );
            }
        }
    }

    assert!(
        exercised > 750,
        "certificate mutation coverage unexpectedly shrank: {exercised} leaves"
    );
    for required in [
        "assumptions",
        "authority",
        "conflict",
        "disproof",
        "metrics",
        "missing",
        "ontology",
        "program_digest",
        "proof",
        "query",
        "status",
        "temporal",
    ] {
        assert!(
            reasoning_sections.contains(required),
            "mutation coverage omitted reasoning.{required}"
        );
    }
}

fn inject_unknown(value: &Value, pointer: &str) -> Value {
    let mut changed = value.clone();
    changed
        .pointer_mut(pointer)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unsigned_semantics".to_owned(), json!("bypass"));
    changed
}

#[test]
fn cli_rejects_unknown_members_across_typed_bundle_objects() {
    let authorized = bundle("authorized");
    for pointer in [
        "",
        "/request",
        "/request/mission",
        "/request/action",
        "/request/action/effects/0",
        "/request/policy",
        "/request/policy/ontology",
        "/request/policy/ontology/predicates/tests_passed",
        "/request/policy/authority",
        "/request/policy/facts/0",
        "/request/policy/rules/0",
        "/request/policy/rules/0/when/0",
        "/request/policy/rules/0/then",
        "/request/policy/query",
        "/certificate",
        "/certificate/mission",
        "/certificate/action",
        "/certificate/action/effects/0",
        "/certificate/reasoning",
        "/certificate/reasoning/query",
        "/certificate/reasoning/ontology",
        "/certificate/reasoning/authority",
        "/certificate/reasoning/temporal",
        "/certificate/reasoning/proof",
        "/certificate/reasoning/proof/nodes/0",
        "/certificate/reasoning/proof/nodes/0/atom",
        "/certificate/reasoning/proof/nodes/0/temporal",
        "/certificate/reasoning/metrics",
    ] {
        let payload = serde_json::to_vec(&inject_unknown(&authorized, pointer)).unwrap();
        Command::cargo_bin("reason")
            .unwrap()
            .args([
                "--format",
                "json",
                "verify-authorization-bundle",
                "-",
                "--require-authorized",
            ])
            .write_stdin(payload)
            .assert()
            .code(1);
    }

    let release_input: Value =
        serde_json::from_slice(&std::fs::read("examples/release-authorization.json").unwrap())
            .unwrap();
    for pointer in [
        "",
        "/mission",
        "/release",
        "/evidence",
        "/evidence/tests/0",
        "/evidence/security_reviews/0",
        "/evidence/artifacts/0",
        "/evidence/approvals/0",
    ] {
        let payload = serde_json::to_vec(&inject_unknown(&release_input, pointer)).unwrap();
        Command::cargo_bin("reason")
            .unwrap()
            .args(["--format", "json", "release", "authorize", "-"])
            .write_stdin(payload)
            .assert()
            .code(1);
    }

    for (name, pointer) in [
        ("expired", "/certificate/issues/0"),
        ("expired", "/certificate/issues/0/atom"),
        ("expired", "/certificate/reasoning/temporal/withheld/0"),
        ("conflict", "/certificate/reasoning/conflict"),
        ("denied", "/certificate/reasoning/disproof"),
    ] {
        let payload = serde_json::to_vec(&inject_unknown(&bundle(name), pointer)).unwrap();
        Command::cargo_bin("reason")
            .unwrap()
            .args(["--format", "json", "verify-authorization-bundle", "-"])
            .write_stdin(payload)
            .assert()
            .code(1);
    }
}

#[test]
fn committed_authorized_bundle_still_verifies_before_mutation() {
    let value = bundle("authorized");
    let bundle: AuthorizationBundle = serde_json::from_value(value).unwrap();
    zerker_reason::action::verify_authorization_bundle(&bundle).unwrap();
}
