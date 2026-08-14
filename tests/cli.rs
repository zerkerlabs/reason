use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn human_output_leads_with_the_decision() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["check", "examples/release-ready.json"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "PROVED  release_ready(1.4.0, commit_abc)",
        ));
}

#[test]
fn unknown_has_a_distinct_exit_code_and_actionable_missing_fact() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["check", "examples/release-blocked.json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("approved(1.4.0, release-manager)"))
        .stdout(predicate::str::contains("Unknown does not mean false"));
}

#[test]
fn untrusted_approval_is_withheld_and_explained() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["check", "examples/release-untrusted.json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Authority withheld 1 fact(s)"))
        .stdout(predicate::str::contains("from agent-proposed"))
        .stdout(predicate::str::contains(
            "admitted authority: human-authorized",
        ));
}

#[test]
fn expired_evidence_reports_the_evaluation_time_and_remediation() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["check", "examples/release-expired.json"])
        .assert()
        .code(2)
        .stdout(predicate::str::starts_with(
            "UNKNOWN  release_ready(1.4.0, commit_abc)",
        ))
        .stdout(predicate::str::contains(
            "Refresh or replace temporally ineligible evidence",
        ))
        .stdout(predicate::str::contains(
            "Evaluated at 2026-08-14T12:00:00Z",
        ))
        .stdout(predicate::str::contains(
            "valid_until 2026-08-14T12:00:00Z is at or before",
        ));
}

#[test]
fn v2_agent_output_exposes_the_temporal_contract() {
    let mut command = Command::cargo_bin("reason").unwrap();
    let output = command
        .args([
            "--format",
            "json",
            "check",
            "examples/release-superseded.json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "zerker.reason.result.v2");
    assert_eq!(value["status"], "disproved");
    assert_eq!(value["temporal"]["evaluation_time"], "2026-08-14T12:00:00Z");
    assert!(
        value["disproof"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| node["kind"] == "fact")
            .all(|node| node["temporal"]["observed_at"].is_string())
    );
}

#[test]
fn explicit_negation_has_a_distinct_disproved_exit_code() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["check", "examples/release-disproved.json"])
        .assert()
        .code(3)
        .stdout(predicate::str::starts_with(
            "DISPROVED  release_ready(1.4.0, commit_abc)",
        ))
        .stdout(predicate::str::contains("explicit negation is supported"));
}

#[test]
fn inconsistency_fails_closed_with_both_proofs_visible() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["check", "examples/release-inconsistent.json"])
        .assert()
        .code(4)
        .stdout(predicate::str::starts_with(
            "INCONSISTENT  release_ready(1.4.0, commit_abc)",
        ))
        .stdout(predicate::str::contains("proof sha256:"))
        .stdout(predicate::str::contains("disproof sha256:"))
        .stdout(predicate::str::contains("Do not authorize action"));
}

#[test]
fn agent_output_has_a_stable_schema() {
    let mut command = Command::cargo_bin("reason").unwrap();
    let output = command
        .args(["--format", "json", "check", "examples/release-ready.json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schema"], "zerker.reason.result.v1");
    assert_eq!(value["status"], "proved");
    assert_eq!(value["authority"]["withheld"], serde_json::json!([]));
    assert!(value["disproof"].is_null());
    assert!(value["conflict"].is_null());
    assert!(
        value["proof"]["digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn proof_file_verifies_independently() {
    let directory = tempfile::tempdir().unwrap();
    let proof = directory.path().join("release-proof.json");

    let mut check = Command::cargo_bin("reason").unwrap();
    check
        .args([
            "check",
            "examples/release-ready.json",
            "--proof-out",
            proof.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Proof written to"));

    let mut verify = Command::cargo_bin("reason").unwrap();
    verify
        .args([
            "verify",
            "examples/release-ready.json",
            proof.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "VERIFIED  release_ready(1.4.0, commit_abc)",
        ));
}

#[test]
fn exact_deployment_action_is_authorized() {
    let mut command = Command::cargo_bin("reason").unwrap();
    command
        .args(["authorize", "examples/authorize-deploy.json"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "AUTHORIZED  action_deploy_140 via mission_release_140",
        ))
        .stdout(predicate::str::contains(
            "all authorization requirements are proved",
        ));
}

#[test]
fn authorization_certificate_verifies_independently() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("authorization.json");
    let mut authorize = Command::cargo_bin("reason").unwrap();
    authorize
        .args([
            "authorize",
            "examples/authorize-deploy.json",
            "--certificate-out",
            certificate.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Certificate written to"));

    let mut verify = Command::cargo_bin("reason").unwrap();
    verify
        .args([
            "verify-authorization",
            "examples/authorize-deploy.json",
            certificate.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::starts_with(
            "VERIFIED_AUTHORIZATION  sha256:",
        ));
}

#[test]
fn authorization_verifier_rejects_changed_tool_arguments() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("authorization.json");
    let changed_request = directory.path().join("changed-request.json");
    let mut authorize = Command::cargo_bin("reason").unwrap();
    authorize
        .args([
            "authorize",
            "examples/authorize-deploy.json",
            "--certificate-out",
            certificate.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read("examples/authorize-deploy.json").unwrap()).unwrap();
    value["action"]["arguments"]["environment"] = serde_json::json!("staging");
    std::fs::write(&changed_request, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let mut verify = Command::cargo_bin("reason").unwrap();
    verify
        .args([
            "verify-authorization",
            changed_request.to_str().unwrap(),
            certificate.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("request_digest: mismatch"));
}

#[test]
fn authorization_json_has_a_stable_machine_contract() {
    let mut command = Command::cargo_bin("reason").unwrap();
    let output = command
        .args([
            "--format",
            "json",
            "authorize",
            "examples/authorize-deploy.json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schema"], "zerker.reason.authorization.v1");
    assert_eq!(value["status"], "authorized");
    assert_eq!(value["action"]["id"], "action_deploy_140");
    assert_eq!(value["reasoning"]["status"], "proved");
    assert!(
        value["request_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
}

#[test]
fn verifier_rejects_a_tampered_proof() {
    let directory = tempfile::tempdir().unwrap();
    let proof = directory.path().join("release-proof.json");
    let mut check = Command::cargo_bin("reason").unwrap();
    check
        .args([
            "check",
            "examples/release-ready.json",
            "--proof-out",
            proof.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&proof).unwrap()).unwrap();
    value["proof"]["nodes"][0]["authority"] = serde_json::json!("agent-proposed");
    std::fs::write(&proof, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let mut verify = Command::cargo_bin("reason").unwrap();
    verify
        .args([
            "verify",
            "examples/release-ready.json",
            proof.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("proof verification failed"));
}
