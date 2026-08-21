use std::{fs, path::Path};

use assert_cmd::Command;
use serde_json::{Value, json};
use zerker_reason::{
    ERROR_SCHEMA,
    action::{
        ACTION_REQUEST_SCHEMA, AUTHORIZATION_BUNDLE_SCHEMA, AUTHORIZATION_RESULT_SCHEMA,
        AUTHORIZATION_VERIFICATION_SCHEMA, ActionRequest, AuthorizationBundle, AuthorizationResult,
        authorize, verify_authorization,
    },
    release::{RELEASE_AUTHORIZATION_SCHEMA, RELEASE_INIT_SCHEMA, ReleaseAuthorizationInput},
};

const CATALOG: &str = include_str!("../schemas/zerker.reason.contracts.v1.schema.json");

fn load_json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn website_json(path: &str) -> Option<Value> {
    Path::new("website").exists().then(|| load_json(path))
}

fn authorized_values() -> (Value, Value, Value) {
    let request: ActionRequest =
        serde_json::from_value(load_json("examples/authorize-deploy.json")).unwrap();
    let certificate = authorize(&request).unwrap();
    let verification = verify_authorization(&request, &certificate).unwrap();
    (
        serde_json::to_value(request).unwrap(),
        serde_json::to_value(certificate).unwrap(),
        serde_json::to_value(verification).unwrap(),
    )
}

fn contract_schema(definition: &str) -> Value {
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    json!({
        "$schema": catalog["$schema"],
        "$ref": format!("#/$defs/{definition}"),
        "$defs": catalog["$defs"],
    })
}

fn validation_errors(definition: &str, instance: &Value) -> Vec<String> {
    let schema = contract_schema(definition);
    let validator = jsonschema::validator_for(&schema).unwrap();
    validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect()
}

fn assert_valid(definition: &str, instance: &Value) {
    let errors = validation_errors(definition, instance);
    assert!(
        errors.is_empty(),
        "{definition} rejected a valid value:\n{}",
        errors.join("\n")
    );
}

fn assert_invalid(definition: &str, instance: &Value) {
    assert!(
        !validation_errors(definition, instance).is_empty(),
        "{definition} accepted an invalid value: {instance}"
    );
}

#[test]
fn entry_schemas_match_rust_wire_identifiers_and_catalog_definitions() {
    let contracts = [
        (
            ACTION_REQUEST_SCHEMA,
            "actionRequest",
            "zerker.reason.action.v1.schema.json",
        ),
        (
            AUTHORIZATION_RESULT_SCHEMA,
            "authorizationResult",
            "zerker.reason.authorization.v1.schema.json",
        ),
        (
            AUTHORIZATION_BUNDLE_SCHEMA,
            "authorizationBundle",
            "zerker.reason.authorization-bundle.v1.schema.json",
        ),
        (
            AUTHORIZATION_VERIFICATION_SCHEMA,
            "authorizationVerification",
            "zerker.reason.authorization-verification.v1.schema.json",
        ),
        (ERROR_SCHEMA, "error", "zerker.reason.error.v1.schema.json"),
        (
            RELEASE_AUTHORIZATION_SCHEMA,
            "releaseAuthorizationInput",
            "zerker.reason.release-authorization.v1.schema.json",
        ),
        (
            RELEASE_INIT_SCHEMA,
            "releaseInit",
            "zerker.reason.release-init.v1.schema.json",
        ),
    ];
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    let schema_readme = fs::read_to_string("schemas/README.md").unwrap();

    for (wire_identifier, definition, filename) in contracts {
        let entry = load_json(Path::new("schemas").join(filename));
        assert_eq!(entry["$id"], filename);
        assert_eq!(entry["title"], wire_identifier);
        assert_eq!(
            entry["$ref"],
            format!("zerker.reason.contracts.v1.schema.json#/$defs/{definition}")
        );
        assert!(catalog["$defs"].get(definition).is_some());
        assert!(schema_readme.contains(filename));

        let schema_const = catalog["$defs"][definition]["properties"]["schema"]["const"]
            .as_str()
            .unwrap();
        assert_eq!(schema_const, wire_identifier);
    }
}

#[test]
fn entry_schemas_resolve_the_committed_catalog() {
    let catalog: Value = serde_json::from_str(CATALOG).unwrap();
    let registry = jsonschema::Registry::new()
        .add(
            "https://reason.test/schemas/zerker.reason.contracts.v1.schema.json",
            catalog,
        )
        .unwrap()
        .prepare()
        .unwrap();
    let (request, certificate, verification) = authorized_values();
    let cases = [
        ("zerker.reason.action.v1.schema.json", request.clone()),
        (
            "zerker.reason.authorization.v1.schema.json",
            certificate.clone(),
        ),
        (
            "zerker.reason.authorization-bundle.v1.schema.json",
            json!({
                "schema": AUTHORIZATION_BUNDLE_SCHEMA,
                "request": request,
                "certificate": certificate,
            }),
        ),
        (
            "zerker.reason.authorization-verification.v1.schema.json",
            verification,
        ),
        (
            "zerker.reason.error.v1.schema.json",
            json!({
                "schema": ERROR_SCHEMA,
                "status": "error",
                "error": "failure",
            }),
        ),
        (
            "zerker.reason.release-authorization.v1.schema.json",
            load_json("examples/release-authorization.json"),
        ),
        (
            "zerker.reason.release-init.v1.schema.json",
            json!({
                "schema": RELEASE_INIT_SCHEMA,
                "status": "created",
                "path": "release.json",
            }),
        ),
    ];

    for (filename, instance) in cases {
        let entry = load_json(Path::new("schemas").join(filename));
        let validator = jsonschema::options()
            .with_base_uri("https://reason.test/schemas/")
            .with_registry(&registry)
            .build(&entry)
            .unwrap();
        assert!(validator.is_valid(&instance), "{filename} did not resolve");
    }
}

#[test]
fn shipped_release_input_matches_its_schema_and_rust_wire_type() {
    let fixture = load_json("examples/release-authorization.json");
    assert_valid("releaseAuthorizationInput", &fixture);
    let wire: ReleaseAuthorizationInput = serde_json::from_value(fixture).unwrap();
    assert_valid(
        "releaseAuthorizationInput",
        &serde_json::to_value(wire).unwrap(),
    );
}

#[test]
fn shipped_requests_match_the_action_schema_and_rust_wire_type() {
    let fixture = load_json("examples/authorize-deploy.json");
    assert_valid("actionRequest", &fixture);
    let wire: ActionRequest = serde_json::from_value(fixture).unwrap();
    assert_valid("actionRequest", &serde_json::to_value(wire).unwrap());

    for path in [
        "website/data/reason/authorized-request.json",
        "website/data/reason/unknown-request.json",
        "website/data/reason/denied-request.json",
        "website/data/reason/conflict-request.json",
    ] {
        let Some(fixture) = website_json(path) else {
            continue;
        };
        assert_valid("actionRequest", &fixture);
        let wire: ActionRequest = serde_json::from_value(fixture).unwrap();
        assert_valid("actionRequest", &serde_json::to_value(wire).unwrap());
    }
}

#[test]
fn shipped_certificates_match_the_authorization_schema_and_rust_wire_type() {
    let (_, generated, _) = authorized_values();
    assert_valid("authorizationResult", &generated);

    for path in [
        "website/data/reason/authorized-certificate.json",
        "website/data/reason/unknown-certificate.json",
        "website/data/reason/denied-certificate.json",
        "website/data/reason/conflict-certificate.json",
    ] {
        let Some(fixture) = website_json(path) else {
            continue;
        };
        assert_valid("authorizationResult", &fixture);
        let wire: AuthorizationResult = serde_json::from_value(fixture).unwrap();
        assert_valid("authorizationResult", &serde_json::to_value(wire).unwrap());
    }
}

#[test]
fn bundle_verification_and_error_values_match_their_schemas() {
    let (request, certificate, generated_verification) = authorized_values();
    let bundle = json!({
        "schema": AUTHORIZATION_BUNDLE_SCHEMA,
        "request": request,
        "certificate": certificate,
    });
    let wire: AuthorizationBundle = serde_json::from_value(bundle).unwrap();
    assert_valid("authorizationBundle", &serde_json::to_value(wire).unwrap());

    assert_valid("authorizationVerification", &generated_verification);
    for path in [
        "website/data/reason/authorized-verification.json",
        "website/data/reason/unknown-verification.json",
        "website/data/reason/denied-verification.json",
        "website/data/reason/conflict-verification.json",
    ] {
        if let Some(fixture) = website_json(path) {
            assert_valid("authorizationVerification", &fixture);
        }
    }

    let output = Command::cargo_bin("reason")
        .unwrap()
        .args(["--format", "json", "authorize", "-"])
        .write_stdin("{}")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_valid("error", &serde_json::from_slice(&output.stdout).unwrap());
}

#[test]
fn schemas_fail_closed_on_typed_contract_drift() {
    let mut request = load_json("examples/authorize-deploy.json");
    request["schema"] = json!("zerker.reason.action.v0");
    assert_invalid("actionRequest", &request);

    let mut request = load_json("examples/authorize-deploy.json");
    request["action"]["unrecognized_execution_mode"] = json!("bypass");
    assert_invalid("actionRequest", &request);

    for invalid_timestamp in [
        "2026-99-99T99:99:99Z",
        "2026-02-30T12:00:00Z",
        "2026-08-14T12:00:00.000Z",
        "2026-08-14T12:00:00+00:00",
    ] {
        let mut request = load_json("examples/authorize-deploy.json");
        request["mission"]["issued_at"] = json!(invalid_timestamp);
        assert_invalid("actionRequest", &request);
    }

    let mut request = load_json("examples/authorize-deploy.json");
    request["policy"]["facts"][0]
        .as_object_mut()
        .unwrap()
        .remove("observed_at");
    assert_invalid("actionRequest", &request);

    let (_, certificate, verification) = authorized_values();

    let mut changed = certificate.clone();
    changed["status"] = json!("expired");
    assert_invalid("authorizationResult", &changed);

    let mut changed = certificate.clone();
    changed["reasoning"]["proof"]["nodes"][0]["unsigned_semantics"] = json!(true);
    assert_invalid("authorizationResult", &changed);

    let mut changed = certificate.clone();
    changed["request_digest"] = json!("sha256:not-a-digest");
    assert_invalid("authorizationResult", &changed);

    let mut changed = certificate;
    changed["reasoning"]
        .as_object_mut()
        .unwrap()
        .remove("proof");
    assert_invalid("authorizationResult", &changed);

    let mut verification = verification;
    verification["ignored"] = json!(true);
    assert_invalid("authorizationVerification", &verification);

    assert_invalid(
        "error",
        &json!({
            "schema": ERROR_SCHEMA,
            "status": "error",
            "error": "failure",
            "host_path": "/private/build/path",
        }),
    );
}

#[test]
fn successful_conformance_bundles_match_the_published_wire_schema() {
    let manifest = load_json("conformance/v1/manifest.json");
    for vector in manifest["vectors"].as_array().unwrap() {
        if vector["expected"]["status"] != "verified" {
            continue;
        }
        let path = Path::new("conformance/v1").join(vector["input"].as_str().unwrap());
        assert_valid("authorizationBundle", &load_json(path));
    }
}

#[test]
fn application_defined_maps_remain_open_without_opening_typed_objects() {
    let mut request = load_json("examples/authorize-deploy.json");
    request["mission"]["constraints"]["gateway.profile"] = json!({
        "tenant": "tenant-1",
        "scopes": ["deploy", {"region": "us-east"}],
    });
    request["action"]["arguments"]["provider_payload"] = json!({
        "dry_run": false,
        "retries": 2,
        "metadata": null,
    });
    assert_valid("actionRequest", &request);
}
