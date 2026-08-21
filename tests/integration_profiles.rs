use serde_json::{Value, json};
use zerker_reason::{
    Atom, Rule,
    action::{ActionEffect, ActionRequest, AuthorizationStatus, authorize, verify_authorization},
};

fn deployment_request() -> ActionRequest {
    serde_json::from_str(include_str!("../examples/authorize-deploy.json")).unwrap()
}

#[test]
fn integration_profile_documentation_names_owned_boundaries() {
    let documentation = include_str!("../docs/INTEGRATION_PROFILES.md");
    for contract in [
        "zerker.reason.action.v1",
        "zerker.reason.authorization-bundle.v1",
        "zerker.gateway.reason-mcp-call.v1",
        "gateway.tenant_id",
        "gateway.agent_id",
        "zerker.rakhshak.network-grant.v1",
        "rakhshak.network.connect",
        "zerker.memory.reason-premises.v1",
        "reason.authorization.v1",
    ] {
        assert!(
            documentation.contains(contract),
            "integration documentation omitted {contract}"
        );
    }
    for boundary in [
        "not universal Reason requirements",
        "Check adapter availability",
        "is not this atomic profile",
        "current governed state",
    ] {
        assert!(
            documentation.contains(boundary),
            "integration documentation omitted boundary: {boundary}"
        );
    }
}

#[test]
fn gateway_context_is_application_defined_but_certificate_bound() {
    let mut request = deployment_request();
    request.mission.constraints.insert(
        "gateway.tenant_id".to_owned(),
        Value::String("tenant_release".to_owned()),
    );
    request.mission.constraints.insert(
        "gateway.agent_id".to_owned(),
        Value::String("agent_deployer".to_owned()),
    );

    let certificate = authorize(&request).unwrap();
    assert_eq!(certificate.status, AuthorizationStatus::Authorized);
    verify_authorization(&request, &certificate).unwrap();

    let mut other_tenant = request.clone();
    other_tenant.mission.constraints.insert(
        "gateway.tenant_id".to_owned(),
        Value::String("tenant_other".to_owned()),
    );
    let error = verify_authorization(&other_tenant, &certificate)
        .unwrap_err()
        .to_string();
    assert!(error.contains("request_digest: mismatch"));

    // Reason binds the application-defined key but does not assign Gateway
    // identity semantics to it. The adapter must compare authenticated context.
    assert_eq!(
        authorize(&other_tenant).unwrap().status,
        AuthorizationStatus::Authorized
    );
}

#[test]
fn rakhshak_destination_claim_is_exact_action_bound() {
    let mut request = deployment_request();
    request.action.tool = "rakhshak.network.connect".to_owned();
    request.action.arguments = [
        ("schema", json!("zerker.rakhshak.network-grant.v1")),
        ("nonce", json!("nonce_0123456789abcdef")),
        ("session_id", json!("gsess_42_100_20")),
        ("transport", json!("tcp")),
        ("host", json!("api.example.com")),
        ("remote_ip", json!("203.0.113.10")),
        ("port", json!(443)),
        ("not_before", json!("2026-08-14T12:00:00Z")),
        ("expires_at", json!("2026-08-14T12:04:00Z")),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    request.action.effects = vec![ActionEffect {
        kind: "network_connect".to_owned(),
        resource: "tcp://203.0.113.10:443".to_owned(),
        value: None,
    }];
    request.policy.rules = vec![Rule {
        id: "authorize_exact_rakhshak_destination".to_owned(),
        when: vec![
            atom("mission_active", &["$mission"]),
            atom("mission_action", &["$mission", "$action"]),
            atom("action_tool", &["$action", "rakhshak.network.connect"]),
            atom(
                "action_argument",
                &["$action", "schema", "zerker.rakhshak.network-grant.v1"],
            ),
            atom(
                "action_argument",
                &["$action", "nonce", "nonce_0123456789abcdef"],
            ),
            atom(
                "action_argument",
                &["$action", "session_id", "gsess_42_100_20"],
            ),
            atom("action_argument", &["$action", "transport", "tcp"]),
            atom("action_argument", &["$action", "host", "api.example.com"]),
            atom("action_argument", &["$action", "remote_ip", "203.0.113.10"]),
            atom("action_argument", &["$action", "port", "number:443"]),
            atom(
                "action_argument",
                &["$action", "not_before", "2026-08-14T12:00:00Z"],
            ),
            atom(
                "action_argument",
                &["$action", "expires_at", "2026-08-14T12:04:00Z"],
            ),
            atom(
                "action_effect",
                &[
                    "$action",
                    "network_connect",
                    "tcp://203.0.113.10:443",
                    "none:",
                ],
            ),
        ],
        then: atom("action_authorized", &["$action"]),
    }];

    let certificate = authorize(&request).unwrap();
    assert_eq!(certificate.status, AuthorizationStatus::Authorized);
    verify_authorization(&request, &certificate).unwrap();

    let mut other_destination = request.clone();
    other_destination
        .action
        .arguments
        .insert("remote_ip".to_owned(), json!("203.0.113.11"));
    let error = verify_authorization(&other_destination, &certificate)
        .unwrap_err()
        .to_string();
    assert!(error.contains("request_digest: mismatch"));
    assert_eq!(
        authorize(&other_destination).unwrap().status,
        AuthorizationStatus::InsufficientEvidence
    );
}

fn atom(predicate: &str, arguments: &[&str]) -> Atom {
    Atom {
        predicate: predicate.to_owned(),
        arguments: arguments
            .iter()
            .map(|argument| Value::String((*argument).to_owned()))
            .collect(),
        negated: false,
    }
}
