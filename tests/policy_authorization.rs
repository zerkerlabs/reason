use std::{fs, path::Path};

use serde_json::{Value, json};
use zerker_reason::{
    Atom,
    action::{AuthorizationStatus, Mission, ProposedAction},
    policy::{
        MAX_POLICY_AUTHORIZATION_INPUT_BYTES, MAX_POLICY_AUTHORIZATION_OUTPUT_BYTES,
        MAX_POLICY_AUTHORIZATION_VERIFICATION_INPUT_BYTES, POLICY_AUTHORIZATION_INPUT_SCHEMA,
        POLICY_AUTHORIZATION_VERIFICATION_INPUT_SCHEMA, PolicyAuthorizationInput,
        PolicyAuthorizationVerificationInput, authorize_policy, lock_policy_bundle,
        parse_policy_authorization, parse_policy_authorization_input,
        parse_policy_authorization_verification_input, parse_policy_source_manifest,
        parse_policy_template, verify_policy_authorization,
    },
};

type AuthorizationMutation = (&'static str, Box<dyn Fn(&mut Value)>);

fn locked_bundle(
    policy: &zerker_reason::policy::PolicyTemplate,
) -> zerker_reason::policy::PolicyBundle {
    let manifest =
        parse_policy_source_manifest(include_bytes!("../examples/policy-source-manifest.json"))
            .unwrap();
    lock_policy_bundle(
        Path::new("tests/fixtures/policy-sources"),
        &manifest,
        policy,
    )
    .unwrap()
}

fn base_policy() -> zerker_reason::policy::PolicyTemplate {
    parse_policy_template(include_bytes!("../examples/policy-template.json")).unwrap()
}

fn input_with_policy(policy: &zerker_reason::policy::PolicyTemplate) -> PolicyAuthorizationInput {
    PolicyAuthorizationInput {
        schema: POLICY_AUTHORIZATION_INPUT_SCHEMA.to_owned(),
        policy_bundle: locked_bundle(policy),
        evaluation_time: "2026-08-29T12:00:00Z".to_owned(),
        mission: Mission {
            id: "mission_support_42".to_owned(),
            principal: "user:123".to_owned(),
            instruction_digest: format!("sha256:{}", "1".repeat(64)),
            issued_at: "2026-08-29T11:00:00Z".to_owned(),
            valid_until: Some("2026-08-29T13:00:00Z".to_owned()),
            constraints: [
                ("gateway.tenant_id".to_owned(), json!("tenant_123")),
                ("gateway.agent_id".to_owned(), json!("agent_456")),
            ]
            .into_iter()
            .collect(),
        },
        action: ProposedAction {
            id: "invocation_789".to_owned(),
            tool: "lookup_ticket".to_owned(),
            proposed_at: "2026-08-29T12:00:00Z".to_owned(),
            arguments: [("ticket_id".to_owned(), json!("T-42"))]
                .into_iter()
                .collect(),
            effects: Vec::new(),
        },
    }
}

fn verification_input(input: &PolicyAuthorizationInput) -> PolicyAuthorizationVerificationInput {
    PolicyAuthorizationVerificationInput {
        schema: POLICY_AUTHORIZATION_VERIFICATION_INPUT_SCHEMA.to_owned(),
        policy_bundle: input.policy_bundle.clone(),
        policy_authorization: authorize_policy(input).unwrap(),
    }
}

#[test]
fn shipped_policy_authorization_input_is_strict_deterministic_and_authorized() {
    let input = parse_policy_authorization_input(include_bytes!(
        "../examples/policy-authorization-input.json"
    ))
    .unwrap();
    let result = authorize_policy(&input).unwrap();
    assert_eq!(result.authorization_status, AuthorizationStatus::Authorized);
    assert_eq!(
        result.policy_bundle_digest,
        "sha256:8aa3219d40f9ca9362fe25b3c4e1ea26f38a60cffc909e4806be2642b96f4f39"
    );
    assert_eq!(
        result.request_digest,
        "sha256:9c44e302163bcbb26f95561f9c106210bbead9e2cccaabfe47bd8842b7a9bc40"
    );
    assert_eq!(
        result.reasoning_result_digest,
        "sha256:65d1ddce6dc77cd188269413f0633024f95628fbbeea9c098f0da0bf475d4a29"
    );
}

#[test]
fn expands_exact_action_authorizes_without_source_reads_and_verifies_independently() {
    let input = input_with_policy(&base_policy());
    let authorization = authorize_policy(&input).unwrap();
    assert_eq!(
        authorization.authorization_status,
        AuthorizationStatus::Authorized
    );
    assert_eq!(
        authorization.policy_bundle_digest,
        input.policy_bundle.bundle_digest
    );
    assert_eq!(
        authorization.request_digest,
        authorization.authorization.certificate.request_digest
    );
    assert_eq!(
        authorization
            .authorization
            .request
            .policy
            .evaluation_time
            .as_deref(),
        Some("2026-08-29T12:00:00Z")
    );
    assert_eq!(
        authorization.authorization.request.policy.query,
        Atom {
            predicate: "action_authorized".to_owned(),
            arguments: vec![json!("invocation_789")],
            negated: false,
        }
    );
    assert_eq!(
        authorization.authorization.request.mission.principal,
        "user:123"
    );
    assert_eq!(
        authorization.authorization.request.action.arguments["ticket_id"],
        "T-42"
    );

    // Authorization consumes only the immutable locked value. Source access is
    // deliberately absent from the API and is a separate operator workflow.
    let verification = verify_policy_authorization(&PolicyAuthorizationVerificationInput {
        schema: POLICY_AUTHORIZATION_VERIFICATION_INPUT_SCHEMA.to_owned(),
        policy_bundle: input.policy_bundle,
        policy_authorization: authorization,
    })
    .unwrap();
    assert_eq!(
        verification.authorization_status,
        AuthorizationStatus::Authorized
    );
}

#[test]
fn unknown_denied_and_conflicted_policy_outcomes_fail_closed() {
    let mut unknown_policy = base_policy();
    unknown_policy.rules.clear();
    let unknown = authorize_policy(&input_with_policy(&unknown_policy)).unwrap();
    assert_eq!(
        unknown.authorization_status,
        AuthorizationStatus::InsufficientEvidence
    );

    let mut denied_policy = base_policy();
    denied_policy.rules[0].then.negated = true;
    let denied = authorize_policy(&input_with_policy(&denied_policy)).unwrap();
    assert_eq!(denied.authorization_status, AuthorizationStatus::Denied);

    let mut conflict_policy = base_policy();
    let mut denial = conflict_policy.rules[0].clone();
    denial.id = "deny_ticket_lookup".to_owned();
    denial.then.negated = true;
    conflict_policy.rules.push(denial);
    let conflict = authorize_policy(&input_with_policy(&conflict_policy)).unwrap();
    assert_eq!(
        conflict.authorization_status,
        AuthorizationStatus::Conflicted
    );
}

#[test]
fn malformed_time_and_future_action_facts_do_not_authorize() {
    let mut malformed = input_with_policy(&base_policy());
    malformed.evaluation_time = "2026-08-29T12:00:00+00:00".to_owned();
    assert!(
        authorize_policy(&malformed)
            .unwrap_err()
            .to_string()
            .contains("evaluation_time")
    );

    let mut future = input_with_policy(&base_policy());
    future.action.proposed_at = "2026-08-29T12:00:01Z".to_owned();
    let result = authorize_policy(&future).unwrap();
    assert_eq!(
        result.authorization_status,
        AuthorizationStatus::InsufficientEvidence
    );
}

#[test]
fn independent_verifier_rejects_every_binding_and_summary_mutation() {
    let input = input_with_policy(&base_policy());
    let valid = verification_input(&input);
    verify_policy_authorization(&valid).unwrap();
    let value = serde_json::to_value(&valid).unwrap();

    let mutations: Vec<AuthorizationMutation> = vec![
        (
            "policy bundle digest",
            Box::new(|value| {
                value["policy_authorization"]["policy_bundle_digest"] =
                    json!(format!("sha256:{}", "f".repeat(64)))
            }),
        ),
        (
            "principal",
            Box::new(|value| {
                value["policy_authorization"]["authorization"]["request"]["mission"]["principal"] =
                    json!("user:attacker")
            }),
        ),
        (
            "tenant",
            Box::new(|value| {
                value["policy_authorization"]["authorization"]["request"]["mission"]["constraints"]
                    ["gateway.tenant_id"] = json!("tenant_attacker")
            }),
        ),
        (
            "tool",
            Box::new(|value| {
                value["policy_authorization"]["authorization"]["request"]["action"]["tool"] =
                    json!("delete_ticket")
            }),
        ),
        (
            "nested arguments",
            Box::new(|value| {
                value["policy_authorization"]["authorization"]["request"]["action"]["arguments"]["ticket_id"] =
                    json!({"nested":"T-99"})
            }),
        ),
        (
            "expanded policy",
            Box::new(|value| {
                value["policy_authorization"]["authorization"]["request"]["policy"]["rules"] =
                    json!([])
            }),
        ),
        (
            "certificate status",
            Box::new(|value| {
                value["policy_authorization"]["authorization"]["certificate"]["status"] =
                    json!("denied")
            }),
        ),
        (
            "summary status",
            Box::new(|value| {
                value["policy_authorization"]["authorization_status"] = json!("denied")
            }),
        ),
        (
            "request digest",
            Box::new(|value| {
                value["policy_authorization"]["request_digest"] =
                    json!(format!("sha256:{}", "e".repeat(64)))
            }),
        ),
        (
            "reasoning digest",
            Box::new(|value| {
                value["policy_authorization"]["reasoning_result_digest"] =
                    json!(format!("sha256:{}", "d".repeat(64)))
            }),
        ),
        (
            "typed policy",
            Box::new(|value| {
                value["policy_bundle"]["policy"]["ontology"]["version"] = json!("attacker")
            }),
        ),
    ];

    for (name, mutate) in mutations {
        let mut changed = value.clone();
        mutate(&mut changed);
        let parsed: PolicyAuthorizationVerificationInput = serde_json::from_value(changed).unwrap();
        assert!(
            verify_policy_authorization(&parsed).is_err(),
            "accepted mutation: {name}"
        );
    }
}

#[test]
fn strict_bounded_policy_authorization_inputs_reject_duplicates_unknowns_and_overflow() {
    let input = input_with_policy(&base_policy());
    let bytes = serde_json::to_vec(&input).unwrap();
    parse_policy_authorization_input(&bytes).unwrap();

    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen(
        "\"schema\":\"zerker.reason.policy-authorization-input.v1\"",
        "\"schema\":\"zerker.reason.policy-authorization-input.v0\",\"schema\":\"zerker.reason.policy-authorization-input.v1\"",
        1,
    );
    assert!(
        parse_policy_authorization_input(duplicate.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("duplicate object member `schema`")
    );

    let mut unknown = serde_json::to_value(&input).unwrap();
    unknown["caller_query"] = json!({"predicate":"allow_all"});
    assert!(
        parse_policy_authorization_input(&serde_json::to_vec(&unknown).unwrap())
            .unwrap_err()
            .to_string()
            .contains("unknown")
    );

    let over = vec![b' '; MAX_POLICY_AUTHORIZATION_INPUT_BYTES + 1];
    assert!(
        parse_policy_authorization_input(&over)
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
    let over = vec![b' '; MAX_POLICY_AUTHORIZATION_OUTPUT_BYTES + 1];
    assert!(
        parse_policy_authorization(&over)
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
    let over = vec![b' '; MAX_POLICY_AUTHORIZATION_VERIFICATION_INPUT_BYTES + 1];
    assert!(
        parse_policy_authorization_verification_input(&over)
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );

    let verify = verification_input(&input);
    let verify_bytes = serde_json::to_vec(&verify).unwrap();
    parse_policy_authorization_verification_input(&verify_bytes).unwrap();
    let verify_text = String::from_utf8(verify_bytes).unwrap();
    let duplicate = verify_text.replacen(
        "\"schema\":\"zerker.reason.policy-authorization-verification-input.v1\"",
        "\"schema\":\"zerker.reason.policy-authorization-verification-input.v0\",\"schema\":\"zerker.reason.policy-authorization-verification-input.v1\"",
        1,
    );
    assert!(
        parse_policy_authorization_verification_input(duplicate.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("duplicate object member `schema`")
    );
}

#[test]
fn policy_authorization_rejects_numbers_that_would_change_during_parsing() {
    let fixture = include_str!("../examples/policy-authorization-input.json");
    let marker = "\"ticket_id\": \"T-42\"";

    for canonical in ["0", "0.0", "-0.0", "1.5", "9007199254740993"] {
        let input = fixture.replacen(marker, &format!("\"ticket_id\": {canonical}"), 1);
        let parsed = parse_policy_authorization_input(input.as_bytes())
            .unwrap_or_else(|error| panic!("rejected canonical number {canonical}: {error}"));
        assert_eq!(
            parsed.action.arguments["ticket_id"].to_string(),
            canonical,
            "changed canonical number {canonical}"
        );
    }

    for noncanonical in [
        "-0",
        "1e0",
        "1.00",
        "0.10000000000000001",
        "9007199254740993.0",
    ] {
        let input = fixture.replacen(marker, &format!("\"ticket_id\": {noncanonical}"), 1);
        let error = parse_policy_authorization_input(input.as_bytes())
            .expect_err("a number that changes during parsing must fail closed")
            .to_string();
        assert!(
            error.contains("non-canonical JSON number"),
            "unexpected error for {noncanonical}: {error}"
        );
    }
}

#[test]
fn source_tree_mutation_is_separate_from_hot_path_bundle_authorization() {
    let root = tempfile::tempdir().unwrap();
    for path in ["AGENTS.md", "CLAUDE.md", ".agents/skills/support/SKILL.md"] {
        let target = root.path().join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(
            Path::new("tests/fixtures/policy-sources").join(path),
            target,
        )
        .unwrap();
    }
    let manifest =
        parse_policy_source_manifest(include_bytes!("../examples/policy-source-manifest.json"))
            .unwrap();
    let policy = base_policy();
    let bundle = lock_policy_bundle(root.path(), &manifest, &policy).unwrap();
    fs::remove_dir_all(root.path()).unwrap();

    let mut input = input_with_policy(&policy);
    input.policy_bundle = bundle;
    assert_eq!(
        authorize_policy(&input).unwrap().authorization_status,
        AuthorizationStatus::Authorized
    );
}
