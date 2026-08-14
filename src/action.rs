use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Atom, CheckResult, Fact, Predicate, Program, ReasonError, ScalarType, Status, check, digest,
    verify,
};

pub const ACTION_REQUEST_SCHEMA: &str = "zerker.reason.action.v1";
pub const AUTHORIZATION_RESULT_SCHEMA: &str = "zerker.reason.authorization.v1";
pub const AUTHORIZATION_VERIFICATION_SCHEMA: &str = "zerker.reason.authorization-verification.v1";
const POLICY_SCHEMA: &str = "zerker.reason.program.v2";
const SYSTEM_AUTHORITY: &str = "system-bound";
const SYSTEM_FACT_PREFIX: &str = "zerker.action.binding.";
const AUTHORIZATION_PREDICATE: &str = "action_authorized";

const RESERVED_PREDICATES: &[(&str, usize)] = &[
    (AUTHORIZATION_PREDICATE, 1),
    ("mission_active", 1),
    ("mission_action", 2),
    ("mission_principal", 2),
    ("mission_instruction", 2),
    ("mission_constraint", 3),
    ("action_tool", 2),
    ("action_argument", 3),
    ("action_effect", 4),
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionRequest {
    pub schema: String,
    pub mission: Mission,
    pub action: ProposedAction,
    pub policy: Program,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Mission {
    pub id: String,
    pub principal: String,
    pub instruction_digest: String,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub constraints: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProposedAction {
    pub id: String,
    pub tool: String,
    pub proposed_at: String,
    #[serde(default)]
    pub arguments: BTreeMap<String, Value>,
    #[serde(default)]
    pub effects: Vec<ActionEffect>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ActionEffect {
    pub kind: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationResult {
    pub schema: String,
    pub status: AuthorizationStatus,
    pub request_digest: String,
    pub mission: BoundObject,
    pub action: BoundAction,
    pub reasoning: CheckResult,
    pub issues: Vec<AuthorizationIssue>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BoundObject {
    pub id: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BoundAction {
    pub id: String,
    pub digest: String,
    pub tool: String,
    pub arguments: BTreeMap<String, Value>,
    pub effects: Vec<ActionEffect>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Authorized,
    Denied,
    Conflicted,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AuthorizationIssue {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atom: Option<Atom>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationVerification {
    pub schema: String,
    pub status: &'static str,
    pub authorization_status: AuthorizationStatus,
    pub request_digest: String,
    pub reasoning_result_digest: String,
}

pub fn authorize(request: &ActionRequest) -> Result<AuthorizationResult, ReasonError> {
    validate_action_request(request)?;
    let program = effective_program(request)?;
    let reasoning = check(&program)?;
    let status = authorization_status(&reasoning.status);
    let issues = authorization_issues(&reasoning, status);
    Ok(AuthorizationResult {
        schema: AUTHORIZATION_RESULT_SCHEMA.to_owned(),
        status,
        request_digest: digest(request)?,
        mission: BoundObject {
            id: request.mission.id.clone(),
            digest: digest(&request.mission)?,
        },
        action: BoundAction {
            id: request.action.id.clone(),
            digest: digest(&request.action)?,
            tool: request.action.tool.clone(),
            arguments: request.action.arguments.clone(),
            effects: request.action.effects.clone(),
        },
        reasoning,
        issues,
    })
}

pub fn verify_authorization(
    request: &ActionRequest,
    result: &AuthorizationResult,
) -> Result<AuthorizationVerification, ReasonError> {
    validate_action_request(request)?;
    if result.schema != AUTHORIZATION_RESULT_SCHEMA {
        return invalid_authorization(format!(
            "$.schema: expected {AUTHORIZATION_RESULT_SCHEMA:?}, got {:?}",
            result.schema
        ));
    }
    let expected_request_digest = digest(request)?;
    if result.request_digest != expected_request_digest {
        return invalid_authorization(format!(
            "$.request_digest: mismatch; expected {expected_request_digest}"
        ));
    }
    let expected_mission = BoundObject {
        id: request.mission.id.clone(),
        digest: digest(&request.mission)?,
    };
    if result.mission.id != expected_mission.id || result.mission.digest != expected_mission.digest
    {
        return invalid_authorization("$.mission: identity or digest mismatch");
    }
    let expected_action = BoundAction {
        id: request.action.id.clone(),
        digest: digest(&request.action)?,
        tool: request.action.tool.clone(),
        arguments: request.action.arguments.clone(),
        effects: request.action.effects.clone(),
    };
    if result.action.id != expected_action.id
        || result.action.digest != expected_action.digest
        || result.action.tool != expected_action.tool
        || result.action.arguments != expected_action.arguments
        || result.action.effects != expected_action.effects
    {
        return invalid_authorization("$.action: content or digest mismatch");
    }

    let program = effective_program(request)?;
    let expected_reasoning = check(&program)?;
    let expected_reasoning_digest = digest(&expected_reasoning)?;
    if digest(&result.reasoning)? != expected_reasoning_digest {
        return invalid_authorization("$.reasoning: result does not recompute from the request");
    }
    if result.reasoning.status != Status::Unknown {
        verify(&program, &result.reasoning)
            .map_err(|error| ReasonError::InvalidAuthorization(format!("$.reasoning: {error}")))?;
    }

    let expected_status = authorization_status(&expected_reasoning.status);
    if result.status != expected_status {
        return invalid_authorization("$.status: does not match the reasoning result");
    }
    let expected_issues = authorization_issues(&expected_reasoning, expected_status);
    if result.issues != expected_issues {
        return invalid_authorization("$.issues: do not match the reasoning result");
    }

    Ok(AuthorizationVerification {
        schema: AUTHORIZATION_VERIFICATION_SCHEMA.to_owned(),
        status: "verified",
        authorization_status: result.status,
        request_digest: expected_request_digest,
        reasoning_result_digest: expected_reasoning_digest,
    })
}

pub fn validate_action_request(request: &ActionRequest) -> Result<(), ReasonError> {
    let mut errors = Vec::new();
    if request.schema != ACTION_REQUEST_SCHEMA {
        errors.push(format!(
            "$.schema: expected {ACTION_REQUEST_SCHEMA:?}, got {:?}",
            request.schema
        ));
    }
    required(&request.mission.id, "$.mission.id", &mut errors);
    required(
        &request.mission.principal,
        "$.mission.principal",
        &mut errors,
    );
    if !valid_digest(&request.mission.instruction_digest) {
        errors.push(
            "$.mission.instruction_digest: expected sha256 followed by 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    required(&request.action.id, "$.action.id", &mut errors);
    required(&request.action.tool, "$.action.tool", &mut errors);
    for key in request.mission.constraints.keys() {
        required(key, "$.mission.constraints key", &mut errors);
    }
    for key in request.action.arguments.keys() {
        required(key, "$.action.arguments key", &mut errors);
    }
    for (index, effect) in request.action.effects.iter().enumerate() {
        required(
            &effect.kind,
            &format!("$.action.effects[{index}].kind"),
            &mut errors,
        );
        required(
            &effect.resource,
            &format!("$.action.effects[{index}].resource"),
            &mut errors,
        );
    }

    if request.policy.schema != POLICY_SCHEMA {
        errors.push(format!(
            "$.policy.schema: action authorization requires {POLICY_SCHEMA:?}"
        ));
    }
    if request.policy.authority.classes.contains(SYSTEM_AUTHORITY) {
        errors.push(format!(
            "$.policy.authority.classes: {SYSTEM_AUTHORITY:?} is reserved for request bindings"
        ));
    }
    for (predicate, _) in RESERVED_PREDICATES {
        if request.policy.ontology.predicates.contains_key(*predicate) {
            errors.push(format!(
                "$.policy.ontology.predicates.{predicate}: reserved for action authorization"
            ));
        }
        if request
            .policy
            .authority
            .predicate_admit
            .contains_key(*predicate)
        {
            errors.push(format!(
                "$.policy.authority.predicate_admit.{predicate}: reserved for action authorization"
            ));
        }
    }
    let reserved = RESERVED_PREDICATES
        .iter()
        .map(|(predicate, _)| *predicate)
        .collect::<BTreeSet<_>>();
    for (index, fact) in request.policy.facts.iter().enumerate() {
        if reserved.contains(fact.atom.predicate.as_str()) {
            errors.push(format!(
                "$.policy.facts[{index}].predicate: {:?} is reserved for request bindings",
                fact.atom.predicate
            ));
        }
        if fact.id.starts_with(SYSTEM_FACT_PREFIX) {
            errors.push(format!(
                "$.policy.facts[{index}].id: prefix {SYSTEM_FACT_PREFIX:?} is reserved"
            ));
        }
        if fact.authority == SYSTEM_AUTHORITY {
            errors.push(format!(
                "$.policy.facts[{index}].authority: {SYSTEM_AUTHORITY:?} is reserved"
            ));
        }
    }
    for (index, rule) in request.policy.rules.iter().enumerate() {
        if reserved.contains(rule.then.predicate.as_str())
            && rule.then.predicate != AUTHORIZATION_PREDICATE
        {
            errors.push(format!(
                "$.policy.rules[{index}].then.predicate: {:?} can only be supplied by request bindings",
                rule.then.predicate
            ));
        }
    }
    let expected_query = authorization_query(&request.action.id);
    if request.policy.query != expected_query {
        errors.push(format!(
            "$.policy.query: expected action_authorized({:?})",
            request.action.id
        ));
    }

    if !errors.is_empty() {
        return Err(ReasonError::InvalidAction(errors.join("\n")));
    }
    effective_program(request).and_then(|program| {
        crate::validate(&program).map_err(|error| ReasonError::InvalidAction(error.to_string()))
    })?;
    Ok(())
}

fn effective_program(request: &ActionRequest) -> Result<Program, ReasonError> {
    let mut program = request.policy.clone();
    program
        .authority
        .classes
        .insert(SYSTEM_AUTHORITY.to_owned());
    for (name, argument_count) in RESERVED_PREDICATES {
        program.ontology.predicates.insert(
            (*name).to_owned(),
            Predicate {
                arguments: vec![ScalarType::String; *argument_count],
            },
        );
        program.authority.predicate_admit.insert(
            (*name).to_owned(),
            BTreeSet::from([SYSTEM_AUTHORITY.to_owned()]),
        );
    }
    program.query = authorization_query(&request.action.id);

    let mission = &request.mission;
    let action = &request.action;
    program.facts.push(system_fact(
        "mission.active",
        Atom {
            predicate: "mission_active".to_owned(),
            arguments: vec![Value::String(mission.id.clone())],
            negated: false,
        },
        &mission.issued_at,
        mission.valid_until.clone(),
    ));
    program.facts.push(system_fact(
        "mission.action",
        string_atom("mission_action", [&mission.id, &action.id]),
        &action.proposed_at,
        mission.valid_until.clone(),
    ));
    program.facts.push(system_fact(
        "mission.principal",
        string_atom("mission_principal", [&mission.id, &mission.principal]),
        &mission.issued_at,
        mission.valid_until.clone(),
    ));
    program.facts.push(system_fact(
        "mission.instruction",
        string_atom(
            "mission_instruction",
            [&mission.id, &mission.instruction_digest],
        ),
        &mission.issued_at,
        mission.valid_until.clone(),
    ));
    for (key, value) in &mission.constraints {
        program.facts.push(system_fact(
            &format!("mission.constraint.{}", binding_digest(&(key, value))?),
            Atom {
                predicate: "mission_constraint".to_owned(),
                arguments: vec![
                    Value::String(mission.id.clone()),
                    Value::String(key.clone()),
                    Value::String(canonical_value(value)?),
                ],
                negated: false,
            },
            &mission.issued_at,
            mission.valid_until.clone(),
        ));
    }
    program.facts.push(system_fact(
        "action.tool",
        string_atom("action_tool", [&action.id, &action.tool]),
        &action.proposed_at,
        None,
    ));
    for (key, value) in &action.arguments {
        program.facts.push(system_fact(
            &format!("action.argument.{}", binding_digest(&(key, value))?),
            Atom {
                predicate: "action_argument".to_owned(),
                arguments: vec![
                    Value::String(action.id.clone()),
                    Value::String(key.clone()),
                    Value::String(canonical_value(value)?),
                ],
                negated: false,
            },
            &action.proposed_at,
            None,
        ));
    }
    for (index, effect) in action.effects.iter().enumerate() {
        program.facts.push(system_fact(
            &format!("action.effect.{index:04}"),
            Atom {
                predicate: "action_effect".to_owned(),
                arguments: vec![
                    Value::String(action.id.clone()),
                    Value::String(effect.kind.clone()),
                    Value::String(effect.resource.clone()),
                    Value::String(match &effect.value {
                        Some(value) => canonical_value(value)?,
                        None => "none:".to_owned(),
                    }),
                ],
                negated: false,
            },
            &action.proposed_at,
            None,
        ));
    }
    Ok(program)
}

fn authorization_status(status: &Status) -> AuthorizationStatus {
    match status {
        Status::Proved => AuthorizationStatus::Authorized,
        Status::Disproved => AuthorizationStatus::Denied,
        Status::Inconsistent => AuthorizationStatus::Conflicted,
        Status::Unknown => AuthorizationStatus::InsufficientEvidence,
    }
}

fn authorization_issues(
    result: &CheckResult,
    status: AuthorizationStatus,
) -> Vec<AuthorizationIssue> {
    let mut issues = Vec::new();
    match status {
        AuthorizationStatus::Authorized => {}
        AuthorizationStatus::Denied => issues.push(AuthorizationIssue {
            code: "explicit_denial".to_owned(),
            message: "The policy derives explicit denial for this exact action.".to_owned(),
            atom: Some(negated(result.query.clone())),
            fact_ids: Vec::new(),
        }),
        AuthorizationStatus::Conflicted => issues.push(AuthorizationIssue {
            code: "conflicting_authorization".to_owned(),
            message: "The policy derives both authorization and explicit denial; action must fail closed."
                .to_owned(),
            atom: Some(result.query.clone()),
            fact_ids: result
                .conflict
                .as_ref()
                .map(|conflict| conflict.fact_ids.clone())
                .unwrap_or_default(),
        }),
        AuthorizationStatus::InsufficientEvidence => {
            for atom in &result.missing {
                issues.push(AuthorizationIssue {
                    code: "missing_requirement".to_owned(),
                    message: "A required premise is not currently derivable.".to_owned(),
                    atom: Some(atom.clone()),
                    fact_ids: Vec::new(),
                });
            }
            if result.missing.is_empty() {
                issues.push(AuthorizationIssue {
                    code: "no_authorization_derivation".to_owned(),
                    message: "No authorization or explicit denial derivation was found.".to_owned(),
                    atom: Some(result.query.clone()),
                    fact_ids: Vec::new(),
                });
            }
        }
    }
    for withheld in &result.authority.withheld {
        issues.push(AuthorizationIssue {
            code: "authority_withheld".to_owned(),
            message: withheld.reason.clone(),
            atom: Some(withheld.atom.clone()),
            fact_ids: vec![withheld.fact_id.clone()],
        });
    }
    if let Some(temporal) = &result.temporal {
        for withheld in &temporal.withheld {
            issues.push(AuthorizationIssue {
                code: if withheld.superseded_by.is_empty() {
                    "temporally_ineligible"
                } else {
                    "superseded"
                }
                .to_owned(),
                message: withheld.reason.clone(),
                atom: Some(withheld.atom.clone()),
                fact_ids: std::iter::once(withheld.fact_id.clone())
                    .chain(withheld.superseded_by.iter().cloned())
                    .collect(),
            });
        }
    }
    issues
}

fn authorization_query(action_id: &str) -> Atom {
    Atom {
        predicate: AUTHORIZATION_PREDICATE.to_owned(),
        arguments: vec![Value::String(action_id.to_owned())],
        negated: false,
    }
}

fn system_fact(suffix: &str, atom: Atom, observed_at: &str, valid_until: Option<String>) -> Fact {
    Fact {
        id: format!("{SYSTEM_FACT_PREFIX}{suffix}"),
        atom,
        authority: SYSTEM_AUTHORITY.to_owned(),
        observed_at: Some(observed_at.to_owned()),
        valid_from: None,
        valid_until,
        supersedes: Vec::new(),
    }
}

fn string_atom<const N: usize>(predicate: &str, values: [&str; N]) -> Atom {
    Atom {
        predicate: predicate.to_owned(),
        arguments: values
            .into_iter()
            .map(|value| Value::String(value.to_owned()))
            .collect(),
        negated: false,
    }
}

fn canonical_value(value: &Value) -> Result<String, ReasonError> {
    let encoded = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => format!("number:{value}"),
        Value::Bool(value) => format!("boolean:{value}"),
        Value::Null => "null:".to_owned(),
        Value::Array(_) | Value::Object(_) => format!("json:{}", serde_json::to_string(value)?),
    };
    Ok(encoded)
}

fn binding_digest<T: Serialize>(value: &T) -> Result<String, ReasonError> {
    Ok(digest(value)?
        .strip_prefix("sha256:")
        .expect("internal digests use sha256")
        .to_owned())
}

fn negated(mut atom: Atom) -> Atom {
    atom.negated = !atom.negated;
    atom
}

fn required(value: &str, path: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{path}: must not be empty"));
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn invalid_authorization<T>(message: impl Into<String>) -> Result<T, ReasonError> {
    Err(ReasonError::InvalidAuthorization(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment_request() -> ActionRequest {
        serde_json::from_str(include_str!("../examples/authorize-deploy.json")).unwrap()
    }

    #[test]
    fn authorizes_and_independently_verifies_the_exact_action() {
        let request = deployment_request();
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::Authorized);
        assert!(result.issues.is_empty());
        let verification = verify_authorization(&request, &result).unwrap();
        assert_eq!(
            verification.authorization_status,
            AuthorizationStatus::Authorized
        );
    }

    #[test]
    fn changed_action_arguments_invalidate_the_certificate() {
        let request = deployment_request();
        let result = authorize(&request).unwrap();
        let mut changed = deployment_request();
        changed.action.arguments.insert(
            "environment".to_owned(),
            Value::String("staging".to_owned()),
        );
        let error = verify_authorization(&changed, &result)
            .unwrap_err()
            .to_string();
        assert!(error.contains("request_digest: mismatch"));
        assert_eq!(
            authorize(&changed).unwrap().status,
            AuthorizationStatus::InsufficientEvidence
        );
    }

    #[test]
    fn expired_approval_fails_closed_with_an_actionable_issue() {
        let mut request = deployment_request();
        request.policy.facts[2].valid_until = Some("2026-08-14T12:00:00Z".to_owned());
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
        assert!(result.issues.iter().any(|issue| {
            issue.code == "temporally_ineligible" && issue.fact_ids == vec!["fact_approval_140"]
        }));
        verify_authorization(&request, &result).unwrap();
    }

    #[test]
    fn untrusted_approval_cannot_authorize_deployment() {
        let mut request = deployment_request();
        request.policy.facts[2].authority = "agent-proposed".to_owned();
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
        assert!(result.issues.iter().any(|issue| {
            issue.code == "authority_withheld" && issue.fact_ids == vec!["fact_approval_140"]
        }));
    }

    #[test]
    fn explicit_negative_evidence_denies_the_action() {
        let mut request = deployment_request();
        request.policy.facts[1].atom.negated = true;
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::Denied);
        assert!(result.reasoning.disproof.is_some());
        verify_authorization(&request, &result).unwrap();
    }

    #[test]
    fn contradictory_governed_evidence_conflicts_and_fails_closed() {
        let mut request = deployment_request();
        let mut revoked = request.policy.facts[1].clone();
        revoked.id = "fact_review_abc_revoked".to_owned();
        revoked.atom.negated = true;
        revoked.observed_at = Some("2026-08-14T11:30:00Z".to_owned());
        request.policy.facts.push(revoked);
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::Conflicted);
        assert!(result.issues.iter().any(|issue| {
            issue.code == "conflicting_authorization"
                && issue.fact_ids.contains(&"fact_review_abc".to_owned())
                && issue
                    .fact_ids
                    .contains(&"fact_review_abc_revoked".to_owned())
        }));
        verify_authorization(&request, &result).unwrap();
    }

    #[test]
    fn expired_mission_cannot_authorize_an_action() {
        let mut request = deployment_request();
        request.mission.valid_until = Some("2026-08-14T12:00:00Z".to_owned());
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
        assert!(result.issues.iter().any(|issue| {
            issue.code == "temporally_ineligible"
                && issue
                    .fact_ids
                    .iter()
                    .any(|id| id == "zerker.action.binding.mission.active")
        }));
    }

    #[test]
    fn policy_cannot_spoof_system_bound_action_facts() {
        let mut request = deployment_request();
        request
            .policy
            .authority
            .classes
            .insert(SYSTEM_AUTHORITY.to_owned());
        let error = authorize(&request).unwrap_err().to_string();
        assert!(error.contains("reserved for request bindings"));
    }

    #[test]
    fn policy_rules_cannot_forge_request_bindings() {
        let mut request = deployment_request();
        request.policy.rules[0].then = Atom {
            predicate: "action_tool".to_owned(),
            arguments: vec![
                Value::String("action_deploy_140".to_owned()),
                Value::String("deploy_release".to_owned()),
            ],
            negated: false,
        };
        let error = authorize(&request).unwrap_err().to_string();
        assert!(error.contains("can only be supplied by request bindings"));
    }

    #[test]
    fn verifier_rejects_a_tampered_authorization_status() {
        let request = deployment_request();
        let mut result = authorize(&request).unwrap();
        result.status = AuthorizationStatus::Denied;
        let error = verify_authorization(&request, &result)
            .unwrap_err()
            .to_string();
        assert!(error.contains("status: does not match"));
    }
}
