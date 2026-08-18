use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Atom, AuthorityPolicy, Fact, Ontology, Predicate, Program, ReasonError, Rule, ScalarType,
    action::{ACTION_REQUEST_SCHEMA, ActionEffect, ActionRequest, Mission, ProposedAction},
};

pub const RELEASE_AUTHORIZATION_SCHEMA: &str = "zerker.reason.release-authorization.v1";
const RELEASE_POLICY_SCHEMA: &str = "zerker.reason.program.v2";
const TOOL_REPORTED: &str = "tool-reported";
const HUMAN_AUTHORIZED: &str = "human-authorized";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReleaseAuthorizationInput {
    pub schema: String,
    pub evaluation_time: String,
    pub mission: ReleaseMission,
    pub release: ReleaseTarget,
    #[serde(default)]
    pub evidence: ReleaseEvidence,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReleaseMission {
    pub id: String,
    pub principal: String,
    pub instruction_digest: String,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReleaseTarget {
    pub action_id: String,
    pub tool: String,
    pub version: String,
    pub commit: String,
    pub environment: String,
    pub artifact_digest: String,
    pub required_approver: String,
    pub proposed_at: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ReleaseEvidence {
    #[serde(default)]
    pub tests: Vec<CommitDecisionEvidence>,
    #[serde(default)]
    pub security_reviews: Vec<CommitDecisionEvidence>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEvidence>,
    #[serde(default)]
    pub approvals: Vec<ApprovalEvidence>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommitDecisionEvidence {
    pub id: String,
    pub commit: String,
    pub status: DecisionStatus,
    pub authority: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtifactEvidence {
    pub id: String,
    pub commit: String,
    pub digest: String,
    pub authority: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApprovalEvidence {
    pub id: String,
    pub version: String,
    pub commit: String,
    pub environment: String,
    pub artifact_digest: String,
    pub tool: String,
    pub approver: String,
    pub status: ApprovalStatus,
    pub authority: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Approved,
    Denied,
}

pub fn compile_release_authorization(
    input: &ReleaseAuthorizationInput,
) -> Result<ActionRequest, ReasonError> {
    if input.schema != RELEASE_AUTHORIZATION_SCHEMA {
        return Err(ReasonError::InvalidAction(format!(
            "$.schema: expected {RELEASE_AUTHORIZATION_SCHEMA:?}, got {:?}",
            input.schema
        )));
    }

    let target = &input.release;
    validate_release_target(target)?;
    let mut classes = BTreeSet::from([TOOL_REPORTED.to_owned(), HUMAN_AUTHORIZED.to_owned()]);
    for authority in evidence_authorities(&input.evidence) {
        classes.insert(authority.to_owned());
    }

    let predicates = BTreeMap::from([
        ("tests_passed".to_owned(), string_predicate(1)),
        ("security_reviewed".to_owned(), string_predicate(1)),
        ("artifact_built".to_owned(), string_predicate(2)),
        ("release_approved".to_owned(), string_predicate(6)),
    ]);
    let predicate_admit = BTreeMap::from([
        (
            "tests_passed".to_owned(),
            BTreeSet::from([TOOL_REPORTED.to_owned()]),
        ),
        (
            "artifact_built".to_owned(),
            BTreeSet::from([TOOL_REPORTED.to_owned()]),
        ),
        (
            "security_reviewed".to_owned(),
            BTreeSet::from([HUMAN_AUTHORIZED.to_owned()]),
        ),
        (
            "release_approved".to_owned(),
            BTreeSet::from([HUMAN_AUTHORIZED.to_owned()]),
        ),
    ]);

    let mut facts = Vec::new();
    for tests in &input.evidence.tests {
        facts.push(decision_fact("tests_passed", tests));
    }
    for review in &input.evidence.security_reviews {
        facts.push(decision_fact("security_reviewed", review));
    }
    for artifact in &input.evidence.artifacts {
        facts.push(Fact {
            id: artifact.id.clone(),
            atom: Atom {
                predicate: "artifact_built".to_owned(),
                arguments: vec![
                    Value::String(artifact.commit.clone()),
                    Value::String(artifact.digest.clone()),
                ],
                negated: false,
            },
            authority: artifact.authority.clone(),
            observed_at: Some(artifact.observed_at.clone()),
            valid_from: None,
            valid_until: artifact.valid_until.clone(),
            supersedes: artifact.supersedes.clone(),
        });
    }
    for approval in &input.evidence.approvals {
        facts.push(Fact {
            id: approval.id.clone(),
            atom: Atom {
                predicate: "release_approved".to_owned(),
                arguments: vec![
                    Value::String(approval.version.clone()),
                    Value::String(approval.commit.clone()),
                    Value::String(approval.environment.clone()),
                    Value::String(approval.artifact_digest.clone()),
                    Value::String(approval.tool.clone()),
                    Value::String(approval.approver.clone()),
                ],
                negated: approval.status == ApprovalStatus::Denied,
            },
            authority: approval.authority.clone(),
            observed_at: Some(approval.observed_at.clone()),
            valid_from: None,
            valid_until: approval.valid_until.clone(),
            supersedes: approval.supersedes.clone(),
        });
    }

    let action_id = Value::String(target.action_id.clone());
    let commit = Value::String(target.commit.clone());
    let version = Value::String(target.version.clone());
    let environment = Value::String(target.environment.clone());
    let artifact_digest = Value::String(target.artifact_digest.clone());
    let approver = Value::String(target.required_approver.clone());

    let authorize_rule = Rule {
        id: "release.authorize".to_owned(),
        when: vec![
            atom("mission_active", vec![json!("$mission")], false),
            atom(
                "mission_action",
                vec![json!("$mission"), action_id.clone()],
                false,
            ),
            atom(
                "mission_principal",
                vec![json!("$mission"), json!(input.mission.principal)],
                false,
            ),
            atom(
                "mission_constraint",
                vec![json!("$mission"), json!("commit"), commit.clone()],
                false,
            ),
            atom(
                "mission_constraint",
                vec![json!("$mission"), json!("version"), version.clone()],
                false,
            ),
            atom(
                "mission_constraint",
                vec![json!("$mission"), json!("environment"), environment.clone()],
                false,
            ),
            atom(
                "mission_constraint",
                vec![
                    json!("$mission"),
                    json!("artifact_digest"),
                    artifact_digest.clone(),
                ],
                false,
            ),
            atom(
                "action_tool",
                vec![action_id.clone(), json!(target.tool)],
                false,
            ),
            action_argument(&action_id, "commit", &commit),
            action_argument(&action_id, "version", &version),
            action_argument(&action_id, "environment", &environment),
            action_argument(&action_id, "artifact_digest", &artifact_digest),
            atom(
                "action_effect",
                vec![
                    action_id.clone(),
                    json!("deploy"),
                    json!(format!("release:{}", target.version)),
                    environment.clone(),
                ],
                false,
            ),
            atom("tests_passed", vec![commit.clone()], false),
            atom("security_reviewed", vec![commit.clone()], false),
            atom(
                "artifact_built",
                vec![commit.clone(), artifact_digest.clone()],
                false,
            ),
            atom(
                "release_approved",
                vec![
                    version.clone(),
                    commit.clone(),
                    environment.clone(),
                    artifact_digest.clone(),
                    Value::String(target.tool.clone()),
                    approver.clone(),
                ],
                false,
            ),
        ],
        then: atom("action_authorized", vec![action_id.clone()], false),
    };

    let deny_rules = vec![
        deny_rule(
            "release.deny.failed-tests",
            atom("tests_passed", vec![commit.clone()], true),
            &action_id,
        ),
        deny_rule(
            "release.deny.rejected-security-review",
            atom("security_reviewed", vec![commit.clone()], true),
            &action_id,
        ),
        deny_rule(
            "release.deny.rejected-approval",
            atom(
                "release_approved",
                vec![
                    version,
                    commit,
                    environment,
                    artifact_digest,
                    Value::String(target.tool.clone()),
                    approver,
                ],
                true,
            ),
            &action_id,
        ),
    ];

    let mut rules = vec![authorize_rule];
    rules.extend(deny_rules);

    Ok(ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.to_owned(),
        mission: Mission {
            id: input.mission.id.clone(),
            principal: input.mission.principal.clone(),
            instruction_digest: input.mission.instruction_digest.clone(),
            issued_at: input.mission.issued_at.clone(),
            valid_until: input.mission.valid_until.clone(),
            constraints: BTreeMap::from([
                ("commit".to_owned(), json!(target.commit)),
                ("version".to_owned(), json!(target.version)),
                ("environment".to_owned(), json!(target.environment)),
                ("artifact_digest".to_owned(), json!(target.artifact_digest)),
            ]),
        },
        action: ProposedAction {
            id: target.action_id.clone(),
            tool: target.tool.clone(),
            proposed_at: target.proposed_at.clone(),
            arguments: BTreeMap::from([
                ("commit".to_owned(), json!(target.commit)),
                ("version".to_owned(), json!(target.version)),
                ("environment".to_owned(), json!(target.environment)),
                ("artifact_digest".to_owned(), json!(target.artifact_digest)),
            ]),
            effects: vec![ActionEffect {
                kind: "deploy".to_owned(),
                resource: format!("release:{}", target.version),
                value: Some(json!(target.environment)),
            }],
        },
        policy: Program {
            schema: RELEASE_POLICY_SCHEMA.to_owned(),
            ontology: Ontology {
                id: "zerker.release-safety".to_owned(),
                version: "1".to_owned(),
                predicates,
            },
            authority: AuthorityPolicy {
                classes,
                default_admit: BTreeSet::new(),
                predicate_admit,
            },
            evaluation_time: Some(input.evaluation_time.clone()),
            facts,
            rules,
            query: atom("action_authorized", vec![action_id], false),
        },
    })
}

fn evidence_authorities(evidence: &ReleaseEvidence) -> impl Iterator<Item = &str> {
    evidence
        .tests
        .iter()
        .map(|value| value.authority.as_str())
        .chain(
            evidence
                .security_reviews
                .iter()
                .map(|value| value.authority.as_str()),
        )
        .chain(
            evidence
                .artifacts
                .iter()
                .map(|value| value.authority.as_str()),
        )
        .chain(
            evidence
                .approvals
                .iter()
                .map(|value| value.authority.as_str()),
        )
}

fn string_predicate(arguments: usize) -> Predicate {
    Predicate {
        arguments: vec![ScalarType::String; arguments],
    }
}

fn decision_fact(predicate: &str, evidence: &CommitDecisionEvidence) -> Fact {
    Fact {
        id: evidence.id.clone(),
        atom: atom(
            predicate,
            vec![Value::String(evidence.commit.clone())],
            evidence.status == DecisionStatus::Failed,
        ),
        authority: evidence.authority.clone(),
        observed_at: Some(evidence.observed_at.clone()),
        valid_from: None,
        valid_until: evidence.valid_until.clone(),
        supersedes: evidence.supersedes.clone(),
    }
}

fn validate_release_target(target: &ReleaseTarget) -> Result<(), ReasonError> {
    let required = [
        ("$.release.action_id", target.action_id.as_str()),
        ("$.release.tool", target.tool.as_str()),
        ("$.release.version", target.version.as_str()),
        ("$.release.commit", target.commit.as_str()),
        ("$.release.environment", target.environment.as_str()),
        (
            "$.release.required_approver",
            target.required_approver.as_str(),
        ),
    ];
    let mut errors = required
        .into_iter()
        .filter(|(_, value)| value.trim().is_empty())
        .map(|(path, _)| format!("{path}: must not be empty"))
        .collect::<Vec<_>>();
    if !valid_sha256(&target.artifact_digest) {
        errors.push("$.release.artifact_digest: expected sha256 followed by 64 lowercase hexadecimal characters".to_owned());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ReasonError::InvalidAction(errors.join("\n")))
    }
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn atom(predicate: &str, arguments: Vec<Value>, negated: bool) -> Atom {
    Atom {
        predicate: predicate.to_owned(),
        arguments,
        negated,
    }
}

fn action_argument(action_id: &Value, key: &str, value: &Value) -> Atom {
    atom(
        "action_argument",
        vec![action_id.clone(), json!(key), value.clone()],
        false,
    )
}

fn deny_rule(id: &str, evidence: Atom, action_id: &Value) -> Rule {
    Rule {
        id: id.to_owned(),
        when: vec![evidence],
        then: atom("action_authorized", vec![action_id.clone()], true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{AuthorizationStatus, authorize, verify_authorization};

    fn ready_input() -> ReleaseAuthorizationInput {
        serde_json::from_str(include_str!("../examples/release-authorization.json")).unwrap()
    }

    #[test]
    fn compiles_and_authorizes_an_exact_release() {
        let request = compile_release_authorization(&ready_input()).unwrap();
        let result = authorize(&request).unwrap();
        assert_eq!(result.status, AuthorizationStatus::Authorized);
        verify_authorization(&request, &result).unwrap();
    }

    #[test]
    fn missing_approval_is_insufficient_evidence() {
        let mut input = ready_input();
        input.evidence.approvals.clear();
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
        assert!(result.issues.iter().any(|issue| {
            issue
                .atom
                .as_ref()
                .is_some_and(|atom| atom.predicate == "release_approved")
        }));
    }

    #[test]
    fn failed_tests_explicitly_deny_the_release() {
        let mut input = ready_input();
        input.evidence.tests[0].status = DecisionStatus::Failed;
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::Denied);
    }

    #[test]
    fn evidence_for_another_commit_does_not_authorize_the_release() {
        let mut input = ready_input();
        input.evidence.tests[0].commit = "commit_old".to_owned();
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
    }

    #[test]
    fn approval_for_another_commit_cannot_be_reused() {
        let mut input = ready_input();
        input.evidence.approvals[0].commit = "commit_old".to_owned();
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
    }

    #[test]
    fn approval_for_another_tool_cannot_be_reused() {
        let mut input = ready_input();
        input.evidence.approvals[0].tool = "another_deploy_tool".to_owned();
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
    }

    #[test]
    fn agent_proposed_approval_is_withheld() {
        let mut input = ready_input();
        input.evidence.approvals[0].authority = "agent-proposed".to_owned();
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::InsufficientEvidence);
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.code == "authority_withheld")
        );
    }

    #[test]
    fn opposing_governed_approvals_conflict() {
        let mut input = ready_input();
        let mut denial = input.evidence.approvals[0].clone();
        denial.id = "evidence_approval_150_denied".to_owned();
        denial.status = ApprovalStatus::Denied;
        denial.observed_at = "2026-08-18T09:31:00Z".to_owned();
        input.evidence.approvals.push(denial);
        let result = authorize(&compile_release_authorization(&input).unwrap()).unwrap();
        assert_eq!(result.status, AuthorizationStatus::Conflicted);
    }
}
