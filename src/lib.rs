use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod action;

pub const PROGRAM_SCHEMA: &str = "zerker.reason.program.v1";
pub const PROGRAM_SCHEMA_V2: &str = "zerker.reason.program.v2";
pub const RESULT_SCHEMA: &str = "zerker.reason.result.v1";
pub const RESULT_SCHEMA_V2: &str = "zerker.reason.result.v2";
pub const VERIFICATION_SCHEMA: &str = "zerker.reason.verification.v1";
pub const VERIFICATION_SCHEMA_V2: &str = "zerker.reason.verification.v2";
const MAX_ROUNDS: usize = 1_024;

type Bindings = BTreeMap<String, Value>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Program {
    pub schema: String,
    pub ontology: Ontology,
    pub authority: AuthorityPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_time: Option<String>,
    #[serde(default)]
    pub facts: Vec<Fact>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    pub query: Atom,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ontology {
    pub id: String,
    pub version: String,
    pub predicates: BTreeMap<String, Predicate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Predicate {
    pub arguments: Vec<ScalarType>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorityPolicy {
    pub classes: BTreeSet<String>,
    pub default_admit: BTreeSet<String>,
    #[serde(default)]
    pub predicate_admit: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Fact {
    pub id: String,
    #[serde(flatten)]
    pub atom: Atom,
    pub authority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub when: Vec<Atom>,
    pub then: Atom,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Atom {
    pub predicate: String,
    #[serde(default)]
    pub arguments: Vec<Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub negated: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckResult {
    pub schema: String,
    pub status: Status,
    pub query: Atom,
    pub program_digest: String,
    pub ontology: OntologyRef,
    pub authority: AuthorityReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal: Option<TemporalReport>,
    pub proof: Option<Proof>,
    pub disproof: Option<Proof>,
    pub conflict: Option<ConflictWitness>,
    pub missing: Vec<Atom>,
    pub assumptions: Vec<String>,
    pub metrics: Metrics,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Proved,
    Disproved,
    Inconsistent,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OntologyRef {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proof {
    pub root: String,
    pub nodes: Vec<ProofNode>,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ConflictWitness {
    pub query: Atom,
    pub complement: Atom,
    pub fact_ids: Vec<String>,
    pub proof_digests: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofNode {
    pub id: String,
    pub kind: ProofNodeKind,
    pub atom: Atom,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal: Option<FactTemporal>,
    pub premises: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProofNodeKind {
    Fact,
    Derivation,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct AuthorityReport {
    pub policy_digest: String,
    pub admitted_fact_ids: Vec<String>,
    pub withheld: Vec<WithheldFact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct WithheldFact {
    pub fact_id: String,
    pub atom: Atom,
    pub authority: String,
    pub admitted_authorities: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TemporalReport {
    pub evaluation_time: String,
    pub eligible_fact_ids: Vec<String>,
    pub withheld: Vec<TemporallyWithheldFact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TemporallyWithheldFact {
    pub fact_id: String,
    pub atom: Atom,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub superseded_by: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct FactTemporal {
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Metrics {
    pub facts_supplied: usize,
    pub facts_admitted: usize,
    pub facts_withheld: usize,
    pub facts_derived: usize,
    pub rules_evaluated: usize,
    pub rounds: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    pub schema: String,
    pub status: VerificationStatus,
    pub result_status: Status,
    pub query: Atom,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluation_time: Option<String>,
    pub proof_digests: Vec<String>,
    pub nodes_verified: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
}

#[derive(Debug, Error)]
pub enum ReasonError {
    #[error("invalid program:\n{0}")]
    InvalidProgram(String),
    #[error("reasoning did not converge after {MAX_ROUNDS} rounds")]
    ResourceLimit,
    #[error("invalid action authorization request:\n{0}")]
    InvalidAction(String),
    #[error("authorization verification failed:\n{0}")]
    InvalidAuthorization(String),
    #[error("proof verification failed:\n{0}")]
    InvalidProof(String),
    #[error("failed to serialize canonical reasoning material: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
enum Derivation {
    Fact {
        fact_id: String,
        authority: String,
        temporal: Option<FactTemporal>,
    },
    Rule {
        rule_id: String,
        premises: Vec<String>,
    },
}

#[derive(Debug, Clone)]
struct KnownAtom {
    atom: Atom,
    derivation: Derivation,
}

pub fn validate(program: &Program) -> Result<(), ReasonError> {
    let mut errors = Vec::new();
    let is_v2 = program.schema == PROGRAM_SCHEMA_V2;
    if program.schema != PROGRAM_SCHEMA && !is_v2 {
        errors.push(format!(
            "$.schema: expected {PROGRAM_SCHEMA:?} or {PROGRAM_SCHEMA_V2:?}, got {:?}",
            program.schema
        ));
    }
    match (&program.evaluation_time, is_v2) {
        (Some(value), true) => validate_timestamp(value, "$.evaluation_time", &mut errors),
        (None, true) => errors.push("$.evaluation_time: required by program.v2".to_owned()),
        (Some(_), false) => errors.push(
            "$.evaluation_time: temporal fields require schema zerker.reason.program.v2".to_owned(),
        ),
        (None, false) => {}
    }
    if program.ontology.id.trim().is_empty() {
        errors.push("$.ontology.id: must not be empty".to_owned());
    }
    if program.ontology.version.trim().is_empty() {
        errors.push("$.ontology.version: must not be empty".to_owned());
    }
    if program.authority.classes.is_empty() {
        errors.push("$.authority.classes: declare at least one authority class".to_owned());
    }
    for class in &program.authority.classes {
        if !valid_authority_name(class) {
            errors.push(format!(
                "$.authority.classes: invalid authority class {class:?}; use lowercase letters, digits, and internal hyphens"
            ));
        }
    }
    validate_admitted_authorities(
        &program.authority.default_admit,
        &program.authority.classes,
        "$.authority.default_admit",
        &mut errors,
    );
    for (predicate, admitted) in &program.authority.predicate_admit {
        if !program.ontology.predicates.contains_key(predicate) {
            errors.push(format!(
                "$.authority.predicate_admit.{predicate}: predicate is not declared in the ontology"
            ));
        }
        validate_admitted_authorities(
            admitted,
            &program.authority.classes,
            &format!("$.authority.predicate_admit.{predicate}"),
            &mut errors,
        );
    }

    let mut ids = BTreeSet::new();
    let mut fact_atoms = BTreeMap::<String, String>::new();
    for (index, fact) in program.facts.iter().enumerate() {
        if fact.id.trim().is_empty() {
            errors.push(format!("$.facts[{index}].id: must not be empty"));
        } else if !ids.insert(fact.id.clone()) {
            errors.push(format!("$.facts[{index}].id: duplicate id {:?}", fact.id));
        }
        if !program.authority.classes.contains(&fact.authority) {
            errors.push(format!(
                "$.facts[{index}].authority: undeclared authority {:?}; add it to $.authority.classes",
                fact.authority
            ));
        }
        match atom_key(&fact.atom) {
            Ok(key) => {
                if let Some(existing_id) = fact_atoms.insert(key, fact.id.clone())
                    && !is_v2
                {
                    errors.push(format!(
                        "$.facts[{index}]: duplicates the atom from fact {existing_id:?}; combine provenance before reasoning"
                    ));
                }
            }
            Err(error) => errors.push(format!(
                "$.facts[{index}]: atom cannot be canonicalized: {error}"
            )),
        }
        validate_atom(
            &fact.atom,
            &program.ontology,
            false,
            &format!("$.facts[{index}]"),
            &mut errors,
        );
        if is_v2 {
            match &fact.observed_at {
                Some(value) => {
                    validate_timestamp(value, &format!("$.facts[{index}].observed_at"), &mut errors)
                }
                None => errors.push(format!(
                    "$.facts[{index}].observed_at: required by program.v2"
                )),
            }
            if let Some(value) = &fact.valid_from {
                validate_timestamp(value, &format!("$.facts[{index}].valid_from"), &mut errors);
            }
            if let Some(value) = &fact.valid_until {
                validate_timestamp(value, &format!("$.facts[{index}].valid_until"), &mut errors);
            }
            if let (Some(from), Some(until)) = (&fact.valid_from, &fact.valid_until)
                && canonical_timestamp(from).is_some()
                && canonical_timestamp(until).is_some()
                && from >= until
            {
                errors.push(format!(
                    "$.facts[{index}]: valid_from must be earlier than valid_until"
                ));
            }
            let mut targets = BTreeSet::new();
            for target in &fact.supersedes {
                if !targets.insert(target) {
                    errors.push(format!(
                        "$.facts[{index}].supersedes: duplicate fact id {target:?}"
                    ));
                }
                if target == &fact.id {
                    errors.push(format!(
                        "$.facts[{index}].supersedes: a fact cannot supersede itself"
                    ));
                }
            }
        } else if fact.observed_at.is_some()
            || fact.valid_from.is_some()
            || fact.valid_until.is_some()
            || !fact.supersedes.is_empty()
        {
            errors.push(format!(
                "$.facts[{index}]: temporal fields require schema zerker.reason.program.v2"
            ));
        }
    }

    if is_v2 {
        validate_supersession(program, &mut errors);
    }

    for (index, rule) in program.rules.iter().enumerate() {
        if rule.id.trim().is_empty() {
            errors.push(format!("$.rules[{index}].id: must not be empty"));
        } else if !ids.insert(rule.id.clone()) {
            errors.push(format!("$.rules[{index}].id: duplicate id {:?}", rule.id));
        }
        let mut body_variables = BTreeSet::new();
        for (atom_index, atom) in rule.when.iter().enumerate() {
            validate_atom(
                atom,
                &program.ontology,
                true,
                &format!("$.rules[{index}].when[{atom_index}]"),
                &mut errors,
            );
            collect_variables(atom, &mut body_variables);
        }
        validate_atom(
            &rule.then,
            &program.ontology,
            true,
            &format!("$.rules[{index}].then"),
            &mut errors,
        );
        let mut head_variables = BTreeSet::new();
        collect_variables(&rule.then, &mut head_variables);
        for variable in head_variables.difference(&body_variables) {
            errors.push(format!(
                "$.rules[{index}].then: variable {variable:?} is not bound in the rule body"
            ));
        }
    }

    validate_atom(
        &program.query,
        &program.ontology,
        false,
        "$.query",
        &mut errors,
    );

    if errors.is_empty() && is_v2 {
        validate_temporal_uniqueness(program, &mut errors)?;
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ReasonError::InvalidProgram(errors.join("\n")))
    }
}

fn canonical_timestamp(value: &str) -> Option<String> {
    let parsed = DateTime::parse_from_rfc3339(value).ok()?;
    let canonical = parsed.to_utc().to_rfc3339_opts(SecondsFormat::Secs, true);
    (canonical == value).then_some(canonical)
}

fn validate_timestamp(value: &str, path: &str, errors: &mut Vec<String>) {
    if canonical_timestamp(value).is_none() {
        errors.push(format!(
            "{path}: expected canonical UTC RFC 3339 seconds, for example 2026-08-14T12:00:00Z"
        ));
    }
}

fn same_claim(left: &Atom, right: &Atom) -> bool {
    left.predicate == right.predicate && left.arguments == right.arguments
}

fn validate_supersession(program: &Program, errors: &mut Vec<String>) {
    let facts = program
        .facts
        .iter()
        .map(|fact| (fact.id.as_str(), fact))
        .collect::<BTreeMap<_, _>>();
    for (index, fact) in program.facts.iter().enumerate() {
        for target_id in &fact.supersedes {
            let Some(target) = facts.get(target_id.as_str()) else {
                errors.push(format!(
                    "$.facts[{index}].supersedes: fact {target_id:?} does not exist"
                ));
                continue;
            };
            if !same_claim(&fact.atom, &target.atom) {
                errors.push(format!(
                    "$.facts[{index}].supersedes: fact {target_id:?} is about a different predicate or arguments"
                ));
            }
            if let (Some(observed), Some(target_observed)) =
                (&fact.observed_at, &target.observed_at)
                && canonical_timestamp(observed).is_some()
                && canonical_timestamp(target_observed).is_some()
                && observed <= target_observed
            {
                errors.push(format!(
                    "$.facts[{index}].supersedes: observed_at must be later than fact {target_id:?}"
                ));
            }
        }
    }
}

fn validate_temporal_uniqueness(
    program: &Program,
    errors: &mut Vec<String>,
) -> Result<(), ReasonError> {
    let report = build_temporal_report(program)?
        .expect("program.v2 with valid evaluation_time has a temporal report");
    let eligible = report
        .eligible_fact_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut atoms = BTreeMap::<String, String>::new();
    for fact in &program.facts {
        if !eligible.contains(fact.id.as_str()) {
            continue;
        }
        let key = atom_key(&fact.atom)?;
        if let Some(existing) = atoms.insert(key, fact.id.clone()) {
            errors.push(format!(
                "$.facts: active facts {existing:?} and {:?} duplicate the same atom; supersede one explicitly",
                fact.id
            ));
        }
    }
    Ok(())
}

fn valid_authority_name(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_admitted_authorities(
    admitted: &BTreeSet<String>,
    classes: &BTreeSet<String>,
    path: &str,
    errors: &mut Vec<String>,
) {
    for authority in admitted {
        if !classes.contains(authority) {
            errors.push(format!(
                "{path}: undeclared authority {authority:?}; add it to $.authority.classes"
            ));
        }
    }
}

fn validate_atom(
    atom: &Atom,
    ontology: &Ontology,
    variables_allowed: bool,
    path: &str,
    errors: &mut Vec<String>,
) {
    let Some(predicate) = ontology.predicates.get(&atom.predicate) else {
        errors.push(format!(
            "{path}.predicate: unknown predicate {:?}; declare it in $.ontology.predicates",
            atom.predicate
        ));
        return;
    };
    if predicate.arguments.len() != atom.arguments.len() {
        errors.push(format!(
            "{path}.arguments: predicate {:?} expects {} arguments, got {}",
            atom.predicate,
            predicate.arguments.len(),
            atom.arguments.len()
        ));
        return;
    }
    for (index, (value, expected)) in atom
        .arguments
        .iter()
        .zip(predicate.arguments.iter())
        .enumerate()
    {
        if variable_name(value).is_some() {
            if !variables_allowed {
                errors.push(format!(
                    "{path}.arguments[{index}]: variables are not allowed here"
                ));
            }
            continue;
        }
        let valid = match expected {
            ScalarType::String => value.is_string(),
            ScalarType::Integer => value.as_i64().is_some(),
            ScalarType::Boolean => value.is_boolean(),
        };
        if !valid {
            errors.push(format!(
                "{path}.arguments[{index}]: expected {}, got {}",
                scalar_name(*expected),
                value_kind(value)
            ));
        }
    }
}

fn scalar_name(value: ScalarType) -> &'static str {
    match value {
        ScalarType::String => "string",
        ScalarType::Integer => "integer",
        ScalarType::Boolean => "boolean",
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn collect_variables(atom: &Atom, variables: &mut BTreeSet<String>) {
    for value in &atom.arguments {
        if let Some(name) = variable_name(value) {
            variables.insert(name.to_owned());
        }
    }
}

fn variable_name(value: &Value) -> Option<&str> {
    value
        .as_str()?
        .strip_prefix('$')
        .filter(|name| !name.is_empty())
}

fn admitted_authorities<'a>(policy: &'a AuthorityPolicy, predicate: &str) -> &'a BTreeSet<String> {
    policy
        .predicate_admit
        .get(predicate)
        .unwrap_or(&policy.default_admit)
}

fn authority_admits(policy: &AuthorityPolicy, fact: &Fact) -> bool {
    admitted_authorities(policy, &fact.atom.predicate).contains(&fact.authority)
}

fn result_schema(program: &Program) -> &'static str {
    if program.schema == PROGRAM_SCHEMA_V2 {
        RESULT_SCHEMA_V2
    } else {
        RESULT_SCHEMA
    }
}

fn verification_schema(program: &Program) -> &'static str {
    if program.schema == PROGRAM_SCHEMA_V2 {
        VERIFICATION_SCHEMA_V2
    } else {
        VERIFICATION_SCHEMA
    }
}

fn fact_temporal(program: &Program, fact: &Fact) -> Option<FactTemporal> {
    (program.schema == PROGRAM_SCHEMA_V2).then(|| FactTemporal {
        observed_at: fact
            .observed_at
            .clone()
            .expect("validated program.v2 facts have observed_at"),
        valid_from: fact.valid_from.clone(),
        valid_until: fact.valid_until.clone(),
        supersedes: fact.supersedes.clone(),
    })
}

fn build_authority_report(program: &Program) -> Result<AuthorityReport, ReasonError> {
    let mut facts = program.facts.iter().collect::<Vec<_>>();
    facts.sort_by(|a, b| a.id.cmp(&b.id));
    let mut admitted_fact_ids = Vec::new();
    let mut withheld = Vec::new();
    for fact in facts {
        let admitted = admitted_authorities(&program.authority, &fact.atom.predicate);
        if admitted.contains(&fact.authority) {
            admitted_fact_ids.push(fact.id.clone());
        } else {
            withheld.push(WithheldFact {
                fact_id: fact.id.clone(),
                atom: fact.atom.clone(),
                authority: fact.authority.clone(),
                admitted_authorities: admitted.iter().cloned().collect(),
                reason: format!(
                    "authority {:?} is not admitted for predicate {:?}",
                    fact.authority, fact.atom.predicate
                ),
            });
        }
    }
    Ok(AuthorityReport {
        policy_digest: digest(&program.authority)?,
        admitted_fact_ids,
        withheld,
    })
}

fn build_temporal_report(program: &Program) -> Result<Option<TemporalReport>, ReasonError> {
    if program.schema != PROGRAM_SCHEMA_V2 {
        return Ok(None);
    }
    let evaluation_time = program
        .evaluation_time
        .clone()
        .expect("validated program.v2 has evaluation_time");
    let mut facts = program.facts.iter().collect::<Vec<_>>();
    facts.sort_by(|left, right| left.id.cmp(&right.id));

    let mut base_eligible = BTreeSet::new();
    let mut time_reasons = BTreeMap::<String, String>::new();
    for fact in &facts {
        if !authority_admits(&program.authority, fact) {
            continue;
        }
        let observed_at = fact
            .observed_at
            .as_ref()
            .expect("validated program.v2 fact has observed_at");
        let reason = if observed_at > &evaluation_time {
            Some(format!(
                "observed_at {observed_at} is after evaluation_time {evaluation_time}"
            ))
        } else if fact
            .valid_from
            .as_ref()
            .is_some_and(|valid_from| valid_from > &evaluation_time)
        {
            Some(format!(
                "valid_from {} is after evaluation_time {evaluation_time}",
                fact.valid_from.as_deref().unwrap_or_default()
            ))
        } else if fact
            .valid_until
            .as_ref()
            .is_some_and(|valid_until| valid_until <= &evaluation_time)
        {
            Some(format!(
                "valid_until {} is at or before evaluation_time {evaluation_time}",
                fact.valid_until.as_deref().unwrap_or_default()
            ))
        } else {
            None
        };
        if let Some(reason) = reason {
            time_reasons.insert(fact.id.clone(), reason);
        } else {
            base_eligible.insert(fact.id.clone());
        }
    }

    let mut superseded_by = BTreeMap::<String, BTreeSet<String>>::new();
    for fact in &facts {
        if !base_eligible.contains(&fact.id) {
            continue;
        }
        for target in &fact.supersedes {
            if base_eligible.contains(target) {
                superseded_by
                    .entry(target.clone())
                    .or_default()
                    .insert(fact.id.clone());
            }
        }
    }

    let eligible_fact_ids = base_eligible
        .iter()
        .filter(|id| !superseded_by.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();
    let mut withheld = Vec::new();
    for fact in facts {
        if !authority_admits(&program.authority, fact)
            || eligible_fact_ids.binary_search(&fact.id).is_ok()
        {
            continue;
        }
        let superseders = superseded_by
            .get(&fact.id)
            .map(|values| values.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let reason = time_reasons
            .get(&fact.id)
            .cloned()
            .unwrap_or_else(|| format!("superseded by {}", superseders.join(", ")));
        withheld.push(TemporallyWithheldFact {
            fact_id: fact.id.clone(),
            atom: fact.atom.clone(),
            reason,
            superseded_by: superseders,
        });
    }

    Ok(Some(TemporalReport {
        evaluation_time,
        eligible_fact_ids,
        withheld,
    }))
}

pub fn check(program: &Program) -> Result<CheckResult, ReasonError> {
    validate(program)?;

    let program_digest = digest(program)?;
    let ontology_digest = digest(&program.ontology)?;
    let authority = build_authority_report(program)?;
    let temporal = build_temporal_report(program)?;
    let temporally_eligible = temporal.as_ref().map(|report| {
        report
            .eligible_fact_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    });
    let mut known = BTreeMap::<String, KnownAtom>::new();
    let mut facts = program.facts.clone();
    facts.sort_by(|a, b| a.id.cmp(&b.id));
    for fact in &facts {
        if !authority_admits(&program.authority, fact)
            || temporally_eligible
                .as_ref()
                .is_some_and(|eligible| !eligible.contains(fact.id.as_str()))
        {
            continue;
        }
        known
            .entry(atom_key(&fact.atom)?)
            .or_insert_with(|| KnownAtom {
                atom: fact.atom.clone(),
                derivation: Derivation::Fact {
                    fact_id: fact.id.clone(),
                    authority: fact.authority.clone(),
                    temporal: fact_temporal(program, fact),
                },
            });
    }

    let initial_count = known.len();
    let mut rules = program.rules.clone();
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    let mut rule_evaluations = 0;
    let mut rounds = 0;

    loop {
        if rounds == MAX_ROUNDS {
            return Err(ReasonError::ResourceLimit);
        }
        rounds += 1;
        let snapshot: Vec<(String, Atom)> = known
            .iter()
            .map(|(key, value)| (key.clone(), value.atom.clone()))
            .collect();
        let mut additions = Vec::<(String, KnownAtom)>::new();

        for rule in &rules {
            rule_evaluations += 1;
            for (bindings, premises) in satisfy(&rule.when, &snapshot) {
                let atom = instantiate(&rule.then, &bindings);
                let key = atom_key(&atom)?;
                if !known.contains_key(&key)
                    && !additions.iter().any(|(candidate, _)| candidate == &key)
                {
                    additions.push((
                        key,
                        KnownAtom {
                            atom,
                            derivation: Derivation::Rule {
                                rule_id: rule.id.clone(),
                                premises,
                            },
                        },
                    ));
                }
            }
        }

        if additions.is_empty() {
            break;
        }
        additions.sort_by(|a, b| a.0.cmp(&b.0));
        known.extend(additions);
    }

    let query_key = atom_key(&program.query)?;
    let complement = complement(&program.query);
    let complement_key = atom_key(&complement)?;
    let proof = if known.contains_key(&query_key) {
        Some(build_proof(&query_key, &known)?)
    } else {
        None
    };
    let disproof = if known.contains_key(&complement_key) {
        Some(build_proof(&complement_key, &known)?)
    } else {
        None
    };
    let status = match (proof.is_some(), disproof.is_some()) {
        (true, false) => Status::Proved,
        (false, true) => Status::Disproved,
        (true, true) => Status::Inconsistent,
        (false, false) => Status::Unknown,
    };
    let conflict = match (&proof, &disproof) {
        (Some(proof), Some(disproof)) => Some(build_conflict_witness(
            &program.query,
            &complement,
            proof,
            disproof,
        )),
        _ => None,
    };
    let missing = if proof.is_none() {
        explain_missing(&program.query, &rules, &known)?
    } else {
        Vec::new()
    };

    Ok(CheckResult {
        schema: result_schema(program).to_owned(),
        status,
        query: program.query.clone(),
        program_digest,
        ontology: OntologyRef {
            id: program.ontology.id.clone(),
            version: program.ontology.version.clone(),
            digest: ontology_digest,
        },
        authority: authority.clone(),
        temporal,
        proof,
        disproof,
        conflict,
        missing,
        assumptions: vec![
            "Only facts admitted by the explicit authority policy participate in inference."
                .to_owned(),
            "Explicit negation does not use absence as evidence of falsity.".to_owned(),
            "Contradictory support is preserved as inconsistent instead of resolved silently."
                .to_owned(),
        ],
        metrics: Metrics {
            facts_supplied: facts.len(),
            facts_admitted: initial_count,
            facts_withheld: facts.len() - initial_count,
            facts_derived: known.len() - initial_count,
            rules_evaluated: rule_evaluations,
            rounds,
        },
    })
}

fn satisfy(patterns: &[Atom], known: &[(String, Atom)]) -> Vec<(Bindings, Vec<String>)> {
    let mut states = vec![(Bindings::new(), Vec::new())];
    for pattern in patterns {
        let mut next = Vec::new();
        for (bindings, premises) in states {
            for (key, fact) in known {
                if let Some(updated) = match_atom(pattern, fact, &bindings) {
                    let mut updated_premises = premises.clone();
                    updated_premises.push(key.clone());
                    next.push((updated, updated_premises));
                }
            }
        }
        states = next;
        if states.is_empty() {
            break;
        }
    }
    states
}

fn match_atom(pattern: &Atom, fact: &Atom, bindings: &Bindings) -> Option<Bindings> {
    if pattern.predicate != fact.predicate
        || pattern.negated != fact.negated
        || pattern.arguments.len() != fact.arguments.len()
    {
        return None;
    }
    let mut result = bindings.clone();
    for (pattern_value, fact_value) in pattern.arguments.iter().zip(&fact.arguments) {
        if let Some(variable) = variable_name(pattern_value) {
            if let Some(bound) = result.get(variable) {
                if bound != fact_value {
                    return None;
                }
            } else {
                result.insert(variable.to_owned(), fact_value.clone());
            }
        } else if pattern_value != fact_value {
            return None;
        }
    }
    Some(result)
}

fn instantiate(pattern: &Atom, bindings: &Bindings) -> Atom {
    Atom {
        predicate: pattern.predicate.clone(),
        arguments: pattern
            .arguments
            .iter()
            .map(|value| {
                variable_name(value)
                    .and_then(|name| bindings.get(name))
                    .cloned()
                    .unwrap_or_else(|| value.clone())
            })
            .collect(),
        negated: pattern.negated,
    }
}

fn complement(atom: &Atom) -> Atom {
    let mut complement = atom.clone();
    complement.negated = !complement.negated;
    complement
}

fn explain_missing(
    query: &Atom,
    rules: &[Rule],
    known: &BTreeMap<String, KnownAtom>,
) -> Result<Vec<Atom>, ReasonError> {
    let mut missing = BTreeMap::<String, Atom>::new();
    for rule in rules {
        let Some(bindings) = match_atom(&rule.then, query, &Bindings::new()) else {
            continue;
        };
        for requirement in &rule.when {
            let ground = instantiate(requirement, &bindings);
            if ground
                .arguments
                .iter()
                .any(|value| variable_name(value).is_some())
            {
                continue;
            }
            let key = atom_key(&ground)?;
            if !known.contains_key(&key) {
                missing.insert(key, ground);
            }
        }
    }
    Ok(missing.into_values().collect())
}

fn build_conflict_witness(
    query: &Atom,
    complement: &Atom,
    proof: &Proof,
    disproof: &Proof,
) -> ConflictWitness {
    let fact_ids = proof
        .nodes
        .iter()
        .chain(disproof.nodes.iter())
        .filter(|node| node.kind == ProofNodeKind::Fact)
        .filter_map(|node| node.source_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ConflictWitness {
        query: query.clone(),
        complement: complement.clone(),
        fact_ids,
        proof_digests: vec![proof.digest.clone(), disproof.digest.clone()],
    }
}

fn build_proof(root_key: &str, known: &BTreeMap<String, KnownAtom>) -> Result<Proof, ReasonError> {
    let mut nodes = BTreeMap::<String, ProofNode>::new();
    let root = collect_proof(root_key, known, &mut nodes)?;
    let nodes: Vec<ProofNode> = nodes.into_values().collect();
    let proof_digest = proof_digest(&root, &nodes)?;
    Ok(Proof {
        root,
        nodes,
        digest: proof_digest,
    })
}

fn collect_proof(
    key: &str,
    known: &BTreeMap<String, KnownAtom>,
    nodes: &mut BTreeMap<String, ProofNode>,
) -> Result<String, ReasonError> {
    let known_atom = known
        .get(key)
        .expect("proof roots are drawn from known atoms");
    let id = node_id(&known_atom.atom)?;
    if nodes.contains_key(&id) {
        return Ok(id);
    }
    let (kind, source_id, authority, temporal, premise_keys) = match &known_atom.derivation {
        Derivation::Fact {
            fact_id,
            authority,
            temporal,
        } => (
            ProofNodeKind::Fact,
            Some(fact_id.clone()),
            Some(authority.clone()),
            temporal.clone(),
            Vec::new(),
        ),
        Derivation::Rule { rule_id, premises } => (
            ProofNodeKind::Derivation,
            Some(rule_id.clone()),
            None,
            None,
            premises.clone(),
        ),
    };
    let mut premise_ids = Vec::new();
    for premise in premise_keys {
        premise_ids.push(collect_proof(&premise, known, nodes)?);
    }
    nodes.insert(
        id.clone(),
        ProofNode {
            id: id.clone(),
            kind,
            atom: known_atom.atom.clone(),
            source_id,
            authority,
            temporal,
            premises: premise_ids,
        },
    );
    Ok(id)
}

pub fn verify(program: &Program, result: &CheckResult) -> Result<VerificationResult, ReasonError> {
    validate(program)?;
    let expected_result_schema = result_schema(program);
    if result.schema != expected_result_schema {
        return invalid_proof(format!(
            "$.schema: expected {expected_result_schema:?}, got {:?}",
            result.schema
        ));
    }
    if result.query != program.query {
        return invalid_proof("$.query: does not match the program query");
    }
    let expected_program_digest = digest(program)?;
    if result.program_digest != expected_program_digest {
        return invalid_proof(format!(
            "$.program_digest: mismatch; expected {expected_program_digest}"
        ));
    }

    let expected_ontology_digest = digest(&program.ontology)?;
    if result.ontology.id != program.ontology.id
        || result.ontology.version != program.ontology.version
        || result.ontology.digest != expected_ontology_digest
    {
        return invalid_proof(
            "$.ontology: identity, version, or digest does not match the program",
        );
    }

    let expected_authority = build_authority_report(program)?;
    if result.authority != expected_authority {
        return invalid_proof("$.authority: report does not match the program authority policy");
    }
    let expected_temporal = build_temporal_report(program)?;
    if result.temporal != expected_temporal {
        return invalid_proof("$.temporal: report does not match the program evaluation time");
    }
    let temporally_eligible = expected_temporal.as_ref().map(|report| {
        report
            .eligible_fact_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    });

    let expected_complement = complement(&program.query);
    let facts: BTreeMap<&str, &Fact> = program
        .facts
        .iter()
        .map(|fact| (fact.id.as_str(), fact))
        .collect();
    let rules: BTreeMap<&str, &Rule> = program
        .rules
        .iter()
        .map(|rule| (rule.id.as_str(), rule))
        .collect();

    let (expected_proof, expected_disproof) = match result.status {
        Status::Proved => (true, false),
        Status::Disproved => (false, true),
        Status::Inconsistent => (true, true),
        Status::Unknown => {
            return invalid_proof(
                "$.status: unknown has no derivation certificate; rerun check against the program",
            );
        }
    };
    if result.proof.is_some() != expected_proof || result.disproof.is_some() != expected_disproof {
        return invalid_proof("$.status: does not match the presence of proof and disproof");
    }

    let mut proof_digests = Vec::new();
    let mut nodes_verified = 0;
    if let Some(proof) = &result.proof {
        nodes_verified += verify_one_proof(
            proof,
            &program.query,
            "$.proof",
            &facts,
            &rules,
            program,
            temporally_eligible.as_ref(),
        )?;
        proof_digests.push(proof.digest.clone());
    }
    if let Some(disproof) = &result.disproof {
        nodes_verified += verify_one_proof(
            disproof,
            &expected_complement,
            "$.disproof",
            &facts,
            &rules,
            program,
            temporally_eligible.as_ref(),
        )?;
        proof_digests.push(disproof.digest.clone());
    }

    match (
        &result.status,
        &result.conflict,
        &result.proof,
        &result.disproof,
    ) {
        (Status::Inconsistent, Some(conflict), Some(proof), Some(disproof)) => {
            let expected =
                build_conflict_witness(&program.query, &expected_complement, proof, disproof);
            if conflict != &expected {
                return invalid_proof("$.conflict: witness does not match the two proofs");
            }
        }
        (Status::Inconsistent, _, _, _) => {
            return invalid_proof("$.conflict: inconsistent result requires a conflict witness");
        }
        (_, Some(_), _, _) => {
            return invalid_proof("$.conflict: only an inconsistent result may contain a witness");
        }
        _ => {}
    }

    Ok(VerificationResult {
        schema: verification_schema(program).to_owned(),
        status: VerificationStatus::Verified,
        result_status: result.status.clone(),
        query: result.query.clone(),
        evaluation_time: program.evaluation_time.clone(),
        proof_digests,
        nodes_verified,
    })
}

fn verify_one_proof(
    proof: &Proof,
    expected_atom: &Atom,
    path: &str,
    facts: &BTreeMap<&str, &Fact>,
    rules: &BTreeMap<&str, &Rule>,
    program: &Program,
    temporally_eligible: Option<&BTreeSet<&str>>,
) -> Result<usize, ReasonError> {
    let expected_digest = proof_digest(&proof.root, &proof.nodes)?;
    if proof.digest != expected_digest {
        return invalid_proof(format!(
            "{path}.digest: mismatch; expected {expected_digest}"
        ));
    }
    if !proof.nodes.windows(2).all(|pair| pair[0].id < pair[1].id) {
        return invalid_proof(format!("{path}.nodes: must be uniquely sorted by node id"));
    }

    let nodes: BTreeMap<&str, &ProofNode> = proof
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    if nodes.len() != proof.nodes.len() {
        return invalid_proof(format!("{path}.nodes: duplicate node id"));
    }
    let root = nodes
        .get(proof.root.as_str())
        .ok_or_else(|| ReasonError::InvalidProof(format!("{path}.root: node does not exist")))?;
    if &root.atom != expected_atom {
        return invalid_proof(format!("{path}.root: conclusion does not match"));
    }

    let context = VerificationContext {
        facts,
        rules,
        program,
        temporally_eligible,
    };
    let mut visiting = BTreeSet::new();
    let mut verified = BTreeSet::new();
    verify_node(
        proof.root.as_str(),
        &nodes,
        &context,
        &mut visiting,
        &mut verified,
    )?;
    if verified.len() != nodes.len() {
        return invalid_proof(format!(
            "{path}.nodes: contains nodes unreachable from the proof root"
        ));
    }
    Ok(verified.len())
}

struct VerificationContext<'a> {
    facts: &'a BTreeMap<&'a str, &'a Fact>,
    rules: &'a BTreeMap<&'a str, &'a Rule>,
    program: &'a Program,
    temporally_eligible: Option<&'a BTreeSet<&'a str>>,
}

fn verify_node<'a>(
    id: &'a str,
    nodes: &BTreeMap<&'a str, &'a ProofNode>,
    context: &VerificationContext<'_>,
    visiting: &mut BTreeSet<&'a str>,
    verified: &mut BTreeSet<&'a str>,
) -> Result<(), ReasonError> {
    if verified.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id) {
        return invalid_proof(format!("$.proof.nodes[{id}]: derivation cycle detected"));
    }
    let node = nodes
        .get(id)
        .ok_or_else(|| ReasonError::InvalidProof(format!("proof node {id:?} does not exist")))?;
    let expected_id = node_id(&node.atom)?;
    if node.id != expected_id {
        return invalid_proof(format!(
            "proof node {:?}: id does not match its atom; expected {expected_id}",
            node.id
        ));
    }

    match node.kind {
        ProofNodeKind::Fact => {
            if !node.premises.is_empty() {
                return invalid_proof(format!(
                    "proof node {:?}: a fact cannot have premises",
                    node.id
                ));
            }
            let source_id = node.source_id.as_deref().ok_or_else(|| {
                ReasonError::InvalidProof(format!(
                    "proof node {:?}: missing fact source_id",
                    node.id
                ))
            })?;
            let fact = context.facts.get(source_id).ok_or_else(|| {
                ReasonError::InvalidProof(format!(
                    "proof node {:?}: fact source {source_id:?} does not exist",
                    node.id
                ))
            })?;
            if node.atom != fact.atom {
                return invalid_proof(format!(
                    "proof node {:?}: atom does not match fact {source_id:?}",
                    node.id
                ));
            }
            if node.authority.as_deref() != Some(fact.authority.as_str()) {
                return invalid_proof(format!(
                    "proof node {:?}: authority does not match fact {source_id:?}",
                    node.id
                ));
            }
            if !authority_admits(&context.program.authority, fact) {
                return invalid_proof(format!(
                    "proof node {:?}: fact {source_id:?} is withheld by the authority policy",
                    node.id
                ));
            }
            if context
                .temporally_eligible
                .is_some_and(|eligible| !eligible.contains(source_id))
            {
                return invalid_proof(format!(
                    "proof node {:?}: fact {source_id:?} is temporally ineligible",
                    node.id
                ));
            }
            if node.temporal != fact_temporal(context.program, fact) {
                return invalid_proof(format!(
                    "proof node {:?}: temporal certificate does not match fact {source_id:?}",
                    node.id
                ));
            }
        }
        ProofNodeKind::Derivation => {
            if node.temporal.is_some() {
                return invalid_proof(format!(
                    "proof node {:?}: derived nodes cannot declare fact temporal evidence",
                    node.id
                ));
            }
            if node.authority.is_some() {
                return invalid_proof(format!(
                    "proof node {:?}: derived nodes cannot declare fact authority",
                    node.id
                ));
            }
            let source_id = node.source_id.as_deref().ok_or_else(|| {
                ReasonError::InvalidProof(format!(
                    "proof node {:?}: missing rule source_id",
                    node.id
                ))
            })?;
            let rule = context.rules.get(source_id).ok_or_else(|| {
                ReasonError::InvalidProof(format!(
                    "proof node {:?}: rule source {source_id:?} does not exist",
                    node.id
                ))
            })?;
            if node.premises.len() != rule.when.len() {
                return invalid_proof(format!(
                    "proof node {:?}: rule {source_id:?} expects {} premises, got {}",
                    node.id,
                    rule.when.len(),
                    node.premises.len()
                ));
            }
            let mut bindings = Bindings::new();
            for (index, (pattern, premise_id)) in
                rule.when.iter().zip(node.premises.iter()).enumerate()
            {
                verify_node(premise_id, nodes, context, visiting, verified)?;
                let premise = nodes.get(premise_id.as_str()).ok_or_else(|| {
                    ReasonError::InvalidProof(format!(
                        "proof node {:?}: premise {premise_id:?} does not exist",
                        node.id
                    ))
                })?;
                bindings = match_atom(pattern, &premise.atom, &bindings).ok_or_else(|| {
                    ReasonError::InvalidProof(format!(
                        "proof node {:?}: premise {index} does not satisfy rule {source_id:?}",
                        node.id
                    ))
                })?;
            }
            if instantiate(&rule.then, &bindings) != node.atom {
                return invalid_proof(format!(
                    "proof node {:?}: conclusion does not follow from rule {source_id:?}",
                    node.id
                ));
            }
        }
    }

    visiting.remove(id);
    verified.insert(id);
    Ok(())
}

fn invalid_proof<T>(message: impl Into<String>) -> Result<T, ReasonError> {
    Err(ReasonError::InvalidProof(message.into()))
}

fn atom_key(atom: &Atom) -> Result<String, serde_json::Error> {
    serde_json::to_string(atom)
}

fn node_id(atom: &Atom) -> Result<String, serde_json::Error> {
    Ok(format!("node_{}", hex_sha256(atom_key(atom)?.as_bytes())))
}

fn proof_digest(root: &str, nodes: &[ProofNode]) -> Result<String, serde_json::Error> {
    digest(&serde_json::json!({"root": root, "nodes": nodes}))
}

pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("sha256:{}", hex_sha256(&bytes)))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-ready.json")).unwrap()
    }

    fn untrusted_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-untrusted.json")).unwrap()
    }

    fn disproved_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-disproved.json")).unwrap()
    }

    fn inconsistent_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-inconsistent.json")).unwrap()
    }

    fn expired_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-expired.json")).unwrap()
    }

    fn superseded_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-superseded.json")).unwrap()
    }

    fn overlapping_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-overlap.json")).unwrap()
    }

    fn wrong_commit_release_program() -> Program {
        serde_json::from_str(include_str!("../examples/release-wrong-commit.json")).unwrap()
    }

    #[test]
    fn proves_release_readiness_with_a_deterministic_proof() {
        let first = check(&release_program()).unwrap();
        let second = check(&release_program()).unwrap();
        assert_eq!(first.status, Status::Proved);
        assert_eq!(
            first.proof.as_ref().unwrap().digest,
            second.proof.as_ref().unwrap().digest
        );
    }

    #[test]
    fn preserves_the_v1_contract_without_temporal_material() {
        let program = release_program();
        let result = check(&program).unwrap();
        assert_eq!(result.schema, RESULT_SCHEMA);
        assert!(result.temporal.is_none());
        assert!(
            result
                .proof
                .as_ref()
                .unwrap()
                .nodes
                .iter()
                .all(|node| node.temporal.is_none())
        );
        assert_eq!(
            verify(&program, &result).unwrap().schema,
            VERIFICATION_SCHEMA
        );
    }

    #[test]
    fn reports_unknown_instead_of_false() {
        let mut program = release_program();
        program
            .facts
            .retain(|fact| fact.atom.predicate != "approved");
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Unknown);
        assert!(result.proof.is_none());
        assert!(
            result
                .missing
                .iter()
                .any(|atom| atom.predicate == "approved")
        );
    }

    #[test]
    fn expired_evidence_is_withheld_at_the_half_open_boundary() {
        let program = expired_release_program();
        let result = check(&program).unwrap();
        assert_eq!(result.schema, RESULT_SCHEMA_V2);
        assert_eq!(result.status, Status::Unknown);
        let temporal = result.temporal.as_ref().unwrap();
        assert_eq!(temporal.evaluation_time, "2026-08-14T12:00:00Z");
        assert_eq!(temporal.withheld.len(), 1);
        assert_eq!(temporal.withheld[0].fact_id, "fact_approval_140");
        assert!(temporal.withheld[0].reason.contains("at or before"));
    }

    #[test]
    fn future_observations_cannot_enter_the_snapshot() {
        let mut program = expired_release_program();
        program.facts[2].valid_until = None;
        program.facts[2].observed_at = Some("2026-08-14T12:00:01Z".to_owned());
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Unknown);
        assert!(
            result.temporal.unwrap().withheld[0]
                .reason
                .contains("after evaluation_time")
        );
    }

    #[test]
    fn admitted_newer_evidence_supersedes_the_old_claim() {
        let program = superseded_release_program();
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Disproved);
        let temporal = result.temporal.as_ref().unwrap();
        let old = temporal
            .withheld
            .iter()
            .find(|fact| fact.fact_id == "fact_review_abc_original")
            .unwrap();
        assert_eq!(old.superseded_by, vec!["fact_review_abc_revoked"]);
        assert_eq!(
            verify(&program, &result).unwrap().schema,
            VERIFICATION_SCHEMA_V2
        );
    }

    #[test]
    fn untrusted_evidence_cannot_supersede_governed_evidence() {
        let mut program = superseded_release_program();
        program.facts[2].authority = "agent-proposed".to_owned();
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Proved);
        assert!(
            result
                .authority
                .withheld
                .iter()
                .any(|fact| fact.fact_id == "fact_review_abc_revoked")
        );
        assert!(
            !result
                .temporal
                .unwrap()
                .withheld
                .iter()
                .any(|fact| { fact.fact_id == "fact_review_abc_original" })
        );
    }

    #[test]
    fn evidence_for_an_old_commit_does_not_authorize_the_new_commit() {
        let result = check(&wrong_commit_release_program()).unwrap();
        assert_eq!(result.status, Status::Unknown);
        assert!(result.missing.iter().any(|atom| {
            atom.predicate == "tests_passed"
                && atom.arguments == vec![Value::String("commit_new".to_owned())]
        }));
        assert!(result.temporal.unwrap().withheld.is_empty());
    }

    #[test]
    fn overlapping_opposing_validity_intervals_are_inconsistent() {
        let program = overlapping_release_program();
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Inconsistent);
        assert_eq!(result.conflict.unwrap().fact_ids.len(), 2);
        assert!(result.temporal.unwrap().withheld.is_empty());
    }

    #[test]
    fn v2_rejects_noncanonical_timestamps() {
        let mut program = expired_release_program();
        program.evaluation_time = Some("2026-08-14T12:00:00+00:00".to_owned());
        let error = validate(&program).unwrap_err().to_string();
        assert!(error.contains("canonical UTC RFC 3339 seconds"));
    }

    #[test]
    fn active_duplicate_atoms_require_explicit_supersession() {
        let mut program = overlapping_release_program();
        let mut duplicate = program.facts[0].clone();
        duplicate.id = "fact_approval_140_new".to_owned();
        duplicate.observed_at = Some("2026-08-14T11:45:00Z".to_owned());
        duplicate.supersedes.clear();
        program.facts.push(duplicate.clone());
        let error = validate(&program).unwrap_err().to_string();
        assert!(error.contains("duplicate the same atom"));

        program.facts.last_mut().unwrap().supersedes = vec!["fact_approval_140".to_owned()];
        validate(&program).unwrap();
    }

    #[test]
    fn verifier_rejects_a_tampered_temporal_certificate() {
        let program = superseded_release_program();
        let mut result = check(&program).unwrap();
        let disproof = result.disproof.as_mut().unwrap();
        let fact = disproof
            .nodes
            .iter_mut()
            .find(|node| node.kind == ProofNodeKind::Fact)
            .unwrap();
        fact.temporal.as_mut().unwrap().observed_at = "2026-08-14T00:00:00Z".to_owned();
        disproof.digest = proof_digest(&disproof.root, &disproof.nodes).unwrap();
        let error = verify(&program, &result).unwrap_err().to_string();
        assert!(error.contains("temporal certificate does not match"));
    }

    #[test]
    fn explicit_negation_disproves_without_closed_world_assumptions() {
        let program = disproved_release_program();
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Disproved);
        assert!(result.proof.is_none());
        assert!(result.disproof.is_some());
        assert!(result.conflict.is_none());
        let verification = verify(&program, &result).unwrap();
        assert_eq!(verification.result_status, Status::Disproved);
    }

    #[test]
    fn preserves_both_sides_as_an_inconsistent_conflict_witness() {
        let program = inconsistent_release_program();
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Inconsistent);
        assert!(result.proof.is_some());
        assert!(result.disproof.is_some());
        let conflict = result.conflict.as_ref().unwrap();
        assert_eq!(conflict.query, program.query);
        assert_eq!(conflict.complement, complement(&program.query));
        assert_eq!(conflict.proof_digests.len(), 2);
        assert!(
            conflict
                .fact_ids
                .contains(&"fact_release_blocked_140".to_owned())
        );
        let verification = verify(&program, &result).unwrap();
        assert_eq!(verification.result_status, Status::Inconsistent);
        assert_eq!(verification.proof_digests.len(), 2);
    }

    #[test]
    fn verifier_rejects_a_tampered_conflict_witness() {
        let program = inconsistent_release_program();
        let mut result = check(&program).unwrap();
        result.conflict.as_mut().unwrap().fact_ids.pop();
        let error = verify(&program, &result).unwrap_err().to_string();
        assert!(error.contains("conflict: witness does not match"));
    }

    #[test]
    fn verifier_rejects_a_status_that_hides_opposing_support() {
        let program = inconsistent_release_program();
        let mut result = check(&program).unwrap();
        result.status = Status::Proved;
        let error = verify(&program, &result).unwrap_err().to_string();
        assert!(error.contains("status: does not match"));
    }

    #[test]
    fn contradiction_does_not_entail_an_unrelated_query() {
        let mut program = inconsistent_release_program();
        program.ontology.predicates.insert(
            "deployment_allowed".to_owned(),
            Predicate {
                arguments: vec![ScalarType::String],
            },
        );
        program.query = Atom {
            predicate: "deployment_allowed".to_owned(),
            arguments: vec![Value::String("production".to_owned())],
            negated: false,
        };
        let result = check(&program).unwrap();
        assert_eq!(result.status, Status::Unknown);
    }

    #[test]
    fn withholds_an_agent_proposed_approval() {
        let result = check(&untrusted_release_program()).unwrap();
        assert_eq!(result.status, Status::Unknown);
        assert_eq!(result.authority.withheld.len(), 1);
        assert_eq!(result.authority.withheld[0].fact_id, "fact_approval_140");
        assert_eq!(result.authority.withheld[0].authority, "agent-proposed");
        assert_eq!(
            result.authority.withheld[0].admitted_authorities,
            vec!["human-authorized"]
        );
        assert!(
            result
                .missing
                .iter()
                .any(|atom| atom.predicate == "approved")
        );
    }

    #[test]
    fn rejects_an_undeclared_authority_class() {
        let mut program = release_program();
        program.facts[0].authority = "mystery-source".to_owned();
        let error = validate(&program).unwrap_err().to_string();
        assert!(error.contains("undeclared authority"));
    }

    #[test]
    fn rejects_duplicate_atoms_instead_of_picking_authority_by_fact_order() {
        let mut program = release_program();
        let mut duplicate = program.facts[0].clone();
        duplicate.id = "fact_tests_duplicate".to_owned();
        duplicate.authority = "human-authorized".to_owned();
        program.facts.push(duplicate);
        let error = validate(&program).unwrap_err().to_string();
        assert!(error.contains("duplicates the atom"));
    }

    #[test]
    fn independently_verifies_a_generated_proof() {
        let program = release_program();
        let result = check(&program).unwrap();
        let verification = verify(&program, &result).unwrap();
        assert_eq!(verification.nodes_verified, 4);
    }

    #[test]
    fn rejects_tampered_fact_authority_even_with_a_recomputed_digest() {
        let program = release_program();
        let mut result = check(&program).unwrap();
        let proof = result.proof.as_mut().unwrap();
        let fact = proof
            .nodes
            .iter_mut()
            .find(|node| node.kind == ProofNodeKind::Fact)
            .unwrap();
        fact.authority = Some("agent-proposed".to_owned());
        proof.digest = proof_digest(&proof.root, &proof.nodes).unwrap();
        let error = verify(&program, &result).unwrap_err().to_string();
        assert!(error.contains("authority does not match"));
    }

    #[test]
    fn verifier_rejects_a_fact_withheld_by_a_changed_policy() {
        let program = release_program();
        let mut result = check(&program).unwrap();
        let mut changed = release_program();
        changed.authority.predicate_admit.insert(
            "approved".to_owned(),
            BTreeSet::from(["agent-proposed".to_owned()]),
        );
        result.program_digest = digest(&changed).unwrap();
        result.authority = build_authority_report(&changed).unwrap();
        let error = verify(&changed, &result).unwrap_err().to_string();
        assert!(error.contains("withheld by the authority policy"));
    }

    #[test]
    fn rejects_a_proof_digest_mismatch() {
        let program = release_program();
        let mut result = check(&program).unwrap();
        result.proof.as_mut().unwrap().digest = "sha256:tampered".to_owned();
        let error = verify(&program, &result).unwrap_err().to_string();
        assert!(error.contains("digest: mismatch"));
    }

    #[test]
    fn rejects_a_different_program_even_when_the_used_atoms_still_match() {
        let program = release_program();
        let result = check(&program).unwrap();
        let mut changed = release_program();
        changed.rules[0].id = "renamed_rule".to_owned();
        let error = verify(&changed, &result).unwrap_err().to_string();
        assert!(error.contains("program_digest: mismatch"));
    }
}
