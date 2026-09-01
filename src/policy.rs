use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::{
    AuthorityPolicy, Fact, Ontology, PROGRAM_SCHEMA_V2, Program, ReasonError, Rule,
    action::{
        ACTION_REQUEST_SCHEMA, AUTHORIZATION_BUNDLE_SCHEMA, ActionRequest, AuthorizationBundle,
        AuthorizationStatus, AuthorizationVerification, Mission, ProposedAction, authorize,
        validate_action_request, verify_authorization_bundle,
    },
    digest,
    strict_json::{parse_strict_json, validate_canonical_json_numbers},
};

pub const POLICY_SOURCE_MANIFEST_SCHEMA: &str = "zerker.reason.policy-source-manifest.v1";
pub const POLICY_TEMPLATE_SCHEMA: &str = "zerker.reason.policy-template.v1";
pub const POLICY_BUNDLE_SCHEMA: &str = "zerker.reason.policy-bundle.v1";
pub const POLICY_BUNDLE_COMMITMENT_SCHEMA: &str = "zerker.reason.policy-bundle-commitment.v1";
pub const POLICY_SOURCE_VERIFICATION_SCHEMA: &str = "zerker.reason.policy-source-verification.v1";
pub const POLICY_AUTHORIZATION_INPUT_SCHEMA: &str = "zerker.reason.policy-authorization-input.v1";
pub const POLICY_AUTHORIZATION_SCHEMA: &str = "zerker.reason.policy-authorization.v1";
pub const POLICY_AUTHORIZATION_VERIFICATION_INPUT_SCHEMA: &str =
    "zerker.reason.policy-authorization-verification-input.v1";

pub const MAX_POLICY_SOURCES: usize = 256;
pub const MAX_SOURCE_BYTES: u64 = 1 << 20;
pub const MAX_AGGREGATE_SOURCE_BYTES: u64 = 16 << 20;
pub const MAX_SOURCE_MANIFEST_BYTES: usize = 256 << 10;
pub const MAX_POLICY_TEMPLATE_BYTES: usize = 1 << 20;
pub const MAX_POLICY_BUNDLE_BYTES: usize = 2 << 20;
pub const MAX_POLICY_AUTHORIZATION_INPUT_BYTES: usize = 2 << 20;
pub const MAX_POLICY_AUTHORIZATION_OUTPUT_BYTES: usize = 2 << 20;
pub const MAX_POLICY_AUTHORIZATION_VERIFICATION_INPUT_BYTES: usize = 4 << 20;
pub const MAX_PORTABLE_POLICY_PATH_BYTES: usize = 4_096;
const TEMPLATE_VALIDATION_TIME: &str = "9999-12-31T23:59:59Z";
const TEMPLATE_VALIDATION_ACTION: &str = "zerker.policy.template.validation";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySourceManifest {
    pub schema: String,
    pub sources: Vec<PolicySource>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySource {
    pub path: String,
    pub kind: PolicySourceKind,
    pub scope: PolicySourceScope,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicySourceKind {
    Instruction,
    Skill,
    Context,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicySourceScope {
    Organization,
    Repository,
    Agent,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTemplate {
    pub schema: String,
    pub ontology: Ontology,
    pub authority: AuthorityPolicy,
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema: String,
    pub bundle_digest: String,
    pub sources: Vec<LockedPolicySource>,
    pub policy: PolicyTemplate,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LockedPolicySource {
    pub path: String,
    pub kind: PolicySourceKind,
    pub scope: PolicySourceScope,
    pub size_bytes: u64,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorizationInput {
    pub schema: String,
    pub policy_bundle: PolicyBundle,
    pub evaluation_time: String,
    pub mission: Mission,
    pub action: ProposedAction,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorization {
    pub schema: String,
    pub policy_bundle_digest: String,
    pub authorization_status: AuthorizationStatus,
    pub request_digest: String,
    pub reasoning_result_digest: String,
    pub authorization: AuthorizationBundle,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorizationVerificationInput {
    pub schema: String,
    pub policy_bundle: PolicyBundle,
    pub policy_authorization: PolicyAuthorization,
}

#[derive(Debug, Serialize)]
pub struct PolicySourceVerification {
    pub schema: &'static str,
    pub status: &'static str,
    pub policy_bundle_digest: String,
    pub sources_verified: usize,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid organization policy contract:\n{0}")]
    Invalid(String),
    #[error("organization policy JSON exceeds the {limit}-byte limit")]
    InputTooLarge { limit: usize },
    #[error("organization policy JSON is not UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("invalid organization policy JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("organization policy authorization failed: {0}")]
    Reason(#[from] ReasonError),
    #[error("policy source access failed for {path:?}: {message}")]
    SourceAccess { path: String, message: String },
}

#[derive(Serialize)]
struct PolicyBundleCommitment<'a> {
    schema: &'static str,
    sources: &'a [LockedPolicySource],
    policy: &'a PolicyTemplate,
}

pub fn parse_policy_source_manifest(bytes: &[u8]) -> Result<PolicySourceManifest, PolicyError> {
    let manifest = parse_bounded(bytes, MAX_SOURCE_MANIFEST_BYTES)?;
    validate_policy_source_manifest(&manifest)?;
    Ok(manifest)
}

pub fn parse_policy_template(bytes: &[u8]) -> Result<PolicyTemplate, PolicyError> {
    let policy = parse_bounded(bytes, MAX_POLICY_TEMPLATE_BYTES)?;
    validate_policy_template(&policy)?;
    Ok(policy)
}

pub fn parse_policy_bundle(bytes: &[u8]) -> Result<PolicyBundle, PolicyError> {
    let bundle = parse_bounded(bytes, MAX_POLICY_BUNDLE_BYTES)?;
    validate_policy_bundle(&bundle)?;
    Ok(bundle)
}

pub fn parse_policy_authorization_input(
    bytes: &[u8],
) -> Result<PolicyAuthorizationInput, PolicyError> {
    let input = parse_bounded(bytes, MAX_POLICY_AUTHORIZATION_INPUT_BYTES)?;
    validate_policy_authorization_input(&input)?;
    Ok(input)
}

pub fn parse_policy_authorization(bytes: &[u8]) -> Result<PolicyAuthorization, PolicyError> {
    let authorization = parse_bounded(bytes, MAX_POLICY_AUTHORIZATION_OUTPUT_BYTES)?;
    validate_policy_authorization_shape(&authorization)?;
    Ok(authorization)
}

pub fn parse_policy_authorization_verification_input(
    bytes: &[u8],
) -> Result<PolicyAuthorizationVerificationInput, PolicyError> {
    let input = parse_bounded(bytes, MAX_POLICY_AUTHORIZATION_VERIFICATION_INPUT_BYTES)?;
    validate_policy_authorization_verification_input_size(&input)?;
    Ok(input)
}

fn parse_bounded<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, PolicyError> {
    if bytes.len() > limit {
        return Err(PolicyError::InputTooLarge { limit });
    }
    let text = std::str::from_utf8(bytes)?;
    let parsed = parse_strict_json(text)?;
    validate_canonical_json_numbers(text).map_err(PolicyError::Invalid)?;
    Ok(parsed)
}

pub fn validate_policy_source_manifest(manifest: &PolicySourceManifest) -> Result<(), PolicyError> {
    let mut errors = Vec::new();
    if serde_json::to_vec(manifest)?.len() > MAX_SOURCE_MANIFEST_BYTES {
        errors.push(format!(
            "$: serialized manifest exceeds the {MAX_SOURCE_MANIFEST_BYTES}-byte limit"
        ));
    }
    if manifest.schema != POLICY_SOURCE_MANIFEST_SCHEMA {
        errors.push(format!(
            "$.schema: expected {POLICY_SOURCE_MANIFEST_SCHEMA:?}, got {:?}",
            manifest.schema
        ));
    }
    if manifest.sources.is_empty() {
        errors.push("$.sources: declare at least one policy source".to_owned());
    }
    if manifest.sources.len() > MAX_POLICY_SOURCES {
        errors.push(format!(
            "$.sources: {} entries exceeds the {MAX_POLICY_SOURCES}-source limit",
            manifest.sources.len()
        ));
    }
    let mut paths = BTreeSet::new();
    for (index, source) in manifest.sources.iter().enumerate() {
        if let Err(message) = validate_portable_path(&source.path) {
            errors.push(format!("$.sources[{index}].path: {message}"));
        } else if !paths.insert(&source.path) {
            errors.push(format!(
                "$.sources[{index}].path: duplicate portable path {:?}",
                source.path
            ));
        }
    }
    finish_validation(errors)
}

pub fn validate_policy_template(policy: &PolicyTemplate) -> Result<(), PolicyError> {
    if serde_json::to_vec(policy)?.len() > MAX_POLICY_TEMPLATE_BYTES {
        return invalid(format!(
            "$: serialized policy template exceeds the {MAX_POLICY_TEMPLATE_BYTES}-byte limit"
        ));
    }
    if policy.schema != POLICY_TEMPLATE_SCHEMA {
        return invalid(format!(
            "$.schema: expected {POLICY_TEMPLATE_SCHEMA:?}, got {:?}",
            policy.schema
        ));
    }

    // A dummy boundary-owned action lets the existing action validator enforce
    // all reusable program, temporal, authority, and reserved-namespace rules.
    // The template still supplies neither a query nor an evaluation time.
    let request = ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.to_owned(),
        mission: Mission {
            id: "zerker.policy.template.validation.mission".to_owned(),
            principal: "zerker:policy-validator".to_owned(),
            instruction_digest: format!("sha256:{}", "0".repeat(64)),
            issued_at: TEMPLATE_VALIDATION_TIME.to_owned(),
            valid_until: None,
            constraints: Default::default(),
        },
        action: ProposedAction {
            id: TEMPLATE_VALIDATION_ACTION.to_owned(),
            tool: "zerker.policy.validate".to_owned(),
            proposed_at: TEMPLATE_VALIDATION_TIME.to_owned(),
            arguments: Default::default(),
            effects: Vec::new(),
        },
        policy: Program {
            schema: PROGRAM_SCHEMA_V2.to_owned(),
            ontology: policy.ontology.clone(),
            authority: policy.authority.clone(),
            evaluation_time: Some(TEMPLATE_VALIDATION_TIME.to_owned()),
            facts: policy.facts.clone(),
            rules: policy.rules.clone(),
            query: crate::Atom {
                predicate: "action_authorized".to_owned(),
                arguments: vec![serde_json::Value::String(
                    TEMPLATE_VALIDATION_ACTION.to_owned(),
                )],
                negated: false,
            },
        },
    };
    validate_action_request(&request)
        .map_err(|error| PolicyError::Invalid(format!("$.policy: {error}")))
}

pub fn validate_policy_bundle(bundle: &PolicyBundle) -> Result<(), PolicyError> {
    let mut errors = Vec::new();
    if serde_json::to_vec(bundle)?.len() > MAX_POLICY_BUNDLE_BYTES {
        errors.push(format!(
            "$: serialized policy bundle exceeds the {MAX_POLICY_BUNDLE_BYTES}-byte limit"
        ));
    }
    if bundle.schema != POLICY_BUNDLE_SCHEMA {
        errors.push(format!(
            "$.schema: expected {POLICY_BUNDLE_SCHEMA:?}, got {:?}",
            bundle.schema
        ));
    }
    if !valid_digest(&bundle.bundle_digest) {
        errors.push(
            "$.bundle_digest: expected sha256 followed by 64 lowercase hexadecimal characters"
                .to_owned(),
        );
    }
    if bundle.sources.is_empty() {
        errors.push("$.sources: declare at least one locked policy source".to_owned());
    }
    if bundle.sources.len() > MAX_POLICY_SOURCES {
        errors.push(format!(
            "$.sources: {} entries exceeds the {MAX_POLICY_SOURCES}-source limit",
            bundle.sources.len()
        ));
    }
    let mut aggregate = 0_u64;
    let mut previous: Option<&str> = None;
    for (index, source) in bundle.sources.iter().enumerate() {
        if let Err(message) = validate_portable_path(&source.path) {
            errors.push(format!("$.sources[{index}].path: {message}"));
        }
        if previous.is_some_and(|path| path >= source.path.as_str()) {
            errors.push(format!(
                "$.sources[{index}].path: locked sources must be strictly sorted by unique portable path"
            ));
        }
        previous = Some(&source.path);
        if source.size_bytes > MAX_SOURCE_BYTES {
            errors.push(format!(
                "$.sources[{index}].size_bytes: exceeds the {MAX_SOURCE_BYTES}-byte source limit"
            ));
        }
        aggregate = aggregate.saturating_add(source.size_bytes);
        if !valid_digest(&source.digest) {
            errors.push(format!(
                "$.sources[{index}].digest: expected sha256 followed by 64 lowercase hexadecimal characters"
            ));
        }
    }
    if aggregate > MAX_AGGREGATE_SOURCE_BYTES {
        errors.push(format!(
            "$.sources: aggregate size exceeds the {MAX_AGGREGATE_SOURCE_BYTES}-byte limit"
        ));
    }
    if let Err(error) = validate_policy_template(&bundle.policy) {
        errors.push(error.to_string());
    }
    if errors.is_empty() && valid_digest(&bundle.bundle_digest) {
        let expected = policy_bundle_digest(&bundle.sources, &bundle.policy)?;
        if bundle.bundle_digest != expected {
            errors.push(format!(
                "$.bundle_digest: commitment mismatch; expected {expected}"
            ));
        }
    }
    finish_validation(errors)
}

pub fn lock_policy_bundle(
    root: &Path,
    manifest: &PolicySourceManifest,
    policy: &PolicyTemplate,
) -> Result<PolicyBundle, PolicyError> {
    validate_policy_source_manifest(manifest)?;
    validate_policy_template(policy)?;
    let mut sources = resolve_sources(root, &manifest.sources)?;
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    let bundle_digest = policy_bundle_digest(&sources, policy)?;
    let bundle = PolicyBundle {
        schema: POLICY_BUNDLE_SCHEMA.to_owned(),
        bundle_digest,
        sources,
        policy: policy.clone(),
    };
    validate_policy_bundle(&bundle)?;
    Ok(bundle)
}

pub fn verify_policy_sources(
    root: &Path,
    bundle: &PolicyBundle,
) -> Result<PolicySourceVerification, PolicyError> {
    validate_policy_bundle(bundle)?;
    let manifest_sources = bundle
        .sources
        .iter()
        .map(|source| PolicySource {
            path: source.path.clone(),
            kind: source.kind,
            scope: source.scope,
        })
        .collect::<Vec<_>>();
    let mut observed = resolve_sources(root, &manifest_sources)?;
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    for (index, (expected, actual)) in bundle.sources.iter().zip(&observed).enumerate() {
        if expected != actual {
            return invalid(format!(
                "$.sources[{index}]: source drift for {:?}; expected size {} and digest {}, observed size {} and digest {}",
                expected.path,
                expected.size_bytes,
                expected.digest,
                actual.size_bytes,
                actual.digest
            ));
        }
    }
    Ok(PolicySourceVerification {
        schema: POLICY_SOURCE_VERIFICATION_SCHEMA,
        status: "verified",
        policy_bundle_digest: bundle.bundle_digest.clone(),
        sources_verified: bundle.sources.len(),
    })
}

pub fn authorize_policy(
    input: &PolicyAuthorizationInput,
) -> Result<PolicyAuthorization, PolicyError> {
    validate_policy_authorization_input(input)?;
    let request = expand_policy_request(
        &input.policy_bundle,
        &input.evaluation_time,
        &input.mission,
        &input.action,
    )?;
    let certificate = authorize(&request)?;
    let authorization_bundle = AuthorizationBundle {
        schema: AUTHORIZATION_BUNDLE_SCHEMA.to_owned(),
        request,
        certificate,
    };
    let verification = verify_authorization_bundle(&authorization_bundle)?;
    let result = PolicyAuthorization {
        schema: POLICY_AUTHORIZATION_SCHEMA.to_owned(),
        policy_bundle_digest: input.policy_bundle.bundle_digest.clone(),
        authorization_status: verification.authorization_status,
        request_digest: verification.request_digest,
        reasoning_result_digest: verification.reasoning_result_digest,
        authorization: authorization_bundle,
    };
    validate_policy_authorization_output_size(&result)?;
    Ok(result)
}

pub fn verify_policy_authorization(
    input: &PolicyAuthorizationVerificationInput,
) -> Result<AuthorizationVerification, PolicyError> {
    validate_policy_authorization_verification_input_size(input)?;
    validate_policy_bundle(&input.policy_bundle)?;
    validate_policy_authorization_shape(&input.policy_authorization)?;

    let result = &input.policy_authorization;
    if result.policy_bundle_digest != input.policy_bundle.bundle_digest {
        return invalid(
            "$.policy_authorization.policy_bundle_digest: does not match the verified policy bundle",
        );
    }
    let request = &result.authorization.request;
    let evaluation_time = request.policy.evaluation_time.as_deref().ok_or_else(|| {
        PolicyError::Invalid(
            "$.policy_authorization.authorization.request.policy.evaluation_time: required"
                .to_owned(),
        )
    })?;
    let expected_request = expand_policy_request(
        &input.policy_bundle,
        evaluation_time,
        &request.mission,
        &request.action,
    )?;
    if digest(&expected_request)? != digest(request)? {
        return invalid(
            "$.policy_authorization.authorization.request: does not match deterministic policy-template expansion",
        );
    }

    let verification = verify_authorization_bundle(&result.authorization)?;
    if result.authorization_status != verification.authorization_status {
        return invalid(
            "$.policy_authorization.authorization_status: does not match the certificate",
        );
    }
    if result.request_digest != verification.request_digest {
        return invalid("$.policy_authorization.request_digest: does not match the certificate");
    }
    if result.reasoning_result_digest != verification.reasoning_result_digest {
        return invalid(
            "$.policy_authorization.reasoning_result_digest: does not match the certificate",
        );
    }
    Ok(verification)
}

fn validate_policy_authorization_input(
    input: &PolicyAuthorizationInput,
) -> Result<(), PolicyError> {
    validate_serialized_limit(
        input,
        MAX_POLICY_AUTHORIZATION_INPUT_BYTES,
        "policy authorization input",
    )?;
    if input.schema != POLICY_AUTHORIZATION_INPUT_SCHEMA {
        return invalid(format!(
            "$.schema: expected {POLICY_AUTHORIZATION_INPUT_SCHEMA:?}, got {:?}",
            input.schema
        ));
    }
    validate_policy_bundle(&input.policy_bundle)?;
    // Full timestamp, mission, action, reserved-namespace, and program checks
    // are deliberately delegated to the unchanged action validator.
    expand_policy_request(
        &input.policy_bundle,
        &input.evaluation_time,
        &input.mission,
        &input.action,
    )?;
    Ok(())
}

fn validate_policy_authorization_shape(
    authorization: &PolicyAuthorization,
) -> Result<(), PolicyError> {
    validate_policy_authorization_output_size(authorization)?;
    if authorization.schema != POLICY_AUTHORIZATION_SCHEMA {
        return invalid(format!(
            "$.schema: expected {POLICY_AUTHORIZATION_SCHEMA:?}, got {:?}",
            authorization.schema
        ));
    }
    if !valid_digest(&authorization.policy_bundle_digest) {
        return invalid("$.policy_bundle_digest: expected a lowercase SHA-256 digest");
    }
    if !valid_digest(&authorization.request_digest) {
        return invalid("$.request_digest: expected a lowercase SHA-256 digest");
    }
    if !valid_digest(&authorization.reasoning_result_digest) {
        return invalid("$.reasoning_result_digest: expected a lowercase SHA-256 digest");
    }
    Ok(())
}

fn validate_policy_authorization_output_size(
    authorization: &PolicyAuthorization,
) -> Result<(), PolicyError> {
    validate_serialized_limit(
        authorization,
        MAX_POLICY_AUTHORIZATION_OUTPUT_BYTES,
        "policy authorization output",
    )
}

fn validate_policy_authorization_verification_input_size(
    input: &PolicyAuthorizationVerificationInput,
) -> Result<(), PolicyError> {
    validate_serialized_limit(
        input,
        MAX_POLICY_AUTHORIZATION_VERIFICATION_INPUT_BYTES,
        "policy authorization verification input",
    )?;
    if input.schema != POLICY_AUTHORIZATION_VERIFICATION_INPUT_SCHEMA {
        return invalid(format!(
            "$.schema: expected {POLICY_AUTHORIZATION_VERIFICATION_INPUT_SCHEMA:?}, got {:?}",
            input.schema
        ));
    }
    Ok(())
}

fn validate_serialized_limit(
    value: &impl Serialize,
    limit: usize,
    label: &str,
) -> Result<(), PolicyError> {
    if serde_json::to_vec(value)?.len() > limit {
        return invalid(format!(
            "$: serialized {label} exceeds the {limit}-byte limit"
        ));
    }
    Ok(())
}

fn expand_policy_request(
    bundle: &PolicyBundle,
    evaluation_time: &str,
    mission: &Mission,
    action: &ProposedAction,
) -> Result<ActionRequest, PolicyError> {
    let request = ActionRequest {
        schema: ACTION_REQUEST_SCHEMA.to_owned(),
        mission: mission.clone(),
        action: action.clone(),
        policy: Program {
            schema: PROGRAM_SCHEMA_V2.to_owned(),
            ontology: bundle.policy.ontology.clone(),
            authority: bundle.policy.authority.clone(),
            evaluation_time: Some(evaluation_time.to_owned()),
            facts: bundle.policy.facts.clone(),
            rules: bundle.policy.rules.clone(),
            query: crate::Atom {
                predicate: "action_authorized".to_owned(),
                arguments: vec![serde_json::Value::String(action.id.clone())],
                negated: false,
            },
        },
    };
    validate_action_request(&request)?;
    Ok(request)
}

fn policy_bundle_digest(
    sources: &[LockedPolicySource],
    policy: &PolicyTemplate,
) -> Result<String, PolicyError> {
    Ok(digest(&PolicyBundleCommitment {
        schema: POLICY_BUNDLE_COMMITMENT_SCHEMA,
        sources,
        policy,
    })?)
}

fn validate_portable_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("must not be empty".to_owned());
    }
    if path.len() > MAX_PORTABLE_POLICY_PATH_BYTES {
        return Err(format!(
            "exceeds the {MAX_PORTABLE_POLICY_PATH_BYTES}-byte portable path limit"
        ));
    }
    if !path.nfc().eq(path.chars()) {
        return Err("must already be Unicode NFC".to_owned());
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err("must be root-relative without a leading or trailing slash".to_owned());
    }
    if path.contains('\\') {
        return Err("backslash is not a portable separator".to_owned());
    }
    if path.chars().any(|character| {
        character == '\0'
            || character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
    }) {
        return Err("control and bidirectional-control characters are forbidden".to_owned());
    }
    let mut segments = path.split('/');
    let first = segments.next().expect("nonempty path has a segment");
    if first.contains(':') {
        return Err("drive and URI-like prefixes are forbidden".to_owned());
    }
    if first.is_empty() || first == "." || first == ".." {
        return Err("empty, dot, and parent segments are forbidden".to_owned());
    }
    for segment in segments {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("empty, dot, and parent segments are forbidden".to_owned());
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn source_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn finish_validation(errors: Vec<String>) -> Result<(), PolicyError> {
    if errors.is_empty() {
        Ok(())
    } else {
        invalid(errors.join("\n"))
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError::Invalid(message.into()))
}

#[cfg(unix)]
fn resolve_sources(
    root: &Path,
    sources: &[PolicySource],
) -> Result<Vec<LockedPolicySource>, PolicyError> {
    unix_source::resolve(root, sources)
}

#[cfg(not(unix))]
fn resolve_sources(
    _root: &Path,
    _sources: &[PolicySource],
) -> Result<Vec<LockedPolicySource>, PolicyError> {
    Err(PolicyError::SourceAccess {
        path: ".".to_owned(),
        message: "descriptor-relative no-follow source access is unsupported on this platform"
            .to_owned(),
    })
}

#[cfg(unix)]
mod unix_source {
    use std::{
        collections::BTreeSet,
        fs::File,
        io::{Read, Seek, SeekFrom},
        os::unix::fs::MetadataExt,
        path::Path,
    };

    use rustix::fs::{Mode, OFlags, open, openat};

    use super::{
        LockedPolicySource, MAX_AGGREGATE_SOURCE_BYTES, MAX_SOURCE_BYTES, PolicyError,
        PolicySource, source_digest,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct Identity {
        device: u64,
        inode: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Stamp {
        identity: Identity,
        size: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    pub(super) fn resolve(
        root: &Path,
        sources: &[PolicySource],
    ) -> Result<Vec<LockedPolicySource>, PolicyError> {
        let root_fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| access(".", error))?;
        let root_metadata = root_fd.metadata().map_err(|error| access(".", error))?;
        if !root_metadata.is_dir() {
            return Err(access(".", "root is not a directory"));
        }
        let root_device = root_metadata.dev();

        let mut identities = BTreeSet::new();
        let mut aggregate = 0_u64;
        let mut locked = Vec::with_capacity(sources.len());
        for source in sources {
            let (bytes, identity) = read_source(&root_fd, root_device, &source.path)?;
            if !identities.insert(identity) {
                return Err(access(
                    &source.path,
                    "duplicates another source file identity (hard link or filesystem alias)",
                ));
            }
            let size_bytes = bytes.len() as u64;
            aggregate = aggregate
                .checked_add(size_bytes)
                .ok_or_else(|| access(&source.path, "aggregate source byte count overflowed"))?;
            if aggregate > MAX_AGGREGATE_SOURCE_BYTES {
                return Err(access(
                    &source.path,
                    format!(
                        "aggregate source bytes exceed the {MAX_AGGREGATE_SOURCE_BYTES}-byte limit"
                    ),
                ));
            }
            locked.push(LockedPolicySource {
                path: source.path.clone(),
                kind: source.kind,
                scope: source.scope,
                size_bytes,
                digest: source_digest(&bytes),
            });
        }
        Ok(locked)
    }

    fn read_source(
        root: &File,
        root_device: u64,
        path: &str,
    ) -> Result<(Vec<u8>, Identity), PolicyError> {
        read_source_observed(root, root_device, path, || {}, || {})
    }

    fn read_source_observed(
        root: &File,
        root_device: u64,
        path: &str,
        between_reads: impl FnOnce(),
        before_retraverse: impl FnOnce(),
    ) -> Result<(Vec<u8>, Identity), PolicyError> {
        let (mut file, parent_identities) = open_manifested_source(root, root_device, path)?;
        let before = stamp(&file, path)?;

        let first = read_bounded(&mut file, path)?;
        between_reads();
        file.seek(SeekFrom::Start(0))
            .map_err(|error| access(path, error))?;
        let second = read_bounded(&mut file, path)?;
        let after = stamp(&file, path)?;
        if first != second || before != after || before.size != first.len() as u64 {
            return Err(access(path, "source changed while it was being read"));
        }

        before_retraverse();
        // Retraverse from the still-open root, rather than trusting the first
        // parent handle, so a renamed or replaced directory component is also
        // detected before the source commitment is returned.
        let (named, named_parent_identities) = open_manifested_source(root, root_device, path)?;
        let named_stamp = stamp(&named, path)?;
        if parent_identities != named_parent_identities || named_stamp != after {
            return Err(access(
                path,
                "source path or metadata changed while it was being read",
            ));
        }
        Ok((first, before.identity))
    }

    fn open_manifested_source(
        root: &File,
        root_device: u64,
        path: &str,
    ) -> Result<(File, Vec<Identity>), PolicyError> {
        let segments = path.split('/').collect::<Vec<_>>();
        let mut directory = root.try_clone().map_err(|error| access(path, error))?;
        let mut parent_identities = Vec::with_capacity(segments.len().saturating_sub(1));
        for segment in &segments[..segments.len() - 1] {
            directory = openat(
                &directory,
                *segment,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| access(path, error))?;
            let metadata = directory.metadata().map_err(|error| access(path, error))?;
            if !metadata.is_dir() || metadata.dev() != root_device {
                return Err(access(
                    path,
                    "directory component is not a directory on the opened root filesystem",
                ));
            }
            parent_identities.push(Identity {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        }

        let name = segments.last().expect("validated path has a final segment");
        let file = openat(
            &directory,
            *name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| access(path, error))?;
        if file.metadata().map_err(|error| access(path, error))?.dev() != root_device {
            return Err(access(path, "source crosses a filesystem mount boundary"));
        }
        Ok((file, parent_identities))
    }

    fn read_bounded(file: &mut File, path: &str) -> Result<Vec<u8>, PolicyError> {
        let mut bytes = Vec::new();
        file.take(MAX_SOURCE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| access(path, error))?;
        if bytes.len() as u64 > MAX_SOURCE_BYTES {
            return Err(access(
                path,
                format!("source exceeds the {MAX_SOURCE_BYTES}-byte limit"),
            ));
        }
        Ok(bytes)
    }

    fn stamp(file: &File, path: &str) -> Result<Stamp, PolicyError> {
        let metadata = file.metadata().map_err(|error| access(path, error))?;
        if !metadata.is_file() {
            return Err(access(path, "source is not a regular file"));
        }
        Ok(Stamp {
            identity: Identity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn access(path: &str, message: impl std::fmt::Display) -> PolicyError {
        PolicyError::SourceAccess {
            path: path.to_owned(),
            message: message.to_string(),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{fs, os::unix::fs::MetadataExt};

        use rustix::fs::{Mode, OFlags, open};

        use super::*;

        fn opened_root(path: &Path) -> (File, u64) {
            let root = open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .unwrap();
            let device = root.metadata().unwrap().dev();
            (root, device)
        }

        fn assert_changed(error: PolicyError) {
            assert!(
                error
                    .to_string()
                    .contains("changed while it was being read"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn rejects_same_size_rewrite_between_descriptor_reads() {
            let tree = tempfile::tempdir().unwrap();
            let path = tree.path().join("source.md");
            fs::write(&path, b"original").unwrap();
            let (root, device) = opened_root(tree.path());

            let error = read_source_observed(
                &root,
                device,
                "source.md",
                || fs::write(&path, b"rewritten").unwrap(),
                || {},
            )
            .unwrap_err();

            assert_changed(error);
        }

        #[test]
        fn rejects_same_size_rewrite_restored_before_second_read() {
            let tree = tempfile::tempdir().unwrap();
            let path = tree.path().join("source.md");
            fs::write(&path, b"original").unwrap();
            let (root, device) = opened_root(tree.path());

            let error = read_source_observed(
                &root,
                device,
                "source.md",
                || {
                    fs::write(&path, b"rewritten").unwrap();
                    fs::write(&path, b"original").unwrap();
                },
                || {},
            )
            .unwrap_err();

            assert_changed(error);
        }

        #[test]
        fn rejects_final_component_replacement_before_name_recheck() {
            let tree = tempfile::tempdir().unwrap();
            let path = tree.path().join("source.md");
            fs::write(&path, b"original").unwrap();
            let (root, device) = opened_root(tree.path());

            let error = read_source_observed(
                &root,
                device,
                "source.md",
                || {},
                || {
                    let replacement = tree.path().join("replacement.md");
                    fs::write(&replacement, b"original").unwrap();
                    fs::rename(replacement, &path).unwrap();
                },
            )
            .unwrap_err();

            assert_changed(error);
        }

        #[test]
        fn rejects_parent_component_replacement_before_name_recheck() {
            let tree = tempfile::tempdir().unwrap();
            let parent = tree.path().join("policy");
            let replacement = tree.path().join("replacement-policy");
            fs::create_dir(&parent).unwrap();
            fs::create_dir(&replacement).unwrap();
            fs::write(parent.join("source.md"), b"original").unwrap();
            // Prepare the alias before the resolver stamps the source so the
            // replacement changes only the parent-directory identity.
            fs::hard_link(parent.join("source.md"), replacement.join("source.md")).unwrap();
            let (root, device) = opened_root(tree.path());

            let error = read_source_observed(
                &root,
                device,
                "policy/source.md",
                || {},
                || {
                    fs::rename(&parent, tree.path().join("old-policy")).unwrap();
                    fs::rename(&replacement, &parent).unwrap();
                },
            )
            .unwrap_err();

            assert_changed(error);
        }
    }
}
