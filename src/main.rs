use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use serde::{
    Deserialize,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use zerker_reason::{
    Atom, CheckResult, Program, Status, VerificationResult,
    action::{
        ACTION_REQUEST_SCHEMA, AUTHORIZATION_BUNDLE_SCHEMA, ActionRequest, AuthorizationBundle,
        AuthorizationResult, AuthorizationStatus, AuthorizationVerification, authorize,
        verify_authorization, verify_authorization_bundle,
    },
    check,
    release::{ReleaseAuthorizationInput, compile_release_authorization},
    validate, verify,
};

#[derive(Debug, Parser)]
#[command(
    name = "reason",
    version,
    about = "Check agent decisions with explicit facts, rules, negation, and proof"
)]
struct Cli {
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, global = true)]
    format: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a reasoning program without evaluating its query.
    Validate { input: PathBuf },
    /// Evaluate support for a query and its explicit negation.
    Check {
        input: PathBuf,
        /// Write the complete JSON result to a file for independent verification.
        #[arg(long)]
        proof_out: Option<PathBuf>,
    },
    /// Independently verify an evidenced result against its program.
    Verify { program: PathBuf, proof: PathBuf },
    /// Authorize an exact proposed action against a governed mission and policy.
    Authorize {
        input: PathBuf,
        /// Write the complete authorization certificate for independent verification.
        #[arg(long)]
        certificate_out: Option<PathBuf>,
    },
    /// Verify an authorization certificate against its original request.
    VerifyAuthorization {
        request: PathBuf,
        certificate: PathBuf,
    },
    /// Atomically verify a request and certificate supplied in one JSON bundle.
    VerifyAuthorizationBundle {
        input: PathBuf,
        /// Return the authorization status exit code after successful verification.
        #[arg(long)]
        require_authorized: bool,
    },
    /// Build and evaluate the standard software-release authorization policy.
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    /// Write an editable release-authorization starter file.
    Init {
        output: PathBuf,
        /// Explicit evaluation snapshot time (canonical UTC RFC 3339 seconds).
        #[arg(long)]
        evaluation_time: String,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
    },
    /// Compile release evidence into an exact action request and authorize it.
    Authorize {
        input: PathBuf,
        /// Write the compiled generic action request.
        #[arg(long)]
        request_out: Option<PathBuf>,
        /// Write the independently verifiable authorization certificate.
        #[arg(long)]
        certificate_out: Option<PathBuf>,
        /// Write the request and certificate as one verifier bundle.
        #[arg(long)]
        bundle_out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(error) => {
            match cli.format {
                OutputFormat::Text => eprintln!(
                    "reason: {error}\n\nFix the reported field and run the command again."
                ),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::json!({
                        "schema": "zerker.reason.error.v1",
                        "status": "error",
                        "error": error.to_string()
                    })
                ),
            }
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match &cli.command {
        Command::Validate { input } => {
            let program: Program = load(input)?;
            validate(&program)?;
            match cli.format {
                OutputFormat::Text => {
                    println!(
                        "VALID  {}@{}\n       {} facts, {} rules",
                        program.ontology.id,
                        program.ontology.version,
                        program.facts.len(),
                        program.rules.len(),
                    );
                    if let Some(evaluation_time) = &program.evaluation_time {
                        println!("       evaluation {evaluation_time}");
                    }
                    println!("\nNext: reason check {}", input.display());
                }
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::json!({
                        "schema": "zerker.reason.validation.v1",
                        "status": "valid",
                        "ontology": {
                            "id": program.ontology.id,
                            "version": program.ontology.version,
                        },
                        "facts": program.facts.len(),
                        "rules": program.rules.len(),
                        "evaluation_time": program.evaluation_time,
                    })
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Check { input, proof_out } => {
            let program: Program = load(input)?;
            let result = check(&program)?;
            if let Some(path) = proof_out {
                fs::write(
                    path,
                    format!("{}\n", serde_json::to_string_pretty(&result)?),
                )?;
            }
            match cli.format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                OutputFormat::Text => print_text_result(&result, proof_out.as_ref()),
            }
            Ok(match result.status {
                Status::Proved => ExitCode::SUCCESS,
                Status::Unknown => ExitCode::from(2),
                Status::Disproved => ExitCode::from(3),
                Status::Inconsistent => ExitCode::from(4),
            })
        }
        Command::Verify { program, proof } => {
            let program: Program = load(program)?;
            let result: CheckResult = load(proof)?;
            let verification = verify(&program, &result)?;
            match cli.format {
                OutputFormat::Text => print_verification(&verification),
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&verification)?)
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Authorize {
            input,
            certificate_out,
        } => {
            let request: ActionRequest = load(input)?;
            let result = authorize(&request)?;
            if let Some(path) = certificate_out {
                fs::write(
                    path,
                    format!("{}\n", serde_json::to_string_pretty(&result)?),
                )?;
            }
            match cli.format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                OutputFormat::Text => print_authorization(&result, certificate_out.as_ref()),
            }
            Ok(authorization_exit_code(result.status))
        }
        Command::VerifyAuthorization {
            request,
            certificate,
        } => {
            let request: ActionRequest = load(request)?;
            let result: AuthorizationResult = load(certificate)?;
            let verification = verify_authorization(&request, &result)?;
            print_authorization_verification_for_format(cli.format, &verification)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::VerifyAuthorizationBundle {
            input,
            require_authorized,
        } => {
            let bundle: AuthorizationBundle = load(input)?;
            let verification = verify_authorization_bundle(&bundle)?;
            print_authorization_verification_for_format(cli.format, &verification)?;
            if *require_authorized {
                Ok(authorization_exit_code(verification.authorization_status))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        Command::Release { command } => run_release(cli.format, command),
    }
}

fn run_release(
    format: OutputFormat,
    command: &ReleaseCommand,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match command {
        ReleaseCommand::Init {
            output,
            evaluation_time,
            force,
        } => {
            if output.exists() && !force {
                return Err(format!(
                    "{} already exists; choose another path or pass --force",
                    output.display()
                )
                .into());
            }
            let mut starter: ReleaseAuthorizationInput =
                serde_json::from_str(include_str!("../examples/release-authorization.json"))?;
            starter.evaluation_time = evaluation_time.clone();
            starter.mission.issued_at = evaluation_time.clone();
            starter.mission.valid_until = None;
            starter.release.proposed_at = evaluation_time.clone();
            for evidence in starter
                .evidence
                .tests
                .iter_mut()
                .chain(starter.evidence.security_reviews.iter_mut())
            {
                evidence.observed_at = evaluation_time.clone();
                evidence.valid_until = None;
            }
            for evidence in &mut starter.evidence.artifacts {
                evidence.observed_at = evaluation_time.clone();
                evidence.valid_until = None;
            }
            for evidence in &mut starter.evidence.approvals {
                evidence.observed_at = evaluation_time.clone();
                evidence.valid_until = None;
            }
            let compiled = compile_release_authorization(&starter)?;
            let _ = authorize(&compiled)?;
            write_pretty_json(output, &starter)?;
            match format {
                OutputFormat::Text => {
                    println!(
                        "Release authorization starter written to {}",
                        output.display()
                    );
                    println!("Next: reason release authorize {}", output.display());
                }
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::json!({
                        "schema": "zerker.reason.release-init.v1",
                        "status": "created",
                        "path": output,
                    })
                ),
            }
            Ok(ExitCode::SUCCESS)
        }
        ReleaseCommand::Authorize {
            input,
            request_out,
            certificate_out,
            bundle_out,
        } => {
            let release: ReleaseAuthorizationInput = load(input)?;
            let request = compile_release_authorization(&release)?;
            let result = authorize(&request)?;
            let bundle = AuthorizationBundle {
                schema: AUTHORIZATION_BUNDLE_SCHEMA.to_owned(),
                request: request.clone(),
                certificate: result.clone(),
            };
            let mut outputs = Vec::new();
            if let Some(path) = request_out {
                outputs.push((path.clone(), pretty_json_bytes(&request)?));
            }
            if let Some(path) = certificate_out {
                outputs.push((path.clone(), pretty_json_bytes(&result)?));
            }
            if let Some(path) = bundle_out {
                outputs.push((path.clone(), pretty_json_bytes(&bundle)?));
            }
            write_output_set(outputs)?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                OutputFormat::Text => {
                    print_authorization(&result, certificate_out.as_ref());
                    if let Some(path) = request_out {
                        println!(
                            "Request written to {} ({ACTION_REQUEST_SCHEMA})",
                            path.display()
                        );
                    }
                    if let Some(path) = bundle_out {
                        println!("Bundle written to {}", path.display());
                        println!(
                            "Next: reason verify-authorization-bundle {} --require-authorized",
                            path.display()
                        );
                    }
                }
            }
            Ok(authorization_exit_code(result.status))
        }
    }
}

fn write_pretty_json(
    path: &PathBuf,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, pretty_json_bytes(value)?)?;
    Ok(())
}

fn pretty_json_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Stage every release artifact before publishing any of them. Hard links make
/// each destination a create-if-absent operation, so aliases and partial writes
/// cannot silently replace a different artifact.
fn write_output_set(outputs: Vec<(PathBuf, Vec<u8>)>) -> Result<(), Box<dyn std::error::Error>> {
    let mut identities = BTreeSet::new();
    for (path, _) in &outputs {
        let identity = output_identity(path)?;
        if !identities.insert(identity) {
            return Err(format!("duplicate release output path: {}", path.display()).into());
        }
        if path.exists() {
            return Err(format!("release output already exists: {}", path.display()).into());
        }
    }

    let mut staged = Vec::new();
    for (index, (path, bytes)) in outputs.iter().enumerate() {
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| format!("release output has no file name: {}", path.display()))?;
        let temporary = parent.join(format!(
            ".{}.reason-stage-{}-{index}",
            name.to_string_lossy(),
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            for (staged_path, _) in &staged {
                let _ = fs::remove_file(staged_path);
            }
            return Err(error.into());
        }
        staged.push((temporary, path.clone()));
    }

    let mut published = Vec::new();
    for (temporary, destination) in &staged {
        if let Err(error) = fs::hard_link(temporary, destination) {
            for path in &published {
                let _ = fs::remove_file(path);
            }
            for (staged_path, _) in &staged {
                let _ = fs::remove_file(staged_path);
            }
            return Err(error.into());
        }
        published.push(destination.clone());
    }
    for (temporary, _) in staged {
        fs::remove_file(temporary)?;
    }
    Ok(())
}

fn output_identity(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let canonical_parent = fs::canonicalize(parent)?;
    let name = path
        .file_name()
        .ok_or_else(|| format!("release output has no file name: {}", path.display()))?;
    Ok(canonical_parent.join(name))
}

const MAX_INPUT_BYTES: u64 = 64 << 20;

fn load<T: DeserializeOwned>(path: &PathBuf) -> Result<T, Box<dyn std::error::Error>> {
    let text = if path.as_os_str() == "-" {
        read_bounded(io::stdin().lock(), MAX_INPUT_BYTES)?
    } else {
        read_bounded(fs::File::open(path)?, MAX_INPUT_BYTES)?
    };
    Ok(parse_unique_json(&text)?)
}

/// Parse through an untyped tree first so duplicate object members are rejected
/// recursively, including inside user-defined maps. Then reject every member
/// the selected versioned schema does not consume. Otherwise one component can
/// act on a field that Reason silently ignored when authorizing the request.
fn parse_unique_json<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = UniqueJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;

    let mut ignored = None;
    let parsed = serde_ignored::deserialize(value, |path| {
        if ignored.is_none() {
            ignored = Some(path.to_string());
        }
    })?;
    match ignored {
        None => Ok(parsed),
        Some(path) => Err(de::Error::custom(format!(
            "unknown object member at {path}"
        ))),
    }
}

struct UniqueJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value with unique object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(UniqueJsonValue(serde_json::Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate object member `{key}`"
                )));
            }
            let value = map.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(serde_json::Value::Object(values)))
    }
}

fn read_bounded(reader: impl Read, limit: u64) -> io::Result<String> {
    let mut text = String::new();
    let bytes_read = reader.take(limit + 1).read_to_string(&mut text)?;
    if bytes_read as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("input exceeds the {limit}-byte limit"),
        ));
    }
    Ok(text)
}

fn print_authorization_verification_for_format(
    format: OutputFormat,
    verification: &AuthorizationVerification,
) -> Result<(), serde_json::Error> {
    match format {
        OutputFormat::Text => print_authorization_verification(verification),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(verification)?),
    }
    Ok(())
}

fn print_text_result(result: &CheckResult, proof_out: Option<&PathBuf>) {
    println!(
        "{}  {}",
        match result.status {
            Status::Proved => "PROVED",
            Status::Disproved => "DISPROVED",
            Status::Inconsistent => "INCONSISTENT",
            Status::Unknown => "UNKNOWN",
        },
        display_atom(&result.query)
    );
    if let Some(proof) = &result.proof {
        println!("        support: {} nodes", proof.nodes.len());
        println!("        proof {}", proof.digest);
    }
    if let Some(disproof) = &result.disproof {
        println!("        opposing support: {} nodes", disproof.nodes.len());
        println!("        disproof {}", disproof.digest);
    }
    if let Some(conflict) = &result.conflict {
        println!("        conflict facts: {}", conflict.fact_ids.join(", "));
        println!(
            "\nBoth the query and its explicit negation are supported. Do not authorize action until the conflict is resolved."
        );
    } else if result.proof.is_none() {
        if result.missing.is_empty() {
            println!("        no supporting derivation was found");
        } else {
            println!("        missing support:");
            for atom in &result.missing {
                println!("        - {}", display_atom(atom));
            }
        }
        if result.disproof.is_some() {
            println!(
                "\nDisproved means the explicit negation is supported. It is not inferred from missing evidence."
            );
        } else if result
            .temporal
            .as_ref()
            .is_some_and(|report| !report.withheld.is_empty())
        {
            println!(
                "\nUnknown does not mean false. Refresh or replace temporally ineligible evidence."
            );
        } else if result.authority.withheld.is_empty() {
            println!("\nUnknown does not mean false. Add an observed fact or an applicable rule.");
        } else {
            println!(
                "\nUnknown does not mean false. Supply evidence from an admitted authority; do not relabel untrusted evidence."
            );
        }
    }
    if !result.authority.withheld.is_empty() {
        println!(
            "\nAuthority withheld {} fact(s):",
            result.authority.withheld.len()
        );
        for withheld in &result.authority.withheld {
            let admitted = if withheld.admitted_authorities.is_empty() {
                "none".to_owned()
            } else {
                withheld.admitted_authorities.join(", ")
            };
            println!(
                "        - {} from {} ({})",
                display_atom(&withheld.atom),
                withheld.authority,
                withheld.fact_id
            );
            println!("          admitted authority: {admitted}");
        }
    }
    if let Some(temporal) = &result.temporal {
        println!("\nEvaluated at {}", temporal.evaluation_time);
        if !temporal.withheld.is_empty() {
            println!(
                "Temporal lifecycle withheld {} fact(s):",
                temporal.withheld.len()
            );
            for withheld in &temporal.withheld {
                println!(
                    "        - {} ({})",
                    display_atom(&withheld.atom),
                    withheld.fact_id
                );
                println!("          {}", withheld.reason);
            }
        }
    }
    println!(
        "\nOntology {}@{}  {} supplied, {} admitted, {} withheld, {} derived, {} rounds",
        result.ontology.id,
        result.ontology.version,
        result.metrics.facts_supplied,
        result.metrics.facts_admitted,
        result.metrics.facts_withheld,
        result.metrics.facts_derived,
        result.metrics.rounds
    );
    if let Some(path) = proof_out {
        println!("Proof written to {}", path.display());
        println!("Next: reason verify <program> {}", path.display());
    }
}

fn print_authorization(result: &AuthorizationResult, certificate_out: Option<&PathBuf>) {
    println!(
        "{}  {} via {}",
        match result.status {
            AuthorizationStatus::Authorized => "AUTHORIZED",
            AuthorizationStatus::Denied => "DENIED",
            AuthorizationStatus::Conflicted => "CONFLICTED",
            AuthorizationStatus::InsufficientEvidence => "INSUFFICIENT_EVIDENCE",
        },
        result.action.id,
        result.mission.id
    );
    let arguments = result
        .action
        .arguments
        .iter()
        .map(|(key, value)| format!("{key}={}", display_value(value)))
        .collect::<Vec<_>>()
        .join(", ");
    println!("            {}({arguments})", result.action.tool);
    for effect in &result.action.effects {
        println!(
            "            effect {} {}{}",
            effect.kind,
            effect.resource,
            effect
                .value
                .as_ref()
                .map(|value| format!(" = {}", display_value(value)))
                .unwrap_or_default()
        );
    }
    println!("            action {}", result.action.digest);
    println!("            mission {}", result.mission.digest);
    if let Some(temporal) = &result.reasoning.temporal {
        println!("            evaluated at {}", temporal.evaluation_time);
    }
    if result.issues.is_empty() {
        println!("            all authorization requirements are proved");
    } else {
        println!("            issues:");
        for issue in &result.issues {
            match &issue.atom {
                Some(atom) => println!(
                    "            - [{}] {}: {}",
                    issue.code,
                    display_atom(atom),
                    issue.message
                ),
                None => println!("            - [{}] {}", issue.code, issue.message),
            }
            if !issue.fact_ids.is_empty() {
                println!("              facts: {}", issue.fact_ids.join(", "));
            }
        }
    }
    if let Some(proof) = &result.reasoning.proof {
        println!("            proof {}", proof.digest);
    }
    if let Some(disproof) = &result.reasoning.disproof {
        println!("            disproof {}", disproof.digest);
    }
    if let Some(path) = certificate_out {
        println!("Certificate written to {}", path.display());
        println!(
            "Next: reason verify-authorization <request> {}",
            path.display()
        );
    }
}

fn authorization_exit_code(status: AuthorizationStatus) -> ExitCode {
    match status {
        AuthorizationStatus::Authorized => ExitCode::SUCCESS,
        AuthorizationStatus::InsufficientEvidence => ExitCode::from(2),
        AuthorizationStatus::Denied => ExitCode::from(3),
        AuthorizationStatus::Conflicted => ExitCode::from(4),
    }
}

fn print_authorization_verification(result: &AuthorizationVerification) {
    println!(
        "VERIFIED_AUTHORIZATION  {} ({})",
        result.request_digest,
        match result.authorization_status {
            AuthorizationStatus::Authorized => "authorized",
            AuthorizationStatus::Denied => "denied",
            AuthorizationStatus::Conflicted => "conflicted",
            AuthorizationStatus::InsufficientEvidence => "insufficient_evidence",
        }
    );
    println!(
        "                        result {}",
        result.reasoning_result_digest
    );
}

fn print_verification(result: &VerificationResult) {
    println!(
        "VERIFIED  {} ({})",
        display_atom(&result.query),
        status_name(&result.result_status)
    );
    if let Some(evaluation_time) = &result.evaluation_time {
        println!("          evaluated at {evaluation_time}");
    }
    println!("          {} proof nodes", result.nodes_verified);
    for digest in &result.proof_digests {
        println!("          proof {digest}");
    }
}

fn status_name(status: &Status) -> &'static str {
    match status {
        Status::Proved => "proved",
        Status::Disproved => "disproved",
        Status::Inconsistent => "inconsistent",
        Status::Unknown => "unknown",
    }
}

fn display_atom(atom: &Atom) -> String {
    let arguments = atom
        .arguments
        .iter()
        .map(display_value)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{}{}({arguments})",
        if atom.negated { "not " } else { "" },
        atom.predicate
    )
}

fn display_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_unique_json, read_bounded};

    #[test]
    fn bounded_reader_rejects_input_before_reading_past_the_sentinel_byte() {
        let error = read_bounded("123456789".as_bytes(), 8).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "input exceeds the 8-byte limit");
    }

    #[test]
    fn bounded_reader_accepts_input_at_the_limit() {
        assert_eq!(read_bounded("12345678".as_bytes(), 8).unwrap(), "12345678");
    }

    #[test]
    fn unique_json_parser_rejects_duplicate_members_at_any_depth() {
        let error = parse_unique_json::<serde_json::Value>(
            r#"{"outer":[{"effect":"read","effect":"write"}]}"#,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate object member `effect`")
        );
    }

    #[test]
    fn unique_json_parser_rejects_unknown_members_at_any_depth() {
        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        struct Envelope {
            request: Request,
        }

        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        struct Request {
            action: Action,
        }

        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        struct Action {
            tool: String,
        }

        let error = parse_unique_json::<Envelope>(
            r#"{"request":{"action":{"tool":"deploy","execution_mode":"bypass"}}}"#,
        )
        .err()
        .expect("unknown member must fail closed");
        assert!(error.to_string().contains("execution_mode"));
    }

    #[test]
    fn unique_json_parser_preserves_nested_values() {
        let input = r#"{"number":42,"values":[null,true,"text",{"key":-1.5}]}"#;
        let parsed = parse_unique_json::<serde_json::Value>(input).unwrap();
        assert_eq!(
            parsed,
            serde_json::from_str::<serde_json::Value>(input).unwrap()
        );
    }
}
