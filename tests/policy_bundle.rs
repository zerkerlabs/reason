use std::{fs, path::Path};

use serde_json::{Value, json};
use tempfile::TempDir;
use zerker_reason::policy::{
    MAX_AGGREGATE_SOURCE_BYTES, MAX_POLICY_BUNDLE_BYTES, MAX_POLICY_SOURCES,
    MAX_POLICY_TEMPLATE_BYTES, MAX_SOURCE_BYTES, MAX_SOURCE_MANIFEST_BYTES, POLICY_BUNDLE_SCHEMA,
    POLICY_SOURCE_MANIFEST_SCHEMA, PolicyBundle, PolicyError, PolicySource, PolicySourceKind,
    PolicySourceManifest, PolicySourceScope, PolicyTemplate, lock_policy_bundle,
    parse_policy_bundle, parse_policy_source_manifest, parse_policy_template,
    validate_policy_bundle, validate_policy_source_manifest, validate_policy_template,
    verify_policy_sources,
};

type BoundedParser = fn(&[u8]) -> Result<(), PolicyError>;

fn manifest_fixture() -> PolicySourceManifest {
    parse_policy_source_manifest(include_bytes!("../examples/policy-source-manifest.json")).unwrap()
}

fn policy_fixture() -> PolicyTemplate {
    parse_policy_template(include_bytes!("../examples/policy-template.json")).unwrap()
}

fn source(path: impl Into<String>) -> PolicySource {
    PolicySource {
        path: path.into(),
        kind: PolicySourceKind::Context,
        scope: PolicySourceScope::Repository,
    }
}

fn manifest(sources: Vec<PolicySource>) -> PolicySourceManifest {
    PolicySourceManifest {
        schema: POLICY_SOURCE_MANIFEST_SCHEMA.to_owned(),
        sources,
    }
}

fn write_file(root: &Path, path: &str, bytes: &[u8]) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, bytes).unwrap();
}

fn copy_fixture_sources() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    for path in ["AGENTS.md", "CLAUDE.md", ".agents/skills/support/SKILL.md"] {
        write_file(
            root.path(),
            path,
            &fs::read(Path::new("tests/fixtures/policy-sources").join(path)).unwrap(),
        );
    }
    root
}

#[test]
fn locks_sorted_exact_source_commitments_deterministically() {
    let root = copy_fixture_sources();
    let manifest = manifest_fixture();
    let policy = policy_fixture();
    let first = lock_policy_bundle(root.path(), &manifest, &policy).unwrap();
    let second = lock_policy_bundle(root.path(), &manifest, &policy).unwrap();
    let mut reordered = manifest.clone();
    reordered.sources.reverse();
    let reordered = lock_policy_bundle(root.path(), &reordered, &policy).unwrap();

    assert_eq!(first.schema, POLICY_BUNDLE_SCHEMA);
    assert_eq!(first.bundle_digest, reordered.bundle_digest);
    assert_eq!(first.bundle_digest, second.bundle_digest);
    assert_eq!(
        first
            .sources
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        [".agents/skills/support/SKILL.md", "AGENTS.md", "CLAUDE.md"]
    );
    assert_eq!(
        first.bundle_digest,
        "sha256:8aa3219d40f9ca9362fe25b3c4e1ea26f38a60cffc909e4806be2642b96f4f39"
    );
    let json = serde_json::to_string(&first).unwrap();
    assert!(!json.contains("Agent policy source"));
    assert!(!json.contains(root.path().to_string_lossy().as_ref()));
    validate_policy_bundle(&first).unwrap();
    verify_policy_sources(root.path(), &first).unwrap();
}

#[test]
fn source_policy_and_metadata_mutations_change_or_invalidate_the_commitment() {
    let root = copy_fixture_sources();
    let original_manifest = manifest_fixture();
    let original_policy = policy_fixture();
    let locked = lock_policy_bundle(root.path(), &original_manifest, &original_policy).unwrap();

    fs::write(root.path().join("AGENTS.md"), b"changed policy source\n").unwrap();
    let drift = verify_policy_sources(root.path(), &locked)
        .unwrap_err()
        .to_string();
    assert!(drift.contains("source drift"));
    let relocked = lock_policy_bundle(root.path(), &original_manifest, &original_policy).unwrap();
    assert_ne!(locked.bundle_digest, relocked.bundle_digest);

    let mut changed_manifest = original_manifest.clone();
    changed_manifest.sources[0].scope = PolicySourceScope::Agent;
    let metadata_changed =
        lock_policy_bundle(root.path(), &changed_manifest, &original_policy).unwrap();
    assert_ne!(relocked.bundle_digest, metadata_changed.bundle_digest);

    let mut changed_policy = original_policy;
    changed_policy.ontology.version = "2".to_owned();
    let policy_changed =
        lock_policy_bundle(root.path(), &changed_manifest, &changed_policy).unwrap();
    assert_ne!(metadata_changed.bundle_digest, policy_changed.bundle_digest);
}

#[test]
fn strict_bounded_parsing_rejects_duplicates_unknowns_and_injected_query_or_time() {
    let duplicate = br#"{
      "schema":"zerker.reason.policy-source-manifest.v1",
      "sources":[{"path":"AGENTS.md","path":"CLAUDE.md","kind":"instruction","scope":"repository"}]
    }"#;
    assert!(
        parse_policy_source_manifest(duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate object member `path`")
    );

    let unsupported = br#"{
      "schema":"zerker.reason.policy-source-manifest.v0",
      "sources":[{"path":"AGENTS.md","kind":"instruction","scope":"repository"}]
    }"#;
    assert!(
        parse_policy_source_manifest(unsupported)
            .unwrap_err()
            .to_string()
            .contains("expected \"zerker.reason.policy-source-manifest.v1\"")
    );

    let unknown = br#"{
      "schema":"zerker.reason.policy-source-manifest.v1",
      "sources":[{"path":"AGENTS.md","kind":"instruction","scope":"repository","authority":true}]
    }"#;
    assert!(
        parse_policy_source_manifest(unknown)
            .unwrap_err()
            .to_string()
            .contains("unknown")
    );

    for injected in [
        ("query", json!({"predicate":"allow_all"})),
        ("evaluation_time", json!("2026-08-29T12:00:00Z")),
    ] {
        let mut value: Value =
            serde_json::from_slice(include_bytes!("../examples/policy-template.json")).unwrap();
        value[injected.0] = injected.1;
        assert!(
            parse_policy_template(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .to_string()
                .contains("unknown")
        );
    }

    let parser_boundaries: [(usize, BoundedParser); 3] = [
        (MAX_SOURCE_MANIFEST_BYTES, |bytes| {
            parse_policy_source_manifest(bytes).map(|_| ())
        }),
        (MAX_POLICY_TEMPLATE_BYTES, |bytes| {
            parse_policy_template(bytes).map(|_| ())
        }),
        (MAX_POLICY_BUNDLE_BYTES, |bytes| {
            parse_policy_bundle(bytes).map(|_| ())
        }),
    ];
    for (limit, parse) in parser_boundaries {
        let exact = vec![b' '; limit];
        assert!(!matches!(
            parse(&exact),
            Err(PolicyError::InputTooLarge { .. })
        ));
        let over = vec![b' '; limit + 1];
        assert!(matches!(
            parse(&over),
            Err(PolicyError::InputTooLarge { .. })
        ));
    }
}

#[test]
fn manifests_reject_unsupported_schema_count_and_portable_path_attacks() {
    let mut wrong = manifest(vec![source("AGENTS.md")]);
    wrong.schema = "zerker.reason.policy-source-manifest.v0".to_owned();
    assert!(validate_policy_source_manifest(&wrong).is_err());

    let exact_count = manifest(
        (0..MAX_POLICY_SOURCES)
            .map(|index| source(format!("source-{index}.md")))
            .collect(),
    );
    validate_policy_source_manifest(&exact_count).unwrap();
    let too_many = manifest(
        (0..=MAX_POLICY_SOURCES)
            .map(|index| source(format!("source-{index}.md")))
            .collect(),
    );
    assert!(validate_policy_source_manifest(&too_many).is_err());

    for path in [
        "../escape",
        "a/../escape",
        "/absolute",
        "C:/drive",
        "file:policy",
        "a//b",
        "a/./b",
        "a\\b",
        "trailing/",
        "control\nname",
        "bidi\u{202e}name",
        "cafe\u{301}.md",
    ] {
        let error = validate_policy_source_manifest(&manifest(vec![source(path)]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("$.sources[0].path"), "accepted {path:?}");
    }

    let duplicate = manifest(vec![source("AGENTS.md"), source("AGENTS.md")]);
    assert!(
        validate_policy_source_manifest(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate portable path")
    );

    let unicode = manifest(vec![source("policies/café.md")]);
    validate_policy_source_manifest(&unicode).unwrap();
    let exact_path = manifest(vec![source("a".repeat(4_096))]);
    validate_policy_source_manifest(&exact_path).unwrap();
    let overlong_path = manifest(vec![source("a".repeat(4_097))]);
    assert!(validate_policy_source_manifest(&overlong_path).is_err());

    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "policies/café.md", b"unicode source\n");
    let locked = lock_policy_bundle(root.path(), &unicode, &policy_fixture()).unwrap();
    assert_eq!(locked.sources[0].path, "policies/café.md");
    verify_policy_sources(root.path(), &locked).unwrap();
}

#[cfg(unix)]
#[test]
fn no_follow_resolution_rejects_root_component_and_final_symlinks() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::tempdir().unwrap();
    write_file(outside.path(), "secret.md", b"outside\n");
    let policy = policy_fixture();

    let parent = tempfile::tempdir().unwrap();
    symlink(outside.path(), parent.path().join("root-link")).unwrap();
    assert!(
        lock_policy_bundle(
            &parent.path().join("root-link"),
            &manifest(vec![source("secret.md")]),
            &policy
        )
        .is_err()
    );

    let root = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("linked-dir")).unwrap();
    assert!(
        lock_policy_bundle(
            root.path(),
            &manifest(vec![source("linked-dir/secret.md")]),
            &policy
        )
        .is_err()
    );

    symlink(
        outside.path().join("secret.md"),
        root.path().join("linked-file.md"),
    )
    .unwrap();
    assert!(
        lock_policy_bundle(
            root.path(),
            &manifest(vec![source("linked-file.md")]),
            &policy
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn no_follow_resolution_rejects_non_files_and_duplicate_file_identities() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("directory.md")).unwrap();
    let policy = policy_fixture();
    assert!(
        lock_policy_bundle(
            root.path(),
            &manifest(vec![source("directory.md")]),
            &policy
        )
        .is_err()
    );

    write_file(root.path(), "first.md", b"same inode\n");
    fs::hard_link(root.path().join("first.md"), root.path().join("second.md")).unwrap();
    let error = lock_policy_bundle(
        root.path(),
        &manifest(vec![source("first.md"), source("second.md")]),
        &policy,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("duplicates another source file identity"));
}

#[test]
fn source_byte_limits_accept_exact_and_reject_one_over_and_aggregate_over() {
    let root = tempfile::tempdir().unwrap();
    let policy = policy_fixture();
    write_file(
        root.path(),
        "exact.bin",
        &vec![b'x'; MAX_SOURCE_BYTES as usize],
    );
    let exact =
        lock_policy_bundle(root.path(), &manifest(vec![source("exact.bin")]), &policy).unwrap();
    assert_eq!(exact.sources[0].size_bytes, MAX_SOURCE_BYTES);

    write_file(
        root.path(),
        "over.bin",
        &vec![b'x'; MAX_SOURCE_BYTES as usize + 1],
    );
    assert!(
        lock_policy_bundle(root.path(), &manifest(vec![source("over.bin")]), &policy)
            .unwrap_err()
            .to_string()
            .contains("source exceeds")
    );

    let count = (MAX_AGGREGATE_SOURCE_BYTES / MAX_SOURCE_BYTES) as usize;
    let mut aggregate_sources = Vec::new();
    for index in 0..=count {
        let path = format!("aggregate-{index}.bin");
        write_file(
            root.path(),
            &path,
            &vec![index as u8; MAX_SOURCE_BYTES as usize],
        );
        aggregate_sources.push(source(path));
    }
    lock_policy_bundle(
        root.path(),
        &manifest(aggregate_sources[..count].to_vec()),
        &policy,
    )
    .unwrap();
    assert!(
        lock_policy_bundle(root.path(), &manifest(aggregate_sources), &policy)
            .unwrap_err()
            .to_string()
            .contains("aggregate source bytes exceed")
    );
}

#[test]
fn template_validation_reuses_reserved_action_namespace_checks() {
    let policy = policy_fixture();
    validate_policy_template(&policy).unwrap();

    let mut authority = policy.clone();
    authority
        .authority
        .classes
        .insert("system-bound".to_owned());
    assert!(
        validate_policy_template(&authority)
            .unwrap_err()
            .to_string()
            .contains("reserved for request bindings")
    );

    for (name, mutate) in [
        ("default admission", |policy: &mut PolicyTemplate| {
            policy
                .authority
                .default_admit
                .insert("system-bound".to_owned());
        }),
        ("predicate admission", |policy: &mut PolicyTemplate| {
            policy.ontology.predicates.insert(
                "reviewed".to_owned(),
                zerker_reason::Predicate {
                    arguments: vec![zerker_reason::ScalarType::String],
                },
            );
            policy.authority.predicate_admit.insert(
                "reviewed".to_owned(),
                ["system-bound".to_owned()].into_iter().collect(),
            );
        }),
    ] as [(&str, fn(&mut PolicyTemplate)); 2]
    {
        let mut admitted = policy.clone();
        mutate(&mut admitted);
        assert!(
            validate_policy_template(&admitted)
                .expect_err("the system-bound authority must be reserved in every admission list")
                .to_string()
                .contains("reserved for request bindings"),
            "unexpected error for {name}"
        );
    }

    let mut reserved_head = policy;
    reserved_head.rules[0].then.predicate = "action_tool".to_owned();
    assert!(
        validate_policy_template(&reserved_head)
            .unwrap_err()
            .to_string()
            .contains("can only be supplied by request bindings")
    );
}

#[test]
fn bundle_semantics_reject_tampering_order_and_aggregate_claims() {
    let root = copy_fixture_sources();
    let bundle = lock_policy_bundle(root.path(), &manifest_fixture(), &policy_fixture()).unwrap();
    let bytes = serde_json::to_vec(&bundle).unwrap();
    let parsed = parse_policy_bundle(&bytes).unwrap();
    validate_policy_bundle(&parsed).unwrap();

    let mut tampered: PolicyBundle = parsed;
    tampered.sources.swap(0, 1);
    assert!(
        validate_policy_bundle(&tampered)
            .unwrap_err()
            .to_string()
            .contains("strictly sorted")
    );

    let mut oversized_claims = bundle.clone();
    let prototype = oversized_claims.sources[0].clone();
    oversized_claims.sources = (0..17)
        .map(|index| {
            let mut entry = prototype.clone();
            entry.path = format!("source-{index:02}.md");
            entry.size_bytes = MAX_SOURCE_BYTES;
            entry
        })
        .collect();
    assert!(
        validate_policy_bundle(&oversized_claims)
            .unwrap_err()
            .to_string()
            .contains("aggregate size exceeds")
    );

    let mut value = serde_json::to_value(&bundle).unwrap();
    value["sources"][0]["digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert!(
        parse_policy_bundle(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .to_string()
            .contains("commitment mismatch")
    );
}
