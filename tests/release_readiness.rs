use std::{fs, path::Path};

use serde_json::Value;

fn cargo_version() -> String {
    fs::read_to_string("Cargo.toml")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
        .unwrap()
        .to_owned()
}

#[test]
fn v030_versions_and_public_fixture_metadata_agree() {
    let version = cargo_version();
    assert_eq!(version, "0.3.0");

    let lock = fs::read_to_string("Cargo.lock").unwrap();
    assert!(lock.contains("name = \"zerker-reason\"\nversion = \"0.3.0\""));

    if Path::new("website").exists() {
        let manifest: Value =
            serde_json::from_slice(&fs::read("website/data/reason/manifest.json").unwrap())
                .unwrap();
        assert_eq!(manifest["generator"], format!("reason {version}"));
    }

    let changelog = fs::read_to_string("CHANGELOG.md").unwrap();
    assert!(changelog.contains("## [0.3.0] - 2026-09-01"));
    assert!(changelog.contains("## [0.2.0] - 2026-08-21"));
    assert!(fs::read_to_string("docs/MIGRATING-0.2.md").is_ok());
    assert!(fs::read_to_string("docs/V0.2-COMPATIBILITY.md").is_ok());
}

#[test]
fn release_workflow_stages_every_platform_before_publication() {
    let workflow = fs::read_to_string(".github/workflows/release.yml").unwrap();
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ] {
        assert!(workflow.contains(target), "release omits {target}");
    }
    for required in [
        "needs: validate",
        "needs: build",
        "Require tag and package version alignment",
        "Replay authorization conformance corpus",
        "actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4",
        "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0",
        "--verify-tag --draft",
        "native_smoke: false",
        "gh release edit",
        "schemas conformance scripts",
    ] {
        assert!(
            workflow.contains(required),
            "release gate omitted {required}"
        );
    }

    let build = workflow.find("  build:").unwrap();
    let publish = workflow.find("  publish:").unwrap();
    let create = workflow.find("gh release create").unwrap();
    assert!(build < publish && publish < create);
}
