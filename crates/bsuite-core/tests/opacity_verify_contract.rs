#![cfg(feature = "verify")]

use std::io::Write as _;

use bsuite_core::BsuiteCoreError;
use tempfile::NamedTempFile;

bsuite_core::tier_evidence_marker!("fixtures/tier_evidence_sample.toml");

#[test]
fn valid_section_and_matching_tier_returns_ok() {
    let exe = std::env::current_exe().expect("current_exe must be available in test context");
    let evidence = bsuite_core::verify_tier_evidence(&exe, "T1")
        .expect("test binary must contain a valid opacity section with tier_id T1");
    assert_eq!(evidence.tier_id, "T1");
    assert_eq!(evidence.schema_version, 1);
    assert_eq!(evidence.probes.bogus_control_flow_blocks, 143);
}

#[test]
fn tier_mismatch_returns_opacity_tier_mismatch_error() {
    let exe = std::env::current_exe().unwrap();
    let result = bsuite_core::verify_tier_evidence(&exe, "wrong-tier-id");
    assert!(
        matches!(result, Err(BsuiteCoreError::OpacityTierMismatch { .. })),
        "expected OpacityTierMismatch, got {result:?}",
    );
}

#[test]
fn section_missing_from_nonexistent_file_returns_section_missing_error() {
    let result = bsuite_core::verify_tier_evidence(
        std::path::Path::new("/nonexistent/__bsuite_opacity_test_fixture__"),
        "T1",
    );
    assert!(
        matches!(result, Err(BsuiteCoreError::OpacitySectionMissing(_))),
        "expected OpacitySectionMissing for missing file, got {result:?}",
    );
}

#[test]
fn section_missing_from_unrecognized_bytes_returns_section_missing_error() {
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"this is not a valid ELF Mach-O or PE binary")
        .unwrap();
    let result = bsuite_core::verify_tier_evidence(tmp.path(), "T1");
    assert!(
        matches!(result, Err(BsuiteCoreError::OpacitySectionMissing(_))),
        "expected OpacitySectionMissing for unrecognized bytes, got {result:?}",
    );
}

#[test]
fn malformed_toml_content_returns_toml_parse_failed_error() {
    let result = bsuite_core::validate_tier_evidence_toml("not valid TOML [[[", "T1");
    assert!(
        matches!(result, Err(BsuiteCoreError::OpacityTomlParseFailed(_))),
        "expected OpacityTomlParseFailed, got {result:?}",
    );
}

#[test]
fn schema_version_mismatch_returns_schema_mismatch_error() {
    let wrong_schema = r#"
schema_version = 99
tier_id = "T1"
build_sha = "abc123"
signing_key_id = "key-01"

[probes]
control_flow_flattening_density = 0.5
instruction_substitution_coverage = 0.5
bogus_control_flow_blocks = 0
basic_block_splitting_ratio = 0.5
anti_debug_heuristic_score = 0.5
"#;
    let result = bsuite_core::validate_tier_evidence_toml(wrong_schema, "T1");
    assert!(
        matches!(
            result,
            Err(BsuiteCoreError::OpacitySchemaMismatch {
                expected: 1,
                found: 99
            })
        ),
        "expected OpacitySchemaMismatch{{expected:1, found:99}}, got {result:?}",
    );
}
