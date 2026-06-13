use bsuite_core::{
    ALLOWED_OVERRIDE_KEYS, ManifestOverlay, OVERLAY_SCHEMA_VERSION, OverlayValidationError,
};
use proptest::prelude::*;
use std::path::PathBuf;

fn parse(toml: &str) -> Result<ManifestOverlay, OverlayValidationError> {
    let toml_value: toml::Value =
        toml::from_str(toml).map_err(|e| OverlayValidationError::TomlParseFailed(e.to_string()))?;

    validate_keys(&toml_value)?;

    let overlay: ManifestOverlay =
        toml::from_str(toml).map_err(|e| OverlayValidationError::TomlParseFailed(e.to_string()))?;

    if overlay.schema_version != OVERLAY_SCHEMA_VERSION {
        return Err(OverlayValidationError::SchemaMismatch {
            expected: OVERLAY_SCHEMA_VERSION,
            found: overlay.schema_version,
        });
    }

    Ok(overlay)
}

fn validate_keys(value: &toml::Value) -> Result<(), OverlayValidationError> {
    let Some(overrides) = value.get("overrides") else {
        return Ok(());
    };
    let toml::Value::Table(table) = overrides else {
        return Err(OverlayValidationError::TomlParseFailed(
            "[overrides] must be a table".into(),
        ));
    };
    for key in table.keys() {
        if !ALLOWED_OVERRIDE_KEYS.contains(&key.as_str()) {
            return Err(OverlayValidationError::UnknownKey { key: key.clone() });
        }
    }
    Ok(())
}

#[test]
fn empty_overrides_section_parses_to_all_none() {
    let toml = "schema_version = 1\n[overrides]\n";
    let overlay = parse(toml).expect("valid TOML");
    assert_eq!(overlay.schema_version, 1);
    assert!(overlay.overrides.transcript_retention_days.is_none());
    assert!(overlay.overrides.transcript_dir.is_none());
    assert!(overlay.overrides.corpus_dir.is_none());
    assert!(overlay.overrides.update_check_interval_minutes.is_none());
    assert!(overlay.overrides.stdout_byte_cap.is_none());
    assert!(overlay.overrides.binary_timeout_ms.is_none());
}

#[test]
fn no_overrides_section_parses_to_all_none() {
    let toml = "schema_version = 1\n";
    let overlay = parse(toml).expect("valid TOML");
    assert_eq!(overlay.overrides, bsuite_core::OverrideMap::default());
}

#[test]
fn all_six_override_keys_parse_correctly() {
    let toml = r#"
schema_version = 1

[overrides]
transcript_retention_days = 30
transcript_dir = "/var/log/bsuite"
corpus_dir = "/usr/share/bsuite"
update_check_interval_minutes = 120
stdout_byte_cap = 8192
binary_timeout_ms = 3000
"#;
    let overlay = parse(toml).expect("valid TOML");
    assert_eq!(overlay.overrides.transcript_retention_days, Some(30));
    assert_eq!(
        overlay.overrides.transcript_dir,
        Some(PathBuf::from("/var/log/bsuite"))
    );
    assert_eq!(
        overlay.overrides.corpus_dir,
        Some(PathBuf::from("/usr/share/bsuite"))
    );
    assert_eq!(overlay.overrides.update_check_interval_minutes, Some(120));
    assert_eq!(overlay.overrides.stdout_byte_cap, Some(8192));
    assert_eq!(overlay.overrides.binary_timeout_ms, Some(3000));
}

#[test]
fn partial_three_of_six_keys_parse_with_rest_none() {
    let toml = r#"
schema_version = 1

[overrides]
transcript_retention_days = 14
stdout_byte_cap = 4096
binary_timeout_ms = 1000
"#;
    let overlay = parse(toml).expect("valid TOML");
    assert_eq!(overlay.overrides.transcript_retention_days, Some(14));
    assert_eq!(overlay.overrides.stdout_byte_cap, Some(4096));
    assert_eq!(overlay.overrides.binary_timeout_ms, Some(1000));
    assert!(overlay.overrides.transcript_dir.is_none());
    assert!(overlay.overrides.corpus_dir.is_none());
    assert!(overlay.overrides.update_check_interval_minutes.is_none());
}

#[test]
fn malformed_toml_returns_toml_parse_failed() {
    let result = parse("this is not toml }{");
    assert!(
        matches!(result, Err(OverlayValidationError::TomlParseFailed(_))),
        "expected TomlParseFailed, got {result:?}"
    );
}

#[test]
fn missing_schema_version_key_returns_toml_parse_failed() {
    let result = parse("[overrides]\ntranscript_retention_days = 30\n");
    assert!(
        matches!(result, Err(OverlayValidationError::TomlParseFailed(_))),
        "expected TomlParseFailed for missing schema_version, got {result:?}"
    );
}

#[test]
fn overrides_not_a_table_returns_toml_parse_failed() {
    let result = parse("schema_version = 1\noverrides = 42\n");
    assert!(
        matches!(result, Err(OverlayValidationError::TomlParseFailed(_))),
        "expected TomlParseFailed when [overrides] is a scalar, got {result:?}"
    );
}

#[test]
fn unknown_key_in_overrides_returns_unknown_key_error() {
    let toml = r#"
schema_version = 1

[overrides]
transcript_retention_days = 30
forbidden_field = "nope"
"#;
    let result = parse(toml);
    assert!(
        matches!(result, Err(OverlayValidationError::UnknownKey { ref key }) if key == "forbidden_field"),
        "expected UnknownKey(forbidden_field), got {result:?}"
    );
}

#[test]
fn schema_version_mismatch_returns_schema_mismatch_error() {
    let toml = "schema_version = 99\n[overrides]\n";
    let result = parse(toml);
    assert!(
        matches!(
            result,
            Err(OverlayValidationError::SchemaMismatch {
                expected: 1,
                found: 99
            })
        ),
        "expected SchemaMismatch, got {result:?}"
    );
}

#[test]
fn schema_version_zero_returns_schema_mismatch_error() {
    let result = parse("schema_version = 0\n[overrides]\n");
    assert!(
        matches!(
            result,
            Err(OverlayValidationError::SchemaMismatch {
                expected: 1,
                found: 0
            })
        ),
        "expected SchemaMismatch for schema_version=0, got {result:?}"
    );
}

proptest! {
    #[test]
    fn valid_retention_days_round_trips(days in 1u32..=36500) {
        let toml = format!("schema_version = 1\n[overrides]\ntranscript_retention_days = {days}\n");
        let overlay = parse(&toml).expect("valid TOML");
        prop_assert_eq!(overlay.overrides.transcript_retention_days, Some(days));
    }

    #[test]
    fn valid_update_check_interval_minutes_round_trips(minutes in 1u32..=525600) {
        let toml = format!("schema_version = 1\n[overrides]\nupdate_check_interval_minutes = {minutes}\n");
        let overlay = parse(&toml).expect("valid TOML");
        prop_assert_eq!(overlay.overrides.update_check_interval_minutes, Some(minutes));
    }

    #[test]
    fn valid_stdout_byte_cap_round_trips(cap in 1u64..=u32::MAX as u64) {
        let toml = format!("schema_version = 1\n[overrides]\nstdout_byte_cap = {cap}\n");
        let overlay = parse(&toml).expect("valid TOML");
        prop_assert_eq!(overlay.overrides.stdout_byte_cap, Some(cap));
    }

    #[test]
    fn valid_binary_timeout_ms_round_trips(ms in 1u64..=u32::MAX as u64) {
        let toml = format!("schema_version = 1\n[overrides]\nbinary_timeout_ms = {ms}\n");
        let overlay = parse(&toml).expect("valid TOML");
        prop_assert_eq!(overlay.overrides.binary_timeout_ms, Some(ms));
    }
}
