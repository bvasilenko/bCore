use bsuite_core::{
    ALLOWED_OVERRIDE_KEYS, ManifestOverlay, ManifestOverlayReader, OVERLAY_SCHEMA_VERSION,
    OverrideMap,
};

struct AlwaysEmptyReader;

impl ManifestOverlayReader for AlwaysEmptyReader {
    fn read(&self) -> Result<ManifestOverlay, bsuite_core::BsuiteCoreError> {
        Ok(ManifestOverlay::empty())
    }
}

#[test]
fn empty_overlay_has_expected_schema_version() {
    let overlay = ManifestOverlay::empty();
    assert_eq!(overlay.schema_version, OVERLAY_SCHEMA_VERSION);
}

#[test]
fn empty_overlay_has_all_none_overrides() {
    let overlay = ManifestOverlay::empty();
    assert_eq!(overlay.overrides, OverrideMap::default());
}

#[test]
fn trait_impl_returning_empty_compiles_and_reads() {
    let reader = AlwaysEmptyReader;
    let overlay = reader.read().expect("always-empty reader must not fail");
    assert_eq!(overlay, ManifestOverlay::empty());
}

#[test]
fn allowed_override_keys_match_the_six_override_map_fields() {
    let expected: &[&str] = &[
        "transcript_retention_days",
        "transcript_dir",
        "corpus_dir",
        "update_check_interval_minutes",
        "stdout_byte_cap",
        "binary_timeout_ms",
    ];
    assert_eq!(
        ALLOWED_OVERRIDE_KEYS, expected,
        "allowlist must match OverrideMap fields exactly"
    );
}
