use bsuite_core::{BinaryDefaults, ManifestOverlay, OverrideMap};
use std::path::PathBuf;

fn defaults() -> BinaryDefaults {
    BinaryDefaults {
        transcript_retention_days: 90,
        transcript_dir: PathBuf::from("/default/transcripts"),
        corpus_dir: PathBuf::from("/default/corpus"),
        update_check_interval_minutes: 60,
        stdout_byte_cap: 65536,
        binary_timeout_ms: 5000,
    }
}

fn overlay_with(overrides: OverrideMap) -> ManifestOverlay {
    ManifestOverlay {
        schema_version: 1,
        overrides,
    }
}

#[test]
fn empty_overlay_leaves_all_defaults_untouched() {
    let overlay = ManifestOverlay::empty();
    let mut d = defaults();
    let expected = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d, expected);
}

#[test]
fn partial_overlay_merges_only_the_three_specified_fields() {
    let overlay = overlay_with(OverrideMap {
        transcript_retention_days: Some(30),
        stdout_byte_cap: Some(8192),
        binary_timeout_ms: Some(2000),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);

    assert_eq!(d.transcript_retention_days, 30);
    assert_eq!(d.stdout_byte_cap, 8192);
    assert_eq!(d.binary_timeout_ms, 2000);
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
    assert_eq!(d.update_check_interval_minutes, 60);
}

#[test]
fn only_transcript_retention_days_is_updated_when_only_that_field_is_set() {
    let overlay = overlay_with(OverrideMap {
        transcript_retention_days: Some(1),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 1);
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
    assert_eq!(d.update_check_interval_minutes, 60);
    assert_eq!(d.stdout_byte_cap, 65536);
    assert_eq!(d.binary_timeout_ms, 5000);
}

#[test]
fn only_transcript_dir_is_updated_when_only_that_field_is_set() {
    let overlay = overlay_with(OverrideMap {
        transcript_dir: Some(PathBuf::from("/custom/transcripts")),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 90);
    assert_eq!(d.transcript_dir, PathBuf::from("/custom/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
    assert_eq!(d.update_check_interval_minutes, 60);
    assert_eq!(d.stdout_byte_cap, 65536);
    assert_eq!(d.binary_timeout_ms, 5000);
}

#[test]
fn only_corpus_dir_is_updated_when_only_that_field_is_set() {
    let overlay = overlay_with(OverrideMap {
        corpus_dir: Some(PathBuf::from("/custom/corpus")),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 90);
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/custom/corpus"));
    assert_eq!(d.update_check_interval_minutes, 60);
    assert_eq!(d.stdout_byte_cap, 65536);
    assert_eq!(d.binary_timeout_ms, 5000);
}

#[test]
fn only_update_check_interval_minutes_is_updated_when_only_that_field_is_set() {
    let overlay = overlay_with(OverrideMap {
        update_check_interval_minutes: Some(5),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 90);
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
    assert_eq!(d.update_check_interval_minutes, 5);
    assert_eq!(d.stdout_byte_cap, 65536);
    assert_eq!(d.binary_timeout_ms, 5000);
}

#[test]
fn only_stdout_byte_cap_is_updated_when_only_that_field_is_set() {
    let overlay = overlay_with(OverrideMap {
        stdout_byte_cap: Some(512),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 90);
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
    assert_eq!(d.update_check_interval_minutes, 60);
    assert_eq!(d.stdout_byte_cap, 512);
    assert_eq!(d.binary_timeout_ms, 5000);
}

#[test]
fn only_binary_timeout_ms_is_updated_when_only_that_field_is_set() {
    let overlay = overlay_with(OverrideMap {
        binary_timeout_ms: Some(100),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 90);
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
    assert_eq!(d.update_check_interval_minutes, 60);
    assert_eq!(d.stdout_byte_cap, 65536);
    assert_eq!(d.binary_timeout_ms, 100);
}

#[test]
fn full_overlay_replaces_all_six_fields() {
    let overlay = overlay_with(OverrideMap {
        transcript_retention_days: Some(14),
        transcript_dir: Some(PathBuf::from("/custom/transcripts")),
        corpus_dir: Some(PathBuf::from("/custom/corpus")),
        update_check_interval_minutes: Some(120),
        stdout_byte_cap: Some(4096),
        binary_timeout_ms: Some(1000),
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);

    assert_eq!(d.transcript_retention_days, 14);
    assert_eq!(d.transcript_dir, PathBuf::from("/custom/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/custom/corpus"));
    assert_eq!(d.update_check_interval_minutes, 120);
    assert_eq!(d.stdout_byte_cap, 4096);
    assert_eq!(d.binary_timeout_ms, 1000);
}

#[test]
fn some_zero_for_numeric_fields_overwrites_default_not_ignored() {
    let overlay = overlay_with(OverrideMap {
        transcript_retention_days: Some(0),
        update_check_interval_minutes: Some(0),
        stdout_byte_cap: Some(0),
        binary_timeout_ms: Some(0),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);

    assert_eq!(
        d.transcript_retention_days, 0,
        "Some(0) must overwrite default"
    );
    assert_eq!(
        d.update_check_interval_minutes, 0,
        "Some(0) must overwrite default"
    );
    assert_eq!(d.stdout_byte_cap, 0, "Some(0) must overwrite default");
    assert_eq!(d.binary_timeout_ms, 0, "Some(0) must overwrite default");
    assert_eq!(d.transcript_dir, PathBuf::from("/default/transcripts"));
    assert_eq!(d.corpus_dir, PathBuf::from("/default/corpus"));
}

#[test]
fn merge_is_idempotent_when_applied_twice_with_same_overlay() {
    let overlay = overlay_with(OverrideMap {
        transcript_retention_days: Some(7),
        ..Default::default()
    });
    let mut d = defaults();
    overlay.merge_into_defaults(&mut d);
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d.transcript_retention_days, 7);
}

#[test]
fn merge_does_not_affect_fields_explicitly_set_to_none() {
    let overlay = overlay_with(OverrideMap {
        transcript_retention_days: None,
        transcript_dir: None,
        corpus_dir: None,
        update_check_interval_minutes: None,
        stdout_byte_cap: None,
        binary_timeout_ms: None,
    });
    let mut d = defaults();
    let expected = defaults();
    overlay.merge_into_defaults(&mut d);
    assert_eq!(d, expected);
}

#[test]
fn second_merge_overrides_values_set_by_first_merge() {
    let overlay_a = overlay_with(OverrideMap {
        transcript_retention_days: Some(7),
        stdout_byte_cap: Some(1024),
        ..Default::default()
    });
    let overlay_b = overlay_with(OverrideMap {
        transcript_retention_days: Some(30),
        binary_timeout_ms: Some(999),
        ..Default::default()
    });
    let mut d = defaults();
    overlay_a.merge_into_defaults(&mut d);
    overlay_b.merge_into_defaults(&mut d);

    assert_eq!(
        d.transcript_retention_days, 30,
        "overlay_b must win on transcript_retention_days"
    );
    assert_eq!(
        d.stdout_byte_cap, 1024,
        "overlay_a value must survive where overlay_b is None"
    );
    assert_eq!(
        d.binary_timeout_ms, 999,
        "overlay_b must write binary_timeout_ms"
    );
    assert_eq!(
        d.update_check_interval_minutes, 60,
        "untouched fields keep defaults"
    );
}
