use bsuite_core::{FetchLimits, SignedManifestUpdater, UpdateChannel, UpdateOutcome};

#[test]
fn embedded_trust_bundle_constructs_signed_manifest_updater() {
    let _updater = SignedManifestUpdater::new().expect("embedded trust bundle must parse");
}

#[test]
fn update_channel_preserves_inner_value() {
    let channel = UpdateChannel::new("stable");

    assert_eq!(channel.as_str(), "stable");
    assert_eq!(channel.into_inner(), "stable");
}

#[test]
fn update_outcome_exposes_expected_shapes() {
    assert_eq!(UpdateOutcome::UpToDate, UpdateOutcome::UpToDate);
}

#[test]
fn fetch_limits_default_matches_production_sizes() {
    let limits = FetchLimits::default();
    assert_eq!(limits.manifest_body_bytes, 1024 * 1024);
    assert_eq!(limits.signature_body_bytes, 1024 * 8);
    assert_eq!(limits.archive_body_bytes, 1024 * 1024 * 100);
}

#[test]
fn fetch_limits_fields_are_independently_addressable() {
    let limits = FetchLimits {
        manifest_body_bytes: 100,
        signature_body_bytes: 200,
        archive_body_bytes: 300,
    };
    assert_eq!(limits.manifest_body_bytes, 100);
    assert_eq!(limits.signature_body_bytes, 200);
    assert_eq!(limits.archive_body_bytes, 300);
}
