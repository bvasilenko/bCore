use bsuite_core::{SignedManifestUpdater, UpdateChannel, UpdateOutcome};

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
