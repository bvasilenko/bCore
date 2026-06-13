mod common;

use bsuite_core::{BsuiteCoreError, PlatformId, SignedManifest};
use common::signed_manifest;
use proptest::prelude::*;

fn parse_manifest_json(bytes: &[u8]) -> Result<SignedManifest, BsuiteCoreError> {
    serde_json::from_slice(bytes)
        .map_err(|error| BsuiteCoreError::ManifestFetchFailed(error.to_string()))
}

proptest! {
    #[test]
    fn valid_manifest_json_round_trips(binary in "[a-z][a-z0-9-]{0,20}", major in 0_u64..10, minor in 0_u64..20, patch in 0_u64..50) {
        let mut expected = signed_manifest(
            &format!("{major}.{minor}.{patch}"),
            "test-only-manifest-v1",
            PlatformId::LinuxX86_64,
            "https://example.test/b.tar".to_string(),
            "0".repeat(64),
        );
        expected.binary_name = binary;
        let bytes = serde_json::to_vec(&expected).expect("manifest serializes");
        let parsed = parse_manifest_json(&bytes).expect("manifest parses");

        prop_assert_eq!(parsed, expected);
    }
}

#[test]
fn malformed_manifest_json_returns_manifest_fetch_failed() {
    for json in [
        br#"{"schema_version":1,"version":"not-semver"}"#.as_slice(),
        br#"{"schema_version":1,"version":"1.2.3","platforms":[]}"#.as_slice(),
        br#"not-json"#.as_slice(),
    ] {
        let error = parse_manifest_json(json).expect_err("invalid manifest grammar must fail");

        assert!(matches!(error, BsuiteCoreError::ManifestFetchFailed(_)));
    }
}

#[test]
fn platform_keys_cover_supported_targets() {
    assert_eq!(
        PlatformId::from_target("linux", "x86_64").unwrap().key(),
        "linux-x86_64"
    );
    assert_eq!(
        PlatformId::from_target("linux", "aarch64").unwrap().key(),
        "linux-aarch64"
    );
    assert_eq!(
        PlatformId::from_target("macos", "x86_64").unwrap().key(),
        "macos-x86_64"
    );
    assert_eq!(
        PlatformId::from_target("macos", "aarch64").unwrap().key(),
        "macos-aarch64"
    );
    assert_eq!(
        PlatformId::from_target("windows", "x86_64").unwrap().key(),
        "windows-x86_64"
    );
    assert_eq!(PlatformId::from_target("windows", "aarch64"), None);
}
