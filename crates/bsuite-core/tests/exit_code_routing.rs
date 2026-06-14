mod common;

use bsuite_core::{BsuiteCoreError, ExitCode, ExitCodeRouting, OverlayValidationError, RoutingKey};
use proptest::prelude::*;

fn route(err: BsuiteCoreError) -> ExitCode {
    BsuiteCoreError::route(&err)
}

fn all_internal_error_variants() -> Vec<BsuiteCoreError> {
    vec![
        BsuiteCoreError::PromptResolution("x".into()),
        BsuiteCoreError::Update("x".into()),
        BsuiteCoreError::Transcript("x".into()),
        BsuiteCoreError::TranscriptPathFailed("x".into()),
        BsuiteCoreError::TranscriptWriteFailed("x".into()),
        BsuiteCoreError::TranscriptSerializationFailed("x".into()),
        BsuiteCoreError::TranscriptManifestFailed("x".into()),
        BsuiteCoreError::ManifestFetchFailed("x".into()),
        BsuiteCoreError::SignatureFetchFailed("x".into()),
        BsuiteCoreError::ManifestSignatureInvalid,
        BsuiteCoreError::ManifestUnknownSigningKey("x".into()),
        BsuiteCoreError::ManifestSigningKeyExpired("x".into()),
        BsuiteCoreError::ManifestSigningKeyNotYetValid("x".into()),
        BsuiteCoreError::ManifestSigningKeyRevoked("x".into()),
        BsuiteCoreError::ManifestSchemaMismatch {
            expected: 1,
            found: 2,
        },
        BsuiteCoreError::ManifestPlatformMissing("x".into()),
        BsuiteCoreError::ArtifactFetchFailed("x".into()),
        BsuiteCoreError::ArtifactSha256Mismatch {
            expected: "aaa".into(),
            found: "bbb".into(),
        },
        BsuiteCoreError::ResponseBodyTooLarge {
            limit_bytes: 1,
            found_bytes: 2,
        },
        BsuiteCoreError::AtomicInstallFailed("x".into()),
        BsuiteCoreError::InstallRollbackFailed("x".into()),
        BsuiteCoreError::ExitCode("x".into()),
        BsuiteCoreError::VisibilityEvidence("x".into()),
        BsuiteCoreError::AdapterHostBinding("x".into()),
        BsuiteCoreError::CorpusSignatureInvalid,
        BsuiteCoreError::CorpusSchemaMismatch {
            expected: 1,
            found: 2,
        },
        BsuiteCoreError::CorpusDeserializationFailed("x".into()),
        BsuiteCoreError::CorpusKeyMissing(RoutingKey::BGround),
        BsuiteCoreError::OpacitySectionMissing("x".into()),
        BsuiteCoreError::OpacityTomlParseFailed("x".into()),
        BsuiteCoreError::OpacityTierMismatch { expected: "a".into(), found: "b".into() },
        BsuiteCoreError::OpacitySchemaMismatch { expected: 1, found: 2 },
    ]
}

#[test]
fn all_internal_error_variants_route_to_internal_error() {
    for err in all_internal_error_variants() {
        assert_eq!(
            route(err.clone()),
            ExitCode::InternalError,
            "expected InternalError for {err:?}",
        );
    }
}

#[test]
fn all_overlay_validation_sub_variants_route_to_usage() {
    for sub in common::all_overlay_validation_sub_variants() {
        assert_eq!(
            route(BsuiteCoreError::ManifestOverlay(sub.clone())),
            ExitCode::Usage,
            "expected Usage for ManifestOverlay({sub:?})",
        );
    }
}

#[test]
fn routing_classes_are_disjoint_and_exhaustive_over_all_error_variants() {
    for err in common::all_bsuite_core_error_variants() {
        let class = route(err.clone());
        assert!(
            class == ExitCode::InternalError || class == ExitCode::Usage,
            "routing must yield InternalError or Usage, got {class:?} for {err:?}",
        );
    }
}

proptest! {
    #[test]
    fn manifest_schema_mismatch_routing_is_independent_of_version_values(
        expected in 0_u32..u32::MAX,
        found in 0_u32..u32::MAX,
    ) {
        assert_eq!(
            route(BsuiteCoreError::ManifestSchemaMismatch { expected, found }),
            ExitCode::InternalError,
        );
    }

    #[test]
    fn corpus_schema_mismatch_routing_is_independent_of_version_values(
        expected in 0_u32..u32::MAX,
        found in 0_u32..u32::MAX,
    ) {
        assert_eq!(
            route(BsuiteCoreError::CorpusSchemaMismatch { expected, found }),
            ExitCode::InternalError,
        );
    }

    #[test]
    fn response_body_routing_is_independent_of_byte_counts(
        limit_bytes in 0_u64..u64::MAX,
        found_bytes in 0_u64..u64::MAX,
    ) {
        assert_eq!(
            route(BsuiteCoreError::ResponseBodyTooLarge { limit_bytes, found_bytes }),
            ExitCode::InternalError,
        );
    }

    #[test]
    fn artifact_sha256_mismatch_routing_is_independent_of_hash_strings(
        expected in "[a-f0-9]{0,64}",
        found in "[a-f0-9]{0,64}",
    ) {
        assert_eq!(
            route(BsuiteCoreError::ArtifactSha256Mismatch { expected, found }),
            ExitCode::InternalError,
        );
    }

    #[test]
    fn overlay_schema_mismatch_routing_is_independent_of_version_values(
        expected in 0_u32..u32::MAX,
        found in 0_u32..u32::MAX,
    ) {
        assert_eq!(
            route(BsuiteCoreError::ManifestOverlay(
                OverlayValidationError::SchemaMismatch { expected, found }
            )),
            ExitCode::Usage,
        );
    }

    #[test]
    fn string_typed_internal_error_variants_routing_is_independent_of_message_content(
        msg in ".*"
    ) {
        let variants = vec![
            BsuiteCoreError::PromptResolution(msg.clone()),
            BsuiteCoreError::Update(msg.clone()),
            BsuiteCoreError::Transcript(msg.clone()),
            BsuiteCoreError::TranscriptPathFailed(msg.clone()),
            BsuiteCoreError::TranscriptWriteFailed(msg.clone()),
            BsuiteCoreError::TranscriptSerializationFailed(msg.clone()),
            BsuiteCoreError::TranscriptManifestFailed(msg.clone()),
            BsuiteCoreError::ManifestFetchFailed(msg.clone()),
            BsuiteCoreError::SignatureFetchFailed(msg.clone()),
            BsuiteCoreError::ManifestUnknownSigningKey(msg.clone()),
            BsuiteCoreError::ManifestSigningKeyExpired(msg.clone()),
            BsuiteCoreError::ManifestSigningKeyNotYetValid(msg.clone()),
            BsuiteCoreError::ManifestSigningKeyRevoked(msg.clone()),
            BsuiteCoreError::ManifestPlatformMissing(msg.clone()),
            BsuiteCoreError::ArtifactFetchFailed(msg.clone()),
            BsuiteCoreError::AtomicInstallFailed(msg.clone()),
            BsuiteCoreError::InstallRollbackFailed(msg.clone()),
            BsuiteCoreError::ExitCode(msg.clone()),
            BsuiteCoreError::VisibilityEvidence(msg.clone()),
            BsuiteCoreError::AdapterHostBinding(msg.clone()),
            BsuiteCoreError::CorpusDeserializationFailed(msg.clone()),
            BsuiteCoreError::OpacitySectionMissing(msg.clone()),
            BsuiteCoreError::OpacityTomlParseFailed(msg.clone()),
        ];
        for err in variants {
            assert_eq!(route(err), ExitCode::InternalError);
        }
    }

    #[test]
    fn overlay_validation_string_fields_routing_is_independent_of_content(
        msg in ".*",
        key in ".*",
    ) {
        assert_eq!(
            route(BsuiteCoreError::ManifestOverlay(
                OverlayValidationError::TomlParseFailed(msg)
            )),
            ExitCode::Usage,
        );
        assert_eq!(
            route(BsuiteCoreError::ManifestOverlay(
                OverlayValidationError::UnknownKey { key }
            )),
            ExitCode::Usage,
        );
    }
}
