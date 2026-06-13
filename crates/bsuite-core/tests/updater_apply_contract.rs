mod common;

use bsuite_core::{BsuiteCoreError, FetchLimits, PlatformId, SignedManifestUpdater, UpdateOutcome};
use common::{
    executable_name, manifest_signing_key, raw_tar_with_unchecked_path, sha256_hex,
    signed_manifest, tar_with_file, trust_bundle,
};
use httpmock::Method::GET;
use httpmock::MockServer;
use std::fs;
use tempfile::tempdir;

const FETCH_ATTEMPTS: usize = 3;

fn serve_archive(server: &MockServer, status: u16, archive: Vec<u8>) {
    server.mock(|when, then| {
        when.method(GET).path("/archive.tar");
        then.status(status).body(archive);
    });
}

fn outcome_for_archive(server: &MockServer, platform: PlatformId, archive: &[u8]) -> UpdateOutcome {
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        sha256_hex(archive),
    );
    UpdateOutcome::UpgradeAvailable { manifest, platform }
}

fn updater() -> SignedManifestUpdater {
    let key = manifest_signing_key(17);
    SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap()
}

fn install_original(install_dir: &tempfile::TempDir, platform: PlatformId) {
    fs::write(
        install_dir.path().join(executable_name(platform)),
        b"old binary",
    )
    .unwrap();
}

fn assert_original_preserved(install_dir: &tempfile::TempDir, platform: PlatformId) {
    assert_eq!(
        fs::read(install_dir.path().join(executable_name(platform))).unwrap(),
        b"old binary"
    );
}

#[test]
fn atomic_rename_installs_new_executable() {
    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    serve_archive(&server, 200, archive.clone());
    let outcome = outcome_for_archive(&server, platform, &archive);
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    updater().apply(&outcome, install_dir.path()).unwrap();

    assert_eq!(
        fs::read(install_dir.path().join(executable_name(platform))).unwrap(),
        b"new binary"
    );
}

#[test]
fn up_to_date_apply_is_noop() {
    let platform = PlatformId::current();
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    updater()
        .apply(&UpdateOutcome::UpToDate, install_dir.path())
        .unwrap();

    assert_original_preserved(&install_dir, platform);
}

#[test]
fn artifact_fetch_failure_is_distinct_and_preserves_original() {
    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    serve_archive(&server, 503, archive.clone());
    let outcome = outcome_for_archive(&server, platform, &archive);
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .apply(&outcome, install_dir.path())
        .expect_err("artifact HTTP failure must fail");

    assert!(matches!(error, BsuiteCoreError::ArtifactFetchFailed(_)));
    assert_original_preserved(&install_dir, platform);
}

#[test]
fn sha256_mismatch_rejects_without_replacing_original() {
    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    serve_archive(&server, 200, archive);
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "f".repeat(64),
    );
    let outcome = UpdateOutcome::UpgradeAvailable { manifest, platform };
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .apply(&outcome, install_dir.path())
        .expect_err("hash mismatch must fail");

    assert!(matches!(
        error,
        BsuiteCoreError::ArtifactSha256Mismatch { .. }
    ));
    assert_original_preserved(&install_dir, platform);
}

#[test]
fn archive_extraction_failures_preserve_original() {
    let cases = [
        raw_tar_with_unchecked_path("../bground", b"evil binary"),
        b"not a tar archive".to_vec(),
    ];

    for archive in cases {
        let server = MockServer::start();
        let platform = PlatformId::current();
        serve_archive(&server, 200, archive.clone());
        let outcome = outcome_for_archive(&server, platform, &archive);
        let install_dir = tempdir().unwrap();
        install_original(&install_dir, platform);

        let error = updater()
            .apply(&outcome, install_dir.path())
            .expect_err("archive extraction failure must fail");

        assert!(matches!(error, BsuiteCoreError::AtomicInstallFailed(_)));
        assert_original_preserved(&install_dir, platform);
    }
}

#[test]
fn missing_expected_executable_rejects_and_preserves_original() {
    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file("other-name", b"new binary");
    serve_archive(&server, 200, archive.clone());
    let outcome = outcome_for_archive(&server, platform, &archive);
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .apply(&outcome, install_dir.path())
        .expect_err("missing executable must fail");

    assert!(matches!(error, BsuiteCoreError::AtomicInstallFailed(_)));
    assert_original_preserved(&install_dir, platform);
}

#[test]
fn oversized_artifact_response_is_rejected_without_replacing_original() {
    const SMALL_LIMIT: u64 = 5;

    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    server.mock(|when, then| {
        when.method(GET).path("/archive.tar");
        then.status(200).body(vec![0u8; SMALL_LIMIT as usize + 1]);
    });
    let outcome = outcome_for_archive(&server, platform, &archive);
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .with_fetch_limits(FetchLimits {
            archive_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        })
        .apply(&outcome, install_dir.path())
        .expect_err("oversized artifact must fail");

    assert_eq!(
        error,
        BsuiteCoreError::ResponseBodyTooLarge {
            limit_bytes: SMALL_LIMIT,
            found_bytes: SMALL_LIMIT + 1,
        }
    );
    assert_original_preserved(&install_dir, platform);
}

#[test]
fn transient_artifact_fetch_failure_is_retried_without_replacing_original() {
    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    let archive_mock = server.mock(|when, then| {
        when.method(GET).path("/archive.tar");
        then.status(503);
    });
    let outcome = outcome_for_archive(&server, platform, &archive);
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .apply(&outcome, install_dir.path())
        .expect_err("transient artifact failure must fail");

    assert!(matches!(error, BsuiteCoreError::ArtifactFetchFailed(_)));
    assert_eq!(archive_mock.hits(), FETCH_ATTEMPTS);
    assert_original_preserved(&install_dir, platform);
}

#[test]
fn artifact_hash_rejection_is_not_retried() {
    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    let archive_mock = server.mock(|when, then| {
        when.method(GET).path("/archive.tar");
        then.status(200).body(archive);
    });
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "f".repeat(64),
    );
    let outcome = UpdateOutcome::UpgradeAvailable { manifest, platform };
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .apply(&outcome, install_dir.path())
        .expect_err("hash mismatch must fail");

    assert!(matches!(
        error,
        BsuiteCoreError::ArtifactSha256Mismatch { .. }
    ));
    assert_eq!(archive_mock.hits(), 1);
    assert_original_preserved(&install_dir, platform);
}

#[test]
fn artifact_body_exactly_at_limit_is_accepted_by_size_check() {
    const SMALL_LIMIT: u64 = 5;
    let body = vec![0u8; SMALL_LIMIT as usize];

    let server = MockServer::start();
    let platform = PlatformId::current();
    serve_archive(&server, 200, body.clone());
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        sha256_hex(&body),
    );
    let outcome = UpdateOutcome::UpgradeAvailable { manifest, platform };
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .with_fetch_limits(FetchLimits {
            archive_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        })
        .apply(&outcome, install_dir.path())
        .expect_err("body at size limit must not be rejected by size check");

    assert!(
        !matches!(error, BsuiteCoreError::ResponseBodyTooLarge { .. }),
        "body exactly at limit must not be rejected by size check"
    );
    assert!(matches!(error, BsuiteCoreError::AtomicInstallFailed(_)));
}

#[test]
fn oversized_artifact_response_is_not_retried() {
    const SMALL_LIMIT: u64 = 5;

    let server = MockServer::start();
    let platform = PlatformId::current();
    let archive = tar_with_file(executable_name(platform), b"new binary");
    let archive_mock = server.mock(|when, then| {
        when.method(GET).path("/archive.tar");
        then.status(200).body(vec![0u8; SMALL_LIMIT as usize + 1]);
    });
    let outcome = outcome_for_archive(&server, platform, &archive);
    let install_dir = tempdir().unwrap();
    install_original(&install_dir, platform);

    let error = updater()
        .with_fetch_limits(FetchLimits {
            archive_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        })
        .apply(&outcome, install_dir.path())
        .expect_err("oversized artifact must fail");

    assert!(matches!(
        error,
        BsuiteCoreError::ResponseBodyTooLarge { .. }
    ));
    assert_eq!(
        archive_mock.hits(),
        1,
        "oversized response must not trigger retries"
    );
    assert_original_preserved(&install_dir, platform);
}
