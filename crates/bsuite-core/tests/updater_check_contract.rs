mod common;

use bsuite_core::{
    BsuiteCoreError, FetchLimits, PlatformId, SignedManifestUpdater, UpdateChannel, UpdateOutcome,
    Updater,
};
use common::{
    manifest_signature, manifest_signing_key, signed_manifest, trust_bundle,
    trust_bundle_with_dates,
};
use httpmock::Method::GET;
use httpmock::MockServer;
use semver::Version;

const FETCH_ATTEMPTS: usize = 3;

fn serve_manifest(server: &MockServer, manifest_body: String, signature_body: String) {
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200).body(manifest_body);
    });
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(200).body(signature_body);
    });
}

fn serve_manifest_status(server: &MockServer, status: u16) {
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(status);
    });
}

fn serve_signature_status(server: &MockServer, manifest_body: String, status: u16) {
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200).body(manifest_body);
    });
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(status);
    });
}

fn check_with_server(
    updater: &SignedManifestUpdater,
    server: &MockServer,
) -> Result<UpdateOutcome, BsuiteCoreError> {
    updater.check(
        &Version::parse("0.1.0").unwrap(),
        &UpdateChannel::new(server.base_url()),
    )
}

#[test]
fn valid_signature_and_newer_version_returns_upgrade_available() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    serve_manifest(
        &server,
        serde_json::to_string(&manifest).unwrap(),
        manifest_signature(&manifest, &key),
    );
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let outcome = check_with_server(&updater, &server).unwrap();

    assert!(matches!(outcome, UpdateOutcome::UpgradeAvailable { .. }));
}

#[test]
fn non_newer_versions_return_up_to_date() {
    for candidate_version in ["0.2.0", "0.1.9"] {
        let server = MockServer::start();
        let key = manifest_signing_key(17);
        let platform = PlatformId::current();
        let manifest = signed_manifest(
            candidate_version,
            "test-key",
            platform,
            server.url("/archive.tar"),
            "0".repeat(64),
        );
        serve_manifest(
            &server,
            serde_json::to_string(&manifest).unwrap(),
            manifest_signature(&manifest, &key),
        );
        let updater =
            SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

        let outcome = updater
            .check(
                &Version::parse("0.2.0").unwrap(),
                &UpdateChannel::new(server.base_url()),
            )
            .unwrap();

        assert_eq!(outcome, UpdateOutcome::UpToDate, "{candidate_version}");
    }
}

#[test]
fn signature_verification_rejects_malformed_invalid_and_tampered_payloads() {
    let cases = [
        "ed25519:not-base64",
        "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ];

    for signature_body in cases {
        let server = MockServer::start();
        let key = manifest_signing_key(17);
        let platform = PlatformId::current();
        let manifest = signed_manifest(
            "0.2.0",
            "test-key",
            platform,
            server.url("/archive.tar"),
            "0".repeat(64),
        );
        serve_manifest(
            &server,
            serde_json::to_string(&manifest).unwrap(),
            signature_body.to_string(),
        );
        let updater =
            SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

        let error = check_with_server(&updater, &server).expect_err("signature must fail");

        assert_eq!(
            error,
            BsuiteCoreError::ManifestSignatureInvalid,
            "{signature_body}"
        );
    }

    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let original = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    let mut tampered = original.clone();
    tampered.corpus_version += 1;
    serve_manifest(
        &server,
        serde_json::to_string(&tampered).unwrap(),
        manifest_signature(&original, &key),
    );
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error = check_with_server(&updater, &server).expect_err("tampered manifest must fail");

    assert_eq!(error, BsuiteCoreError::ManifestSignatureInvalid);
}

#[test]
fn unknown_signing_key_returns_manifest_unknown_signing_key() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let trusted = manifest_signing_key(18);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "unknown-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    serve_manifest(
        &server,
        serde_json::to_string(&manifest).unwrap(),
        manifest_signature(&manifest, &key),
    );
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &trusted)).unwrap();

    let error = check_with_server(&updater, &server).expect_err("unknown key must fail");

    assert_eq!(
        error,
        BsuiteCoreError::ManifestUnknownSigningKey("unknown-key".to_string())
    );
}

#[test]
fn schema_mismatch_returns_manifest_schema_mismatch() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let mut manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    manifest.schema_version = 99;
    serve_manifest(
        &server,
        serde_json::to_string(&manifest).unwrap(),
        manifest_signature(&manifest, &key),
    );
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error = check_with_server(&updater, &server).expect_err("schema mismatch must fail");

    assert_eq!(
        error,
        BsuiteCoreError::ManifestSchemaMismatch {
            expected: 1,
            found: 99
        }
    );
}

#[test]
fn manifest_and_signature_transport_failures_are_distinct() {
    let key = manifest_signing_key(17);

    let manifest_server = MockServer::start();
    serve_manifest_status(&manifest_server, 503);
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();
    let manifest_error = check_with_server(&updater, &manifest_server)
        .expect_err("manifest status failure must fail");
    assert!(matches!(
        manifest_error,
        BsuiteCoreError::ManifestFetchFailed(_)
    ));

    let signature_server = MockServer::start();
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        signature_server.url("/archive.tar"),
        "0".repeat(64),
    );
    serve_signature_status(
        &signature_server,
        serde_json::to_string(&manifest).unwrap(),
        503,
    );
    let signature_error = check_with_server(&updater, &signature_server)
        .expect_err("signature status failure must fail");
    assert!(matches!(
        signature_error,
        BsuiteCoreError::SignatureFetchFailed(_)
    ));
}

#[test]
fn network_failure_returns_manifest_fetch_failed() {
    let key = manifest_signing_key(17);
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error = updater
        .check(
            &Version::parse("0.1.0").unwrap(),
            &UpdateChannel::new("http://127.0.0.1:9"),
        )
        .expect_err("closed port must fail manifest fetch");

    assert!(matches!(error, BsuiteCoreError::ManifestFetchFailed(_)));
}

#[test]
fn key_validity_rejects_expired_not_yet_valid_and_revoked_keys() {
    let cases = [
        (
            trust_bundle_with_dates(
                "test-key",
                &manifest_signing_key(17),
                "2020-01-01T00:00:00Z",
                "2021-01-01T00:00:00Z",
                None,
            ),
            BsuiteCoreError::ManifestSigningKeyExpired("test-key".to_string()),
        ),
        (
            trust_bundle_with_dates(
                "test-key",
                &manifest_signing_key(17),
                "2098-01-01T00:00:00Z",
                "2099-01-01T00:00:00Z",
                None,
            ),
            BsuiteCoreError::ManifestSigningKeyNotYetValid("test-key".to_string()),
        ),
        (
            trust_bundle_with_dates(
                "test-key",
                &manifest_signing_key(17),
                "2020-01-01T00:00:00Z",
                "2099-01-01T00:00:00Z",
                Some("2021-01-01T00:00:00Z"),
            ),
            BsuiteCoreError::ManifestSigningKeyRevoked("test-key".to_string()),
        ),
    ];

    for (bundle, expected) in cases {
        let server = MockServer::start();
        let key = manifest_signing_key(17);
        let platform = PlatformId::current();
        let manifest = signed_manifest(
            "0.2.0",
            "test-key",
            platform,
            server.url("/archive.tar"),
            "0".repeat(64),
        );
        serve_manifest(
            &server,
            serde_json::to_string(&manifest).unwrap(),
            manifest_signature(&manifest, &key),
        );
        let updater = SignedManifestUpdater::from_trust_bundle_str(&bundle).unwrap();

        let error = check_with_server(&updater, &server)
            .expect_err("invalid key validity window must fail");

        assert_eq!(error, expected);
    }
}

#[test]
fn missing_current_platform_returns_manifest_platform_missing() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        PlatformId::LinuxX86_64,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    serve_manifest(
        &server,
        serde_json::to_string(&manifest).unwrap(),
        manifest_signature(&manifest, &key),
    );
    let updater = SignedManifestUpdater::from_trust_bundle_str_for_platform(
        &trust_bundle("test-key", &key),
        PlatformId::WindowsX86_64,
    )
    .unwrap();

    let error = check_with_server(&updater, &server).expect_err("missing platform must fail");

    assert_eq!(
        error,
        BsuiteCoreError::ManifestPlatformMissing("windows-x86_64".to_string())
    );
}

#[test]
fn oversized_manifest_response_is_rejected_without_signature_fetch() {
    const SMALL_LIMIT: u64 = 5;

    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let manifest_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200).body(vec![0u8; SMALL_LIMIT as usize + 1]);
    });
    let signature_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(200).body("");
    });
    let updater = SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key))
        .unwrap()
        .with_fetch_limits(FetchLimits {
            manifest_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        });

    let error = check_with_server(&updater, &server).expect_err("oversized manifest must fail");

    assert_eq!(
        error,
        BsuiteCoreError::ResponseBodyTooLarge {
            limit_bytes: SMALL_LIMIT,
            found_bytes: SMALL_LIMIT + 1,
        }
    );
    assert_eq!(manifest_mock.hits(), 1);
    assert_eq!(signature_mock.hits(), 0);
}

#[test]
fn oversized_signature_response_is_rejected_after_manifest_fetch() {
    const SMALL_LIMIT: u64 = 5;

    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    let manifest_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200)
            .body(serde_json::to_string(&manifest).unwrap());
    });
    let signature_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(200).body(vec![0u8; SMALL_LIMIT as usize + 1]);
    });
    let updater = SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key))
        .unwrap()
        .with_fetch_limits(FetchLimits {
            signature_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        });

    let error = check_with_server(&updater, &server).expect_err("oversized signature must fail");

    assert_eq!(
        error,
        BsuiteCoreError::ResponseBodyTooLarge {
            limit_bytes: SMALL_LIMIT,
            found_bytes: SMALL_LIMIT + 1,
        }
    );
    assert_eq!(manifest_mock.hits(), 1);
    assert_eq!(signature_mock.hits(), 1);
}

#[test]
fn invalid_manifest_body_reports_manifest_fetch_failed() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    serve_manifest(
        &server,
        "{not-json".to_string(),
        "ed25519:not-base64".to_string(),
    );
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error = check_with_server(&updater, &server).expect_err("invalid manifest body must fail");

    assert!(matches!(error, BsuiteCoreError::ManifestFetchFailed(_)));
}

#[test]
fn transient_manifest_fetch_failure_is_retried() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let manifest_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(503);
    });
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error = check_with_server(&updater, &server).expect_err("transient failure must fail");

    assert!(matches!(error, BsuiteCoreError::ManifestFetchFailed(_)));
    assert_eq!(manifest_mock.hits(), FETCH_ATTEMPTS);
}

#[test]
fn semantic_manifest_rejections_are_not_retried() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let mut manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    manifest.schema_version = 99;
    let manifest_body = serde_json::to_string(&manifest).unwrap();
    let signature_body = manifest_signature(&manifest, &key);
    let manifest_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200).body(manifest_body);
    });
    let signature_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(200).body(signature_body);
    });
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error = check_with_server(&updater, &server).expect_err("schema mismatch must fail");

    assert!(matches!(
        error,
        BsuiteCoreError::ManifestSchemaMismatch { .. }
    ));
    assert_eq!(manifest_mock.hits(), 1);
    assert_eq!(signature_mock.hits(), 1);
}

#[test]
fn manifest_body_exactly_at_limit_is_accepted_by_size_check() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    let manifest_body = serde_json::to_string(&manifest).unwrap();
    let body_len = manifest_body.len() as u64;

    server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200).body(manifest_body);
    });
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(200)
            .body("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    });
    let updater = SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key))
        .unwrap()
        .with_fetch_limits(FetchLimits {
            manifest_body_bytes: body_len,
            ..FetchLimits::default()
        });

    let error = check_with_server(&updater, &server)
        .expect_err("manifest body at size limit must not be rejected by size check");

    assert!(
        !matches!(error, BsuiteCoreError::ResponseBodyTooLarge { .. }),
        "manifest body exactly at limit must not be rejected by size check"
    );
    assert_eq!(error, BsuiteCoreError::ManifestSignatureInvalid);
}

#[test]
fn signature_body_exactly_at_limit_is_accepted_by_size_check() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    let sig_body = manifest_signature(&manifest, &key);
    let sig_len = sig_body.len() as u64;

    serve_manifest(&server, serde_json::to_string(&manifest).unwrap(), sig_body);
    let updater = SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key))
        .unwrap()
        .with_fetch_limits(FetchLimits {
            signature_body_bytes: sig_len,
            ..FetchLimits::default()
        });

    let outcome = check_with_server(&updater, &server).unwrap();

    assert!(matches!(outcome, UpdateOutcome::UpgradeAvailable { .. }));
}

#[test]
fn oversized_manifest_response_is_not_retried() {
    const SMALL_LIMIT: u64 = 5;

    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let manifest_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200).body(vec![0u8; SMALL_LIMIT as usize + 1]);
    });
    let updater = SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key))
        .unwrap()
        .with_fetch_limits(FetchLimits {
            manifest_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        });

    let error = check_with_server(&updater, &server).expect_err("oversized manifest must fail");

    assert!(matches!(
        error,
        BsuiteCoreError::ResponseBodyTooLarge { .. }
    ));
    assert_eq!(
        manifest_mock.hits(),
        1,
        "oversized response must not trigger retries"
    );
}

#[test]
fn oversized_signature_response_is_not_retried() {
    const SMALL_LIMIT: u64 = 5;

    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200)
            .body(serde_json::to_string(&manifest).unwrap());
    });
    let signature_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(200).body(vec![0u8; SMALL_LIMIT as usize + 1]);
    });
    let updater = SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key))
        .unwrap()
        .with_fetch_limits(FetchLimits {
            signature_body_bytes: SMALL_LIMIT,
            ..FetchLimits::default()
        });

    let error = check_with_server(&updater, &server).expect_err("oversized signature must fail");

    assert!(matches!(
        error,
        BsuiteCoreError::ResponseBodyTooLarge { .. }
    ));
    assert_eq!(
        signature_mock.hits(),
        1,
        "oversized response must not trigger retries"
    );
}

#[test]
fn transient_signature_fetch_failure_is_retried() {
    let server = MockServer::start();
    let key = manifest_signing_key(17);
    let platform = PlatformId::current();
    let manifest = signed_manifest(
        "0.2.0",
        "test-key",
        platform,
        server.url("/archive.tar"),
        "0".repeat(64),
    );
    server.mock(|when, then| {
        when.method(GET).path("/manifest.json");
        then.status(200)
            .body(serde_json::to_string(&manifest).unwrap());
    });
    let signature_mock = server.mock(|when, then| {
        when.method(GET).path("/manifest.json.sig");
        then.status(503);
    });
    let updater =
        SignedManifestUpdater::from_trust_bundle_str(&trust_bundle("test-key", &key)).unwrap();

    let error =
        check_with_server(&updater, &server).expect_err("transient signature failure must fail");

    assert!(matches!(error, BsuiteCoreError::SignatureFetchFailed(_)));
    assert_eq!(signature_mock.hits(), FETCH_ATTEMPTS);
}
