use base64::Engine;
use bsuite_core::{
    BsuiteCoreError, FileSystemManifestOverlayReader, ManifestOverlayReader, OverlayValidationError,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::io::Write;
use tempfile::TempDir;

struct SignedOverlay {
    dir: TempDir,
    binary_name: String,
}

impl SignedOverlay {
    fn build(toml: &str) -> Self {
        Self::build_with_signing_key(toml, deterministic_signing_key())
    }

    fn build_with_key(toml: &str, key_seed: u8) -> Self {
        Self::build_with_signing_key(toml, SigningKey::from_bytes(&[key_seed; 32]))
    }

    fn build_with_signing_key(toml: &str, signing_key: SigningKey) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let binary_name = "test-binary".to_string();

        let verifying_key = signing_key.verifying_key();
        let overlay_path = dir.path().join(format!("{binary_name}.overlay.toml"));
        let sig_path = overlay_path.with_extension("toml.sig");
        let pubkey_path = dir.path().join(format!("{binary_name}.overlay.pubkey"));

        std::fs::write(&overlay_path, toml).unwrap();
        std::fs::write(&pubkey_path, verifying_key.to_bytes()).unwrap();

        let canonical = toml_to_jcs(toml.as_bytes());
        let signature: Signature = signing_key.sign(&canonical);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&sig_path, sig_b64).unwrap();

        Self { dir, binary_name }
    }

    fn reader(&self) -> FileSystemManifestOverlayReader {
        FileSystemManifestOverlayReader::new(&self.binary_name, self.dir.path())
    }

    fn overlay_path(&self) -> std::path::PathBuf {
        self.dir
            .path()
            .join(format!("{}.overlay.toml", self.binary_name))
    }

    fn sig_path(&self) -> std::path::PathBuf {
        self.overlay_path().with_extension("toml.sig")
    }

    fn pubkey_path(&self) -> std::path::PathBuf {
        self.dir
            .path()
            .join(format!("{}.overlay.pubkey", self.binary_name))
    }
}

fn deterministic_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

fn toml_to_jcs(toml_bytes: &[u8]) -> Vec<u8> {
    let toml_str = std::str::from_utf8(toml_bytes).unwrap();
    let toml_value: toml::Value = toml::from_str(toml_str).unwrap();
    let json_value: serde_json::Value = serde_json::to_value(toml_value).unwrap();
    serde_json_canonicalizer::to_vec(&json_value).unwrap()
}

const VALID_TOML: &str = "schema_version = 1\n\n[overrides]\ntranscript_retention_days = 30\n";

#[test]
fn valid_sig_and_pubkey_returns_parsed_overlay() {
    let fixture = SignedOverlay::build(VALID_TOML);
    let overlay = fixture
        .reader()
        .read()
        .expect("valid signature and pubkey must succeed");
    assert_eq!(overlay.schema_version, 1);
    assert_eq!(overlay.overrides.transcript_retention_days, Some(30));
}

#[test]
fn tampered_overlay_content_returns_signature_invalid() {
    let fixture = SignedOverlay::build(VALID_TOML);
    let tampered = "schema_version = 1\n\n[overrides]\ntranscript_retention_days = 999\n";
    std::fs::write(fixture.overlay_path(), tampered).unwrap();

    let err = fixture.reader().read().expect_err("tampered must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid)
        ),
        "expected SignatureInvalid, got {err:?}"
    );
}

#[test]
fn wrong_pubkey_returns_signature_invalid() {
    let fixture = SignedOverlay::build_with_key(VALID_TOML, 1);
    let wrong_key = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
    std::fs::write(fixture.pubkey_path(), wrong_key.to_bytes()).unwrap();

    let err = fixture.reader().read().expect_err("wrong key must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid)
        ),
        "expected SignatureInvalid, got {err:?}"
    );
}

#[test]
fn truncated_pubkey_file_returns_signature_invalid() {
    let fixture = SignedOverlay::build(VALID_TOML);
    std::fs::write(fixture.pubkey_path(), [0xAB_u8; 31]).unwrap();

    let err = fixture
        .reader()
        .read()
        .expect_err("truncated pubkey must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid)
        ),
        "expected SignatureInvalid for 31-byte pubkey, got {err:?}"
    );
}

#[test]
fn oversized_pubkey_file_returns_signature_invalid() {
    let fixture = SignedOverlay::build(VALID_TOML);
    std::fs::write(fixture.pubkey_path(), [0xAB_u8; 33]).unwrap();

    let err = fixture
        .reader()
        .read()
        .expect_err("oversized pubkey must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid)
        ),
        "expected SignatureInvalid for 33-byte pubkey, got {err:?}"
    );
}

#[test]
fn missing_sig_file_returns_signature_missing() {
    let fixture = SignedOverlay::build(VALID_TOML);
    std::fs::remove_file(fixture.sig_path()).unwrap();

    let err = fixture.reader().read().expect_err("missing sig must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureMissing)
        ),
        "expected SignatureMissing, got {err:?}"
    );
}

#[test]
fn missing_pubkey_file_returns_pubkey_missing() {
    let fixture = SignedOverlay::build(VALID_TOML);
    std::fs::remove_file(fixture.pubkey_path()).unwrap();

    let err = fixture
        .reader()
        .read()
        .expect_err("missing pubkey must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::PubkeyMissing)
        ),
        "expected PubkeyMissing, got {err:?}"
    );
}

#[test]
fn corrupt_base64_in_sig_file_returns_signature_invalid() {
    let fixture = SignedOverlay::build(VALID_TOML);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(fixture.sig_path())
        .unwrap();
    file.write_all(b"not-valid-base64!!!").unwrap();

    let err = fixture.reader().read().expect_err("corrupt sig must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid)
        ),
        "expected SignatureInvalid, got {err:?}"
    );
}

#[test]
fn valid_base64_but_wrong_sig_length_returns_signature_invalid() {
    let fixture = SignedOverlay::build(VALID_TOML);
    let short_b64 = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
    std::fs::write(fixture.sig_path(), &short_b64).unwrap();

    let err = fixture.reader().read().expect_err("32-byte sig must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureInvalid)
        ),
        "expected SignatureInvalid for wrong-length sig, got {err:?}"
    );
}

#[test]
fn sig_file_with_trailing_newline_verifies_successfully() {
    let fixture = SignedOverlay::build(VALID_TOML);
    let original_sig = std::fs::read_to_string(fixture.sig_path()).unwrap();
    std::fs::write(fixture.sig_path(), format!("{original_sig}\n")).unwrap();

    let overlay = fixture
        .reader()
        .read()
        .expect("trailing newline in sig file must still verify");
    assert_eq!(overlay.overrides.transcript_retention_days, Some(30));
}

#[test]
fn unknown_key_in_overrides_is_rejected_after_successful_sig_verification() {
    let toml = "schema_version = 1\n\n[overrides]\ntranscript_retention_days = 30\nbanned = true\n";
    let fixture = SignedOverlay::build(toml);

    let err = fixture.reader().read().expect_err("unknown key must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::UnknownKey { ref key }) if key == "banned"
        ),
        "expected UnknownKey(banned), got {err:?}"
    );
}

#[test]
fn schema_mismatch_in_signed_overlay_returns_schema_error_not_signature_error() {
    let toml = "schema_version = 99\n\n[overrides]\ntranscript_retention_days = 30\n";
    let fixture = SignedOverlay::build(toml);

    let err = fixture
        .reader()
        .read()
        .expect_err("schema mismatch must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SchemaMismatch {
                expected: 1,
                found: 99
            })
        ),
        "expected SchemaMismatch after valid sig, got {err:?}"
    );
}
