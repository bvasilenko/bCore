use base64::Engine;
use bsuite_core::{
    BsuiteCoreError, FileSystemManifestOverlayReader, ManifestOverlay, ManifestOverlayReader,
    OverlayValidationError,
};
use ed25519_dalek::{Signature, Signer, SigningKey};
use std::path::PathBuf;
use std::sync::Mutex;
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn empty_install_dir() -> TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn write_signed_overlay(dir: &TempDir, binary_name: &str, toml: &str) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = key.verifying_key();

    let overlay_path = dir.path().join(format!("{binary_name}.overlay.toml"));
    let sig_path = overlay_path.with_extension("toml.sig");
    let pubkey_path = dir.path().join(format!("{binary_name}.overlay.pubkey"));

    std::fs::write(&overlay_path, toml).unwrap();
    std::fs::write(&pubkey_path, verifying_key.to_bytes()).unwrap();

    let toml_value: toml::Value = toml::from_str(toml).unwrap();
    let json_value: serde_json::Value = serde_json::to_value(toml_value).unwrap();
    let canonical = serde_json_canonicalizer::to_vec(&json_value).unwrap();
    let signature: Signature = key.sign(&canonical);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    std::fs::write(&sig_path, sig_b64).unwrap();
}

const VALID_TOML: &str = "schema_version = 1\n\n[overrides]\ntranscript_retention_days = 14\n";

#[test]
fn absent_overlay_file_returns_empty_manifest_overlay() {
    let dir = empty_install_dir();
    let reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let overlay = reader
        .read()
        .expect("absent overlay must return empty, not error");
    assert_eq!(overlay, ManifestOverlay::empty());
}

#[test]
fn overlay_file_at_default_path_is_detected_when_present() {
    let dir = empty_install_dir();
    std::fs::write(dir.path().join("bground.overlay.toml"), b"").unwrap();

    let reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let err = reader
        .read()
        .expect_err("overlay present without sig must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureMissing)
        ),
        "SignatureMissing proves overlay was found at the default path; got {err:?}"
    );
}

#[test]
fn sig_path_is_derived_from_overlay_path_with_toml_sig_extension() {
    let dir = empty_install_dir();
    std::fs::write(dir.path().join("bground.overlay.toml"), b"").unwrap();
    std::fs::write(dir.path().join("bground.overlay.toml.sig"), b"").unwrap();

    let reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let err = reader
        .read()
        .expect_err("overlay+sig present without pubkey must fail");
    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::PubkeyMissing)
        ),
        "PubkeyMissing proves sig was found at the derived .toml.sig path; got {err:?}"
    );
}

#[test]
fn valid_overlay_at_default_path_is_read_and_parsed() {
    let dir = empty_install_dir();
    write_signed_overlay(&dir, "bground", VALID_TOML);

    let reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let overlay = reader
        .read()
        .expect("valid signed overlay at default path must succeed");
    assert_eq!(overlay.overrides.transcript_retention_days, Some(14));
}

#[test]
fn binary_name_scopes_the_overlay_filename() {
    let dir = empty_install_dir();
    write_signed_overlay(&dir, "banchor", VALID_TOML);

    let bground_reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let overlay = bground_reader
        .read()
        .expect("bground reader must not find banchor overlay");
    assert_eq!(
        overlay,
        ManifestOverlay::empty(),
        "bground reader must not accidentally read banchor.overlay.toml"
    );

    let banchor_reader = FileSystemManifestOverlayReader::new("banchor", dir.path());
    let overlay = banchor_reader
        .read()
        .expect("banchor reader must find its overlay");
    assert_eq!(overlay.overrides.transcript_retention_days, Some(14));
}

#[test]
fn from_paths_constructor_accepts_explicit_paths_without_env_resolution() {
    let reader = FileSystemManifestOverlayReader::from_paths(
        PathBuf::from("/explicit/overlay.toml"),
        PathBuf::from("/explicit/overlay.toml.sig"),
        PathBuf::from("/explicit/overlay.pubkey"),
    );
    let overlay = reader
        .read()
        .expect("absent explicit paths must return empty, not error");
    assert_eq!(overlay, ManifestOverlay::empty());
}

#[test]
fn bsuite_overlay_path_env_var_controls_which_file_is_read() {
    let _guard = ENV_LOCK.lock().unwrap();
    let install_dir = empty_install_dir();
    let override_dir = empty_install_dir();

    std::fs::write(override_dir.path().join("custom.overlay.toml"), b"").unwrap();

    unsafe {
        std::env::set_var(
            "BSUITE_OVERLAY_PATH",
            override_dir.path().join("custom.overlay.toml"),
        );
        std::env::remove_var("BSUITE_OVERLAY_PUBKEY_PATH");
    }

    let reader = FileSystemManifestOverlayReader::new("bground", install_dir.path());
    let err = reader
        .read()
        .expect_err("env-overridden overlay must be detected");

    unsafe {
        std::env::remove_var("BSUITE_OVERLAY_PATH");
    }

    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureMissing)
        ),
        "SignatureMissing proves env-overridden path was read (not the absent default); got {err:?}"
    );
}

#[test]
fn bsuite_overlay_path_env_absent_falls_back_to_default_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = empty_install_dir();

    unsafe {
        std::env::remove_var("BSUITE_OVERLAY_PATH");
        std::env::remove_var("BSUITE_OVERLAY_PUBKEY_PATH");
    }

    let reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let overlay = reader
        .read()
        .expect("absent default path must return empty");
    assert_eq!(overlay, ManifestOverlay::empty());
}

#[test]
fn sig_path_derives_from_env_overridden_overlay_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let install_dir = empty_install_dir();
    let override_dir = empty_install_dir();

    let custom_overlay = override_dir.path().join("custom.overlay.toml");
    std::fs::write(&custom_overlay, b"").unwrap();
    let custom_sig = custom_overlay.with_extension("toml.sig");
    std::fs::write(&custom_sig, b"").unwrap();

    unsafe {
        std::env::set_var("BSUITE_OVERLAY_PATH", &custom_overlay);
        std::env::remove_var("BSUITE_OVERLAY_PUBKEY_PATH");
    }

    let reader = FileSystemManifestOverlayReader::new("bground", install_dir.path());
    let err = reader
        .read()
        .expect_err("env overlay + derived sig, no pubkey must fail");

    unsafe {
        std::env::remove_var("BSUITE_OVERLAY_PATH");
    }

    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::PubkeyMissing)
        ),
        "PubkeyMissing proves sig was found at custom.overlay.toml.sig (derived from env path); got {err:?}"
    );
}

#[test]
fn bsuite_overlay_pubkey_path_env_var_controls_which_pubkey_is_read() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = empty_install_dir();

    std::fs::write(dir.path().join("bground.overlay.toml"), b"").unwrap();
    std::fs::write(dir.path().join("bground.overlay.toml.sig"), b"").unwrap();
    std::fs::write(
        dir.path().join("bground.overlay.pubkey"),
        b"default-pubkey-bytes",
    )
    .unwrap();

    let absent_pubkey = dir.path().join("absent.pubkey");
    unsafe {
        std::env::remove_var("BSUITE_OVERLAY_PATH");
        std::env::set_var("BSUITE_OVERLAY_PUBKEY_PATH", &absent_pubkey);
    }

    let reader = FileSystemManifestOverlayReader::new("bground", dir.path());
    let err = reader
        .read()
        .expect_err("absent env-overridden pubkey must fail");

    unsafe {
        std::env::remove_var("BSUITE_OVERLAY_PUBKEY_PATH");
    }

    assert!(
        matches!(
            err,
            BsuiteCoreError::ManifestOverlay(OverlayValidationError::PubkeyMissing)
        ),
        "PubkeyMissing proves env-overridden pubkey path was checked (default exists but env path is absent); got {err:?}"
    );
}
