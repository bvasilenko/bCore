#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt::Debug;

pub fn assert_stable_mappings<T, U, const N: usize>(actual: [(T, U); N], expected: [(T, U); N])
where
    T: Debug + Eq,
    U: Debug + Eq,
{
    assert_eq!(actual, expected);
}

pub fn assert_unique_projection<T, U, const N: usize>(items: [T; N], projection: impl Fn(T) -> U)
where
    T: Copy,
    U: Ord + Debug,
{
    let values = items.into_iter().map(projection).collect::<BTreeSet<_>>();

    assert_eq!(values.len(), N);
}

pub fn assert_projection_contains<T, U, const N: usize>(
    items: [T; N],
    projection: impl Fn(T) -> U,
    expected: U,
) where
    T: Copy,
    U: Ord + Debug,
{
    let values = items.into_iter().map(projection).collect::<BTreeSet<_>>();

    assert!(values.contains(&expected));
}

use base64::Engine;
use bsuite_core::{
    CorpusEntry, CorpusFile, CorpusResolver, ProvenanceRecord, RoutingKey,
    corpus::canonical_payload_bytes,
};
use ed25519_dalek::{Signer, SigningKey};

pub fn corpus_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn provenance(iteration: u32) -> ProvenanceRecord {
    ProvenanceRecord {
        run_id: format!("test-run-{iteration}"),
        iteration,
        observation_source: "contract-test".to_string(),
        pre_compliance: 0.25,
        post_compliance: 0.95,
    }
}

pub fn corpus_entry(
    routing_key: RoutingKey,
    directive: impl Into<String>,
    iteration: u32,
) -> CorpusEntry {
    CorpusEntry {
        routing_key,
        directive: directive.into(),
        provenance: provenance(iteration),
    }
}

pub fn corpus_file(entries: Vec<CorpusEntry>) -> CorpusFile {
    CorpusFile {
        schema_version: 1,
        signature: String::new(),
        canonical_key_id: "test-key".to_string(),
        entries,
    }
}

pub fn single_entry_corpus(routing_key: RoutingKey) -> CorpusFile {
    corpus_file(vec![corpus_entry(
        routing_key,
        "Stop and inspect the supplied evidence before acting.",
        1,
    )])
}

pub fn signed_toml(mut corpus: CorpusFile, signing_key: &SigningKey) -> String {
    let payload = canonical_payload_bytes(&corpus).expect("canonical payload is available");
    let signature = signing_key.sign(&payload);
    corpus.signature = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    toml::to_string(&corpus).expect("signed corpus encodes as TOML")
}

pub fn signed_resolver(corpus: CorpusFile) -> CorpusResolver {
    let signing_key = corpus_signing_key(42);
    let toml = signed_toml(corpus, &signing_key);
    CorpusResolver::from_toml_signed(&toml, &(&signing_key).into())
        .expect("test corpus signature verifies")
}

use bsuite_core::{PlatformArtefact, PlatformId, SignedManifest};
use chrono::{TimeZone, Utc};
use ed25519_dalek::VerifyingKey;
use semver::Version;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;

pub fn manifest_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn trust_bundle(key_id: &str, key: &SigningKey) -> String {
    trust_bundle_with_dates(
        key_id,
        key,
        "2020-01-01T00:00:00Z",
        "2099-01-01T00:00:00Z",
        None,
    )
}

pub fn trust_bundle_with_dates(
    key_id: &str,
    key: &SigningKey,
    valid_from: &str,
    valid_until: &str,
    revoked_at: Option<&str>,
) -> String {
    let public_key = VerifyingKey::from(key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
    let revoked = revoked_at
        .map(|value| format!("revoked_at = \"{value}\"\n"))
        .unwrap_or_default();
    format!(
        r#"[[keys]]
key_id = "{key_id}"
verifying_key_base64 = "{encoded}"
valid_from = "{valid_from}"
valid_until = "{valid_until}"
{revoked}"#
    )
}

pub fn signed_manifest(
    version: &str,
    key_id: &str,
    platform: PlatformId,
    archive_url: String,
    archive_sha256: String,
) -> SignedManifest {
    let mut platforms = HashMap::new();
    platforms.insert(
        platform.key().to_string(),
        PlatformArtefact {
            archive_url,
            sha256: archive_sha256,
        },
    );

    SignedManifest {
        schema_version: 1,
        binary_name: "bground".to_string(),
        version: Version::parse(version).unwrap(),
        release_at: Utc.with_ymd_and_hms(2026, 6, 13, 0, 0, 0).unwrap(),
        platforms,
        corpus_version: 2,
        obfuscation_tier: "test".to_string(),
        signing_key_id: key_id.to_string(),
    }
}

pub fn manifest_signature(manifest: &SignedManifest, key: &SigningKey) -> String {
    let payload = serde_json_canonicalizer::to_vec(manifest).unwrap();
    let signature = key.sign(&payload);
    format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    )
}

pub fn executable_name(platform: PlatformId) -> &'static str {
    match platform {
        PlatformId::WindowsX86_64 => "bground.exe",
        _ => "bground",
    }
}

pub fn tar_with_file(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut output);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, path, Cursor::new(bytes))
            .unwrap();
        builder.finish().unwrap();
    }
    output
}

pub fn raw_tar_with_unchecked_path(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    let path_bytes = path.as_bytes();
    header[..path_bytes.len()].copy_from_slice(path_bytes);
    header[100..108].copy_from_slice(b"0000755\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size = format!("{:011o}\0", bytes.len());
    header[124..136].copy_from_slice(size.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let checksum = format!("{:06o}\0 ", checksum);
    header[148..156].copy_from_slice(checksum.as_bytes());

    let mut output = Vec::new();
    output.extend_from_slice(&header);
    output.extend_from_slice(bytes);
    let padding = (512 - (bytes.len() % 512)) % 512;
    output.extend(std::iter::repeat_n(0, padding));
    output.extend_from_slice(&[0_u8; 1024]);
    output
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

use bsuite_core::{EmitFormat, ProcessExitEmitter};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }

    pub fn string(&self) -> String {
        String::from_utf8(self.bytes()).expect("valid utf8")
    }
}

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn buf_emitter(format: EmitFormat) -> (ProcessExitEmitter, SharedBuf, SharedBuf) {
    let out = SharedBuf::new();
    let err = SharedBuf::new();
    let emitter =
        ProcessExitEmitter::for_streams(format, Box::new(out.clone()), Box::new(err.clone()));
    (emitter, out, err)
}

use bsuite_core::{BsuiteCoreError, OverlayValidationError};

pub fn all_bsuite_core_error_variants() -> Vec<BsuiteCoreError> {
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
        BsuiteCoreError::ManifestOverlay(OverlayValidationError::SignatureMissing),
        BsuiteCoreError::OpacitySectionMissing("x".into()),
        BsuiteCoreError::OpacityTomlParseFailed("x".into()),
        BsuiteCoreError::OpacityTierMismatch {
            expected: "a".into(),
            found: "b".into(),
        },
        BsuiteCoreError::OpacitySchemaMismatch {
            expected: 1,
            found: 2,
        },
        BsuiteCoreError::HostContextParseFailed("x".into()),
        BsuiteCoreError::UnknownHostId("unknown-cms-v99".into()),
    ]
}

pub fn all_overlay_validation_sub_variants() -> Vec<OverlayValidationError> {
    vec![
        OverlayValidationError::SignatureMissing,
        OverlayValidationError::SignatureInvalid,
        OverlayValidationError::PubkeyMissing,
        OverlayValidationError::SchemaMismatch {
            expected: 1,
            found: 2,
        },
        OverlayValidationError::UnknownKey { key: "k".into() },
        OverlayValidationError::TomlParseFailed("bad".into()),
    ]
}
