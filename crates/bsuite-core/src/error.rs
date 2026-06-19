use crate::RoutingKey;
use crate::manifest_overlay::OverlayValidationError;
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum BsuiteCoreError {
    #[error("prompt resolution failed: {0}")]
    PromptResolution(String),
    #[error("update failed: {0}")]
    Update(String),
    #[error("transcript append failed: {0}")]
    Transcript(String),
    #[error("transcript path failed: {0}")]
    TranscriptPathFailed(String),
    #[error("transcript write failed: {0}")]
    TranscriptWriteFailed(String),
    #[error("transcript serialization failed: {0}")]
    TranscriptSerializationFailed(String),
    #[error("transcript manifest failed: {0}")]
    TranscriptManifestFailed(String),

    #[error("manifest fetch failed: {0}")]
    ManifestFetchFailed(String),
    #[error("manifest signature fetch failed: {0}")]
    SignatureFetchFailed(String),
    #[error("manifest signature is invalid")]
    ManifestSignatureInvalid,
    #[error("manifest signing key is unknown: {0}")]
    ManifestUnknownSigningKey(String),
    #[error("manifest signing key is expired: {0}")]
    ManifestSigningKeyExpired(String),
    #[error("manifest signing key is not yet valid: {0}")]
    ManifestSigningKeyNotYetValid(String),
    #[error("manifest signing key is revoked: {0}")]
    ManifestSigningKeyRevoked(String),
    #[error("manifest schema mismatch: expected {expected}, found {found}")]
    ManifestSchemaMismatch { expected: u32, found: u32 },
    #[error("manifest platform is missing: {0}")]
    ManifestPlatformMissing(String),
    #[error("artifact fetch failed: {0}")]
    ArtifactFetchFailed(String),
    #[error("artifact sha256 mismatch: expected {expected}, found {found}")]
    ArtifactSha256Mismatch { expected: String, found: String },
    #[error("response body exceeds limit: limit {limit_bytes}, found {found_bytes}")]
    ResponseBodyTooLarge { limit_bytes: u64, found_bytes: u64 },
    #[error("atomic install failed: {0}")]
    AtomicInstallFailed(String),
    #[error("install rollback failed: {0}")]
    InstallRollbackFailed(String),
    #[error("manifest overlay validation failed: {0}")]
    ManifestOverlay(#[from] OverlayValidationError),
    #[error("exit code emission failed: {0}")]
    ExitCode(String),
    #[error("visibility evidence publication failed: {0}")]
    VisibilityEvidence(String),
    #[error("adapter host binding failed: {0}")]
    AdapterHostBinding(String),
    #[error("corpus signature is invalid")]
    CorpusSignatureInvalid,
    #[error("corpus schema mismatch: expected {expected}, found {found}")]
    CorpusSchemaMismatch { expected: u32, found: u32 },
    #[error("corpus deserialization failed: {0}")]
    CorpusDeserializationFailed(String),
    #[error("corpus key is missing: {0}")]
    CorpusKeyMissing(RoutingKey),
    #[error("opacity section missing: {0}")]
    OpacitySectionMissing(String),
    #[error("opacity TOML parse failed: {0}")]
    OpacityTomlParseFailed(String),
    #[error("opacity tier mismatch: expected {expected}, found {found}")]
    OpacityTierMismatch { expected: String, found: String },
    #[error("opacity schema mismatch: expected {expected}, found {found}")]
    OpacitySchemaMismatch { expected: u32, found: u32 },
    #[error("host context JSON in BSUITE_HOST_CONTEXT could not be parsed: {0}")]
    HostContextParseFailed(String),
    #[error("host_id is not a recognized host context identifier: {0}")]
    UnknownHostId(String),
}
