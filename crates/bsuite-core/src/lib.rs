pub mod adapter_host_bind;
pub mod corpus;
pub mod error;
pub mod exit_code;
pub mod manifest_overlay;
pub mod opacity_hook;
pub mod prompt_resolver;
pub mod routing_key;
pub mod transcript_writer;
pub mod upgrade_carrier;

pub use adapter_host_bind::{
    AdapterBinding, AdapterHostBinder, FullAdapterHostBinder, HOST_CONTEXT_ENV_VAR, HostContext,
    HostInvocationContext, format_context_tag, parse_host_invocation_context,
    parse_host_invocation_context_from_env,
};
pub use corpus::{CorpusEntry, CorpusFile, ProvenanceRecord};
pub use error::BsuiteCoreError;
pub use exit_code::{EmitFormat, ExitCode, ExitCodeEmitter, ExitCodeRouting, ProcessExitEmitter};
pub use manifest_overlay::{
    ALLOWED_OVERRIDE_KEYS, BinaryDefaults, FileSystemManifestOverlayReader, ManifestOverlay,
    ManifestOverlayReader, OVERLAY_SCHEMA_VERSION, OverlayValidationError, OverrideMap,
};
pub use opacity_hook::{
    OPACITY_SECTION_ELF, OPACITY_SECTION_MACHO, OPACITY_SECTION_PE, OpacityHookPublisher,
    TierEvidence, TierProbes,
};
#[cfg(feature = "verify")]
pub use opacity_hook::{validate_tier_evidence_toml, verify_tier_evidence};
pub use prompt_resolver::{CorpusResolver, DirectiveString, EvidenceMap, PromptResolver};
pub use routing_key::RoutingKey;
pub use transcript_writer::{
    FileSystemTranscriptAppender, TranscriptAppender, TranscriptHandle, TranscriptRecord,
};
pub use upgrade_carrier::{
    FetchLimits, PlatformArtefact, PlatformId, SignedManifest, SignedManifestUpdater, TrustedKey,
    UpdateChannel, UpdateOutcome, Updater,
};
