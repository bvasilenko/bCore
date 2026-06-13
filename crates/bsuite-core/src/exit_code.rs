use std::io::Write;

use serde::Serialize;

use crate::BsuiteCoreError;
use crate::prompt_resolver::DirectiveString;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ExitCode {
    Success,
    Finding,
    InternalError,
    Usage,
}

impl ExitCode {
    pub const ALL: [Self; 4] = [
        Self::Success,
        Self::Finding,
        Self::InternalError,
        Self::Usage,
    ];

    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Finding => 1,
            Self::InternalError => 2,
            Self::Usage => 64,
        }
    }

    fn as_outcome_str(self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Finding => "finding",
            Self::InternalError => "internal_error",
            Self::Usage => "usage_error",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EmitFormat {
    Plain,
    Json,
}

pub trait ExitCodeRouting {
    fn route(err: &BsuiteCoreError) -> ExitCode;
}

impl ExitCodeRouting for BsuiteCoreError {
    fn route(err: &BsuiteCoreError) -> ExitCode {
        match err {
            BsuiteCoreError::ManifestOverlay(_) => ExitCode::Usage,

            BsuiteCoreError::PromptResolution(_)
            | BsuiteCoreError::Update(_)
            | BsuiteCoreError::Transcript(_)
            | BsuiteCoreError::TranscriptPathFailed(_)
            | BsuiteCoreError::TranscriptWriteFailed(_)
            | BsuiteCoreError::TranscriptSerializationFailed(_)
            | BsuiteCoreError::TranscriptManifestFailed(_)
            | BsuiteCoreError::ManifestFetchFailed(_)
            | BsuiteCoreError::SignatureFetchFailed(_)
            | BsuiteCoreError::ManifestSignatureInvalid
            | BsuiteCoreError::ManifestUnknownSigningKey(_)
            | BsuiteCoreError::ManifestSigningKeyExpired(_)
            | BsuiteCoreError::ManifestSigningKeyNotYetValid(_)
            | BsuiteCoreError::ManifestSigningKeyRevoked(_)
            | BsuiteCoreError::ManifestSchemaMismatch { .. }
            | BsuiteCoreError::ManifestPlatformMissing(_)
            | BsuiteCoreError::ArtifactFetchFailed(_)
            | BsuiteCoreError::ArtifactSha256Mismatch { .. }
            | BsuiteCoreError::ResponseBodyTooLarge { .. }
            | BsuiteCoreError::AtomicInstallFailed(_)
            | BsuiteCoreError::InstallRollbackFailed(_)
            | BsuiteCoreError::ExitCode(_)
            | BsuiteCoreError::VisibilityEvidence(_)
            | BsuiteCoreError::AdapterHostBinding(_)
            | BsuiteCoreError::CorpusSignatureInvalid
            | BsuiteCoreError::CorpusSchemaMismatch { .. }
            | BsuiteCoreError::CorpusDeserializationFailed(_)
            | BsuiteCoreError::CorpusKeyMissing(_) => ExitCode::InternalError,
        }
    }
}

pub trait ExitCodeEmitter {
    fn exit_code_for(&self, err: &BsuiteCoreError) -> ExitCode;
}

pub struct ProcessExitEmitter {
    format: EmitFormat,
    stdout: Box<dyn Write>,
    stderr: Box<dyn Write>,
}

impl ProcessExitEmitter {
    pub fn new(format: EmitFormat) -> Self {
        Self {
            format,
            stdout: Box::new(std::io::stdout()),
            stderr: Box::new(std::io::stderr()),
        }
    }

    pub fn for_streams(format: EmitFormat, stdout: Box<dyn Write>, stderr: Box<dyn Write>) -> Self {
        Self {
            format,
            stdout,
            stderr,
        }
    }

    pub fn emit_directive(
        &mut self,
        result: Result<(DirectiveString, ExitCode), BsuiteCoreError>,
    ) -> ExitCode {
        match result {
            Ok((directive, exit_code)) => {
                self.write_ok(directive, exit_code);
                exit_code
            }
            Err(err) => {
                let exit_code = BsuiteCoreError::route(&err);
                self.write_err(&err, exit_code);
                exit_code
            }
        }
    }

    fn write_ok(&mut self, directive: DirectiveString, exit_code: ExitCode) {
        match self.format {
            EmitFormat::Plain => {
                let _ = writeln!(self.stdout, "{}", directive.as_str());
            }
            EmitFormat::Json => {
                let envelope = EmitEnvelope {
                    schema_version: ENVELOPE_SCHEMA_VERSION,
                    outcome: exit_code.as_outcome_str(),
                    directive: Some(directive.into_inner()),
                    error: None,
                };
                self.write_envelope(envelope);
            }
        }
    }

    fn write_err(&mut self, err: &BsuiteCoreError, exit_code: ExitCode) {
        match self.format {
            EmitFormat::Plain => {
                let _ = writeln!(self.stderr, "{}", err);
            }
            EmitFormat::Json => {
                let envelope = EmitEnvelope {
                    schema_version: ENVELOPE_SCHEMA_VERSION,
                    outcome: exit_code.as_outcome_str(),
                    directive: None,
                    error: Some(ErrorDetail {
                        kind: error_variant_name(err).to_owned(),
                        message: err.to_string(),
                    }),
                };
                self.write_envelope(envelope);
            }
        }
    }

    fn write_envelope(&mut self, envelope: EmitEnvelope) {
        let json = serde_json::to_string(&envelope)
            .expect("EmitEnvelope fields are all JSON-safe; serialization is infallible");
        let _ = writeln!(self.stdout, "{json}");
    }
}

impl ExitCodeEmitter for ProcessExitEmitter {
    fn exit_code_for(&self, err: &BsuiteCoreError) -> ExitCode {
        BsuiteCoreError::route(err)
    }
}

const ENVELOPE_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct EmitEnvelope {
    schema_version: u32,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    directive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorDetail>,
}

#[derive(Serialize)]
struct ErrorDetail {
    kind: String,
    message: String,
}

fn error_variant_name(err: &BsuiteCoreError) -> &'static str {
    match err {
        BsuiteCoreError::PromptResolution(_) => "PromptResolution",
        BsuiteCoreError::Update(_) => "Update",
        BsuiteCoreError::Transcript(_) => "Transcript",
        BsuiteCoreError::TranscriptPathFailed(_) => "TranscriptPathFailed",
        BsuiteCoreError::TranscriptWriteFailed(_) => "TranscriptWriteFailed",
        BsuiteCoreError::TranscriptSerializationFailed(_) => "TranscriptSerializationFailed",
        BsuiteCoreError::TranscriptManifestFailed(_) => "TranscriptManifestFailed",
        BsuiteCoreError::ManifestFetchFailed(_) => "ManifestFetchFailed",
        BsuiteCoreError::SignatureFetchFailed(_) => "SignatureFetchFailed",
        BsuiteCoreError::ManifestSignatureInvalid => "ManifestSignatureInvalid",
        BsuiteCoreError::ManifestUnknownSigningKey(_) => "ManifestUnknownSigningKey",
        BsuiteCoreError::ManifestSigningKeyExpired(_) => "ManifestSigningKeyExpired",
        BsuiteCoreError::ManifestSigningKeyNotYetValid(_) => "ManifestSigningKeyNotYetValid",
        BsuiteCoreError::ManifestSigningKeyRevoked(_) => "ManifestSigningKeyRevoked",
        BsuiteCoreError::ManifestSchemaMismatch { .. } => "ManifestSchemaMismatch",
        BsuiteCoreError::ManifestPlatformMissing(_) => "ManifestPlatformMissing",
        BsuiteCoreError::ArtifactFetchFailed(_) => "ArtifactFetchFailed",
        BsuiteCoreError::ArtifactSha256Mismatch { .. } => "ArtifactSha256Mismatch",
        BsuiteCoreError::ResponseBodyTooLarge { .. } => "ResponseBodyTooLarge",
        BsuiteCoreError::AtomicInstallFailed(_) => "AtomicInstallFailed",
        BsuiteCoreError::InstallRollbackFailed(_) => "InstallRollbackFailed",
        BsuiteCoreError::ManifestOverlay(_) => "ManifestOverlay",
        BsuiteCoreError::ExitCode(_) => "ExitCode",
        BsuiteCoreError::VisibilityEvidence(_) => "VisibilityEvidence",
        BsuiteCoreError::AdapterHostBinding(_) => "AdapterHostBinding",
        BsuiteCoreError::CorpusSignatureInvalid => "CorpusSignatureInvalid",
        BsuiteCoreError::CorpusSchemaMismatch { .. } => "CorpusSchemaMismatch",
        BsuiteCoreError::CorpusDeserializationFailed(_) => "CorpusDeserializationFailed",
        BsuiteCoreError::CorpusKeyMissing(_) => "CorpusKeyMissing",
    }
}
