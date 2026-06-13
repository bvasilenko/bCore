use crate::{BsuiteCoreError, RoutingKey};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const CORPUS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusFile {
    pub schema_version: u32,
    pub signature: String,
    pub canonical_key_id: String,
    pub entries: Vec<CorpusEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub routing_key: RoutingKey,
    pub directive: String,
    pub provenance: ProvenanceRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub run_id: String,
    pub iteration: u32,
    pub observation_source: String,
    pub pre_compliance: f64,
    pub post_compliance: f64,
}

impl CorpusFile {
    pub fn payload_without_signature(&self) -> CorpusPayload<'_> {
        CorpusPayload {
            schema_version: self.schema_version,
            canonical_key_id: &self.canonical_key_id,
            entries: &self.entries,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CorpusPayload<'a> {
    pub schema_version: u32,
    pub canonical_key_id: &'a str,
    pub entries: &'a [CorpusEntry],
}

pub fn parse_signed_corpus(
    toml_str: &str,
    pubkey: &VerifyingKey,
) -> Result<CorpusFile, BsuiteCoreError> {
    let corpus = parse_corpus_toml(toml_str)?;
    verify_schema_version(corpus.schema_version)?;
    verify_corpus_signature(&corpus, pubkey)?;
    Ok(corpus)
}

fn parse_corpus_toml(toml_str: &str) -> Result<CorpusFile, BsuiteCoreError> {
    toml::from_str(toml_str)
        .map_err(|error| BsuiteCoreError::CorpusDeserializationFailed(error.to_string()))
}

fn verify_schema_version(found: u32) -> Result<(), BsuiteCoreError> {
    if found == CORPUS_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(BsuiteCoreError::CorpusSchemaMismatch {
            expected: CORPUS_SCHEMA_VERSION,
            found,
        })
    }
}

fn verify_corpus_signature(
    corpus: &CorpusFile,
    pubkey: &VerifyingKey,
) -> Result<(), BsuiteCoreError> {
    let signature = parse_ed25519_signature(&corpus.signature)?;
    let signed_payload = canonical_payload_bytes(corpus)?;

    pubkey
        .verify_strict(&signed_payload, &signature)
        .map_err(|_| BsuiteCoreError::CorpusSignatureInvalid)
}

fn parse_ed25519_signature(value: &str) -> Result<Signature, BsuiteCoreError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or(BsuiteCoreError::CorpusSignatureInvalid)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| BsuiteCoreError::CorpusSignatureInvalid)?;
    Signature::from_slice(&bytes).map_err(|_| BsuiteCoreError::CorpusSignatureInvalid)
}

pub fn canonical_payload_bytes(corpus: &CorpusFile) -> Result<Vec<u8>, BsuiteCoreError> {
    validate_finite_provenance_scores(corpus)?;

    serde_json_canonicalizer::to_vec(&corpus.payload_without_signature())
        .map_err(|error| BsuiteCoreError::CorpusDeserializationFailed(error.to_string()))
}

fn validate_finite_provenance_scores(corpus: &CorpusFile) -> Result<(), BsuiteCoreError> {
    for entry in &corpus.entries {
        if !entry.provenance.pre_compliance.is_finite()
            || !entry.provenance.post_compliance.is_finite()
        {
            return Err(BsuiteCoreError::CorpusDeserializationFailed(
                "corpus provenance compliance scores must be finite".to_string(),
            ));
        }
    }

    Ok(())
}
