//! Lookup latency stays bounded so command-line binaries can emit directives without
//! making resolver overhead visible to the calling workflow. The non-binding target for
//! warm in-process lookup is p99 <= 10 microseconds on a 50-entry corpus.

use crate::{
    BsuiteCoreError, CorpusEntry, CorpusFile, ManifestOverlay, RoutingKey,
    corpus::parse_signed_corpus,
};
use ed25519_dalek::VerifyingKey;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DirectiveString(String);

impl DirectiveString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

pub type EvidenceMap = BTreeMap<String, String>;

pub trait PromptResolver {
    fn resolve(
        &self,
        key: RoutingKey,
        evidence: EvidenceMap,
        overlay: Option<ManifestOverlay>,
    ) -> Result<DirectiveString, BsuiteCoreError>;
}

#[derive(Debug, Clone)]
pub struct CorpusResolver {
    entries: CorpusEntryIndex,
    schema_version: u32,
    canonical_key_id: String,
}

#[derive(Debug, Clone, Default)]
struct CorpusEntryIndex {
    by_routing_key: HashMap<RoutingKey, Vec<CorpusEntry>>,
    total_entries: usize,
}

impl CorpusEntryIndex {
    fn from_entries(entries: Vec<CorpusEntry>) -> Self {
        let total_entries = entries.len();
        let mut by_routing_key: HashMap<RoutingKey, Vec<CorpusEntry>> = HashMap::new();

        for entry in entries {
            by_routing_key
                .entry(entry.routing_key)
                .or_default()
                .push(entry);
        }

        Self {
            by_routing_key,
            total_entries,
        }
    }

    fn first_for(&self, key: RoutingKey) -> Option<&CorpusEntry> {
        self.by_routing_key
            .get(&key)
            .and_then(|entries| entries.first())
    }

    fn entries_for(&self, key: RoutingKey) -> &[CorpusEntry] {
        self.by_routing_key
            .get(&key)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn len(&self) -> usize {
        self.total_entries
    }
}

impl CorpusResolver {
    pub fn from_toml_signed(
        toml_str: &str,
        pubkey: &VerifyingKey,
    ) -> Result<Self, BsuiteCoreError> {
        let corpus = parse_signed_corpus(toml_str, pubkey)?;
        Ok(Self::from_verified_corpus_file(corpus))
    }

    fn from_verified_corpus_file(corpus: CorpusFile) -> Self {
        Self {
            entries: CorpusEntryIndex::from_entries(corpus.entries),
            schema_version: corpus.schema_version,
            canonical_key_id: corpus.canonical_key_id,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn canonical_key_id(&self) -> &str {
        &self.canonical_key_id
    }

    pub fn entries_for(&self, key: RoutingKey) -> &[CorpusEntry] {
        self.entries.entries_for(key)
    }
}

impl PromptResolver for CorpusResolver {
    fn resolve(
        &self,
        key: RoutingKey,
        _evidence: EvidenceMap,
        _overlay: Option<ManifestOverlay>,
    ) -> Result<DirectiveString, BsuiteCoreError> {
        let entry = self
            .entries
            .first_for(key)
            .ok_or(BsuiteCoreError::CorpusKeyMissing(key))?;

        Ok(DirectiveString::new(entry.directive.clone()))
    }
}
