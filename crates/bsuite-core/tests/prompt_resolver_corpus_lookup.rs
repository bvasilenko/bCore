mod common;

use bsuite_core::{
    BsuiteCoreError, CorpusEntry, CorpusFile, CorpusResolver, EvidenceMap, ManifestOverlay,
    PromptResolver, RoutingKey,
};
use common::{corpus_entry, corpus_file, signed_resolver};

fn directive_for(key: RoutingKey) -> String {
    format!("directive for {}", key.stable_name())
}

fn duplicate_directive_for(key: RoutingKey, suffix: &str) -> String {
    format!("{} {}", key.stable_name(), suffix)
}

fn populated_evidence() -> EvidenceMap {
    EvidenceMap::from([(
        "corpus-lookup-ignored".to_string(),
        "directive remains selected by routing key".to_string(),
    )])
}

fn populated_overlay() -> ManifestOverlay {
    ManifestOverlay::empty()
}

fn resolver_with_all_keys() -> CorpusResolver {
    let entries = RoutingKey::ALL
        .into_iter()
        .enumerate()
        .map(|(index, key)| corpus_entry(key, directive_for(key), index as u32))
        .collect();

    signed_resolver(CorpusFile {
        schema_version: 1,
        signature: String::new(),
        canonical_key_id: "lookup-key".to_string(),
        entries,
    })
}

fn duplicate_entries_for_all_keys() -> Vec<CorpusEntry> {
    let first_entries = RoutingKey::ALL
        .into_iter()
        .enumerate()
        .map(|(index, key)| corpus_entry(key, duplicate_directive_for(key, "first"), index as u32));
    let second_entries = RoutingKey::ALL
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, key)| {
            corpus_entry(
                key,
                duplicate_directive_for(key, "second"),
                (RoutingKey::ALL.len() + index) as u32,
            )
        });

    first_entries.chain(second_entries).collect()
}

fn assert_resolves_to(
    resolver: &CorpusResolver,
    key: RoutingKey,
    evidence: EvidenceMap,
    overlay: Option<ManifestOverlay>,
    expected: impl AsRef<str>,
) {
    let directive = resolver
        .resolve(key, evidence, overlay)
        .expect("corpus entry must resolve");

    assert_eq!(directive.as_str(), expected.as_ref());
}

fn assert_missing_key(resolver: &CorpusResolver, key: RoutingKey) {
    let error = resolver
        .resolve(key, EvidenceMap::new(), None)
        .expect_err("missing key must be explicit");

    assert_eq!(error, BsuiteCoreError::CorpusKeyMissing(key));
    assert!(resolver.entries_for(key).is_empty());
}

#[test]
fn each_routing_key_variant_hits_the_right_entry() {
    let resolver = resolver_with_all_keys();

    for key in RoutingKey::ALL {
        assert_resolves_to(&resolver, key, EvidenceMap::new(), None, directive_for(key));
    }
}

#[test]
fn missing_key_returns_expected_error_for_empty_and_partial_corpora() {
    let empty_resolver = signed_resolver(corpus_file(Vec::new()));
    for key in RoutingKey::ALL {
        assert_missing_key(&empty_resolver, key);
    }

    for present_key in RoutingKey::ALL {
        let resolver = signed_resolver(corpus_file(vec![corpus_entry(
            present_key,
            directive_for(present_key),
            1,
        )]));

        for key in RoutingKey::ALL {
            if key == present_key {
                assert_resolves_to(&resolver, key, EvidenceMap::new(), None, directive_for(key));
            } else {
                assert_missing_key(&resolver, key);
            }
        }
    }
}

#[test]
fn evidence_and_overlay_do_not_change_lookup_for_any_routing_key() {
    let resolver = resolver_with_all_keys();
    let input_cases = [
        (EvidenceMap::new(), None),
        (EvidenceMap::new(), Some(ManifestOverlay::empty())),
        (populated_evidence(), None),
        (populated_evidence(), Some(populated_overlay())),
    ];

    for key in RoutingKey::ALL {
        for (evidence, overlay) in input_cases.clone() {
            assert_resolves_to(&resolver, key, evidence, overlay, directive_for(key));
        }
    }
}

#[test]
fn duplicate_routing_entries_are_preserved_and_resolve_by_corpus_order_for_every_key() {
    let resolver = signed_resolver(corpus_file(duplicate_entries_for_all_keys()));

    assert_eq!(resolver.entry_count(), RoutingKey::ALL.len() * 2);

    for key in RoutingKey::ALL {
        assert_eq!(resolver.entries_for(key).len(), 2);
        assert_resolves_to(
            &resolver,
            key,
            EvidenceMap::new(),
            None,
            duplicate_directive_for(key, "first"),
        );
    }
}

#[test]
fn resolver_metadata_preserves_loaded_corpus_identity() {
    let resolver = signed_resolver(CorpusFile {
        schema_version: 1,
        signature: String::new(),
        canonical_key_id: "lookup-key".to_string(),
        entries: vec![corpus_entry(RoutingKey::BSpector, "directive", 1)],
    });

    assert_eq!(resolver.entry_count(), 1);
    assert_eq!(resolver.schema_version(), 1);
    assert_eq!(resolver.canonical_key_id(), "lookup-key");
}
