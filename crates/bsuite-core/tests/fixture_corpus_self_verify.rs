use bsuite_core::{CorpusResolver, EvidenceMap, PromptResolver, RoutingKey};
use ed25519_dalek::{SigningKey, VerifyingKey};

fn fixture_public_key() -> VerifyingKey {
    let pubkey_bytes: [u8; 32] = include_bytes!("fixtures/corpus-sample-v1-pubkey.bin")
        .as_slice()
        .try_into()
        .expect("fixture public key is 32 bytes");
    VerifyingKey::from_bytes(&pubkey_bytes).expect("fixture public key is valid")
}

#[test]
fn fixture_corpus_self_verifies_with_test_only_public_key() {
    let corpus = include_str!("fixtures/corpus-sample-v1.toml");
    let resolver = CorpusResolver::from_toml_signed(corpus, &fixture_public_key())
        .expect("fixture corpus signature verifies");

    assert_eq!(resolver.entry_count(), 12);
    for key in RoutingKey::ALL {
        assert_eq!(resolver.entries_for(key).len(), 2);
        let first_entry = resolver
            .entries_for(key)
            .first()
            .expect("fixture keeps at least one entry for every routing key");
        let directive = resolver
            .resolve(key, EvidenceMap::new(), None)
            .expect("fixture entry resolves");

        assert_eq!(directive.as_str(), first_entry.directive);
    }
}

#[test]
fn fixture_signing_key_is_test_only_and_matches_public_key() {
    let signkey_bytes: [u8; 32] = include_bytes!("fixtures/corpus-sample-v1-signkey.bin")
        .as_slice()
        .try_into()
        .expect("fixture signing key is 32 bytes");
    let signing_key = SigningKey::from_bytes(&signkey_bytes);

    assert_eq!(VerifyingKey::from(&signing_key), fixture_public_key());
}
