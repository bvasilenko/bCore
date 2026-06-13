mod common;

use base64::Engine;
use bsuite_core::{
    BsuiteCoreError, CorpusEntry, CorpusFile, CorpusResolver, ProvenanceRecord, RoutingKey,
    corpus::canonical_payload_bytes,
};
use common::{corpus_entry, corpus_file, corpus_signing_key, signed_toml, single_entry_corpus};
use ed25519_dalek::VerifyingKey;

const ED25519_BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

const ED25519_IDENTITY_COMPRESSED: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn canonical_string(corpus: &CorpusFile) -> String {
    String::from_utf8(canonical_payload_bytes(corpus).expect("canonical payload"))
        .expect("canonical payload is UTF-8")
}

fn corpus_with_edge_values(
    directive: impl Into<String>,
    observation_source: impl Into<String>,
    pre_compliance: f64,
    post_compliance: f64,
) -> CorpusFile {
    CorpusFile {
        schema_version: 1,
        signature: "ed25519:ignored".to_string(),
        canonical_key_id: "key-\u{20ac}".to_string(),
        entries: vec![CorpusEntry {
            routing_key: RoutingKey::BGround,
            directive: directive.into(),
            provenance: ProvenanceRecord {
                run_id: "run-\u{1f600}".to_string(),
                iteration: 7,
                observation_source: observation_source.into(),
                pre_compliance,
                post_compliance,
            },
        }],
    }
}

#[test]
fn valid_signature_returns_resolver_for_each_routing_key() {
    let key = corpus_signing_key(7);

    for routing_key in RoutingKey::ALL {
        let toml = signed_toml(single_entry_corpus(routing_key), &key);
        let resolver = CorpusResolver::from_toml_signed(&toml, &VerifyingKey::from(&key))
            .expect("valid signature must load");

        assert_eq!(resolver.entry_count(), 1);
        assert_eq!(resolver.entries_for(routing_key).len(), 1);
    }
}

#[test]
fn signature_rejects_wrong_key() {
    let good_key = corpus_signing_key(7);
    let wrong_key = corpus_signing_key(8);
    let toml = signed_toml(single_entry_corpus(RoutingKey::BGround), &good_key);
    let error = CorpusResolver::from_toml_signed(&toml, &VerifyingKey::from(&wrong_key))
        .expect_err("wrong key must fail verification");

    assert_eq!(error, BsuiteCoreError::CorpusSignatureInvalid);
}

#[test]
fn signature_rejects_every_signed_payload_field_tamper() {
    let key = corpus_signing_key(7);
    let corpus = single_entry_corpus(RoutingKey::BGround);
    let valid_toml = signed_toml(corpus, &key);

    for (name, tampered_toml) in [
        ("directive", valid_toml.replace("inspect", "ignore")),
        ("canonical key", valid_toml.replace("test-key", "other-key")),
        ("routing key", valid_toml.replace("bground", "banchor")),
        (
            "provenance",
            valid_toml.replace("contract-test", "altered-source"),
        ),
    ] {
        let error = CorpusResolver::from_toml_signed(&tampered_toml, &VerifyingKey::from(&key))
            .expect_err("tamper must fail verification");

        assert_eq!(error, BsuiteCoreError::CorpusSignatureInvalid, "{name}");
    }
}

fn basepoint_signature_with_scalar_one() -> [u8; 64] {
    let mut signature_bytes = [0_u8; 64];
    signature_bytes[..32].copy_from_slice(&ED25519_BASEPOINT_COMPRESSED);
    signature_bytes[32] = 1;
    signature_bytes
}

fn identity_weak_verifying_key() -> VerifyingKey {
    let weak_key = VerifyingKey::from_bytes(&ED25519_IDENTITY_COMPRESSED)
        .expect("identity encoding is a recognized weak verifying key");
    assert!(weak_key.is_weak());
    weak_key
}

fn corpus_toml_with_signature(signature_bytes: [u8; 64]) -> String {
    let mut corpus = single_entry_corpus(RoutingKey::BGround);
    corpus.signature = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature_bytes)
    );
    toml::to_string(&corpus).expect("corpus encodes as TOML")
}

fn assert_signed_corpus_rejected(toml: &str, pubkey: &VerifyingKey) {
    let error = CorpusResolver::from_toml_signed(toml, pubkey)
        .expect_err("strict signed corpus acceptance must reject invalid verifier states");

    assert_eq!(error, BsuiteCoreError::CorpusSignatureInvalid);
}

#[test]
fn strict_verification_rejects_low_order_public_key_acceptance() {
    let weak_key = identity_weak_verifying_key();
    let toml = corpus_toml_with_signature(basepoint_signature_with_scalar_one());

    assert_signed_corpus_rejected(&toml, &weak_key);
}

#[test]
fn malformed_signature_strings_return_signature_invalid() {
    let key = corpus_signing_key(7);

    for signature in [
        "not-ed25519",
        "ed25519:not-base64",
        "ed25519:AA==",
        "ed25519:",
    ] {
        let mut corpus = single_entry_corpus(RoutingKey::BGround);
        corpus.signature = signature.to_string();
        let toml = toml::to_string(&corpus).expect("corpus encodes as TOML");
        let error = CorpusResolver::from_toml_signed(&toml, &VerifyingKey::from(&key))
            .expect_err("malformed signature must fail verification");

        assert_eq!(error, BsuiteCoreError::CorpusSignatureInvalid);
    }
}

#[test]
fn schema_mismatch_returns_schema_error_before_signature_use() {
    let key = corpus_signing_key(7);
    let mut corpus = single_entry_corpus(RoutingKey::BGround);
    corpus.schema_version = 2;
    corpus.signature = "not-ed25519".to_string();
    let toml = toml::to_string(&corpus).expect("corpus encodes as TOML");
    let error = CorpusResolver::from_toml_signed(&toml, &VerifyingKey::from(&key))
        .expect_err("schema mismatch must fail before use");

    assert_eq!(
        error,
        BsuiteCoreError::CorpusSchemaMismatch {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn equivalent_corpus_data_has_one_canonical_verification_input() {
    let key = corpus_signing_key(7);
    let toml = signed_toml(single_entry_corpus(RoutingKey::BGround), &key);
    let decoded: CorpusFile = toml::from_str(&toml).expect("fixture decodes");
    let reencoded = toml::to_string(&decoded).expect("fixture re-encodes");
    let decoded_again: CorpusFile = toml::from_str(&reencoded).expect("re-encoded fixture decodes");

    assert_eq!(
        canonical_payload_bytes(&decoded).expect("first canonical payload"),
        canonical_payload_bytes(&decoded_again).expect("second canonical payload")
    );
}

#[test]
fn canonical_payload_uses_jcs_key_order_and_string_escaping() {
    let corpus = corpus_with_edge_values(
        "Line\nEuro:\u{20ac} Quote:\" Slash:/",
        "source\twith-control",
        0.000001,
        1e21,
    );
    let canonical = canonical_string(&corpus);

    assert_eq!(
        canonical,
        "{\"canonical_key_id\":\"key-€\",\"entries\":[{\"directive\":\"Line\\nEuro:€ Quote:\\\" Slash:/\",\"provenance\":{\"iteration\":7,\"observation_source\":\"source\\twith-control\",\"post_compliance\":1e+21,\"pre_compliance\":0.000001,\"run_id\":\"run-😀\"},\"routing_key\":\"bground\"}],\"schema_version\":1}"
    );
}

#[test]
fn canonical_payload_uses_jcs_number_serialization_for_provenance_scores() {
    for (bits, expected) in [
        (0x0000000000000000, "0"),
        (0x8000000000000000, "0"),
        (0x0000000000000001, "5e-324"),
        (0x7fefffffffffffff, "1.7976931348623157e+308"),
        (0x4340000000000000, "9007199254740992"),
        (0x44b52d02c7e14af6, "1e+23"),
        (0x3eb0c6f7a0b5ed8d, "0.000001"),
        (0x43143ff3c1cb0959, "1424953923781206.2"),
    ] {
        let corpus = corpus_with_edge_values("directive", "source", f64::from_bits(bits), 0.5);
        let canonical = canonical_string(&corpus);

        assert!(
            canonical.contains(&format!("\"pre_compliance\":{expected}")),
            "canonical payload used unexpected number serialization for {bits:#018x}: {canonical}"
        );
    }
}

#[test]
fn canonical_payload_rejects_non_finite_provenance_scores() {
    for score in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let corpus = corpus_with_edge_values("directive", "source", score, 0.5);
        let error = canonical_payload_bytes(&corpus)
            .expect_err("non-finite corpus scores must not produce signed payload bytes");

        assert!(matches!(
            error,
            BsuiteCoreError::CorpusDeserializationFailed(_)
        ));
    }
}

#[test]
fn equivalent_toml_field_order_verifies_against_same_signature() {
    let key = corpus_signing_key(7);
    let signed = signed_toml(
        corpus_file(vec![corpus_entry(
            RoutingKey::BGround,
            "Stop and inspect the supplied evidence before acting.",
            1,
        )]),
        &key,
    );
    let signed_corpus: CorpusFile = toml::from_str(&signed).expect("signed corpus decodes");
    let reordered_toml = format!(
        r#"canonical_key_id = "test-key"
signature = "{}"
schema_version = 1

[[entries]]
directive = "Stop and inspect the supplied evidence before acting."
routing_key = "bground"

[entries.provenance]
post_compliance = 0.95
pre_compliance = 0.25
observation_source = "contract-test"
iteration = 1
run_id = "test-run-1"
"#,
        signed_corpus.signature
    );

    CorpusResolver::from_toml_signed(&reordered_toml, &VerifyingKey::from(&key))
        .expect("equivalent TOML field order must verify against the same signature");
}
