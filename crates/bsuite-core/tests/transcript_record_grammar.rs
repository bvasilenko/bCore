use bsuite_core::{HostContext, RoutingKey, TranscriptRecord};
use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use serde_json::json;

fn any_routing_key() -> impl Strategy<Value = RoutingKey> {
    prop_oneof![
        Just(RoutingKey::BGround),
        Just(RoutingKey::BAnchor),
        Just(RoutingKey::BSmell),
        Just(RoutingKey::BRatch),
        Just(RoutingKey::BWatch),
        Just(RoutingKey::BSpector),
    ]
}

fn any_host_context() -> impl Strategy<Value = HostContext> {
    prop_oneof![
        Just(HostContext::L2a),
        Just(HostContext::PayloadV3),
        Just(HostContext::StrapiV5),
        Just(HostContext::SanityV3),
        Just(HostContext::DirectusV10),
    ]
}

proptest! {
    #[test]
    fn transcript_record_json_round_trips(
        routing_key in any_routing_key(),
        host_context in any_host_context(),
        exit_code in 0_u8..=64,
        elapsed_ms in 0_u64..1_000_000,
        corpus_version in 0_u32..10_000,
    ) {
        let record = TranscriptRecord {
            schema_version: 1,
            binary_name: "bground".to_string(),
            binary_version: "0.2.0-alpha.3".to_string(),
            invocation_id: "01J00000000000000000000000".to_string(),
            timestamp: Utc.with_ymd_and_hms(2026, 6, 13, 12, 0, 0).unwrap(),
            routing_key,
            host_context,
            exit_code,
            directive_emitted: true,
            elapsed_ms,
            corpus_version,
            additional_fields: json!({"case": "round-trip"}),
        };

        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: TranscriptRecord = serde_json::from_str(&encoded).unwrap();

        prop_assert_eq!(decoded, record);
    }
}

#[test]
fn malformed_transcript_json_is_rejected() {
    let error = serde_json::from_str::<TranscriptRecord>("{not-json").unwrap_err();

    assert!(error.is_syntax());
}
