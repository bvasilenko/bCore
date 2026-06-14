use bsuite_core::{HostContext, RoutingKey, TranscriptRecord};
use chrono::Utc;
use serde_json::{Value, json};

pub fn today_manifest_name() -> String {
    format!("manifest-{}.txt", Utc::now().format("%Y-%m-%d"))
}

pub fn transcript_record(invocation_id: impl Into<String>) -> TranscriptRecord {
    transcript_record_for(
        invocation_id,
        RoutingKey::BGround,
        HostContext::L2a,
        json!({}),
    )
}

pub fn transcript_record_for(
    invocation_id: impl Into<String>,
    routing_key: RoutingKey,
    host_context: HostContext,
    additional_fields: Value,
) -> TranscriptRecord {
    TranscriptRecord {
        schema_version: 1,
        binary_name: routing_key.stable_name().to_string(),
        binary_version: "0.2.0-alpha.3".to_string(),
        invocation_id: invocation_id.into(),
        timestamp: Utc::now(),
        routing_key,
        host_context,
        exit_code: 0,
        directive_emitted: true,
        elapsed_ms: 10,
        corpus_version: 1,
        additional_fields,
    }
}
