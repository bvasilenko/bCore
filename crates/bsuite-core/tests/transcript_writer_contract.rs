mod transcript_common;

use bsuite_core::{
    BsuiteCoreError, FileSystemTranscriptAppender, HostContext, RoutingKey, TranscriptAppender,
    TranscriptHandle,
};
use serde_json::json;
use transcript_common::{transcript_record, transcript_record_for};

#[test]
fn transcript_record_preserves_wire_fields() {
    let record = transcript_record_for(
        "wire-fields",
        RoutingKey::BGround,
        HostContext::L2a,
        json!({"fixture": true}),
    );

    assert_eq!(record.schema_version, 1);
    assert_eq!(record.binary_name, "bground");
    assert_eq!(record.routing_key, RoutingKey::BGround);
    assert_eq!(record.host_context, HostContext::L2a);
    assert_eq!(record.additional_fields, json!({"fixture": true}));
}

#[test]
fn transcript_handle_exposes_written_path() {
    let handle = TranscriptHandle::new("transcript-1.jsonl");

    assert_eq!(handle.as_path().to_string_lossy(), "transcript-1.jsonl");
    assert_eq!(handle.as_str(), "transcript-1.jsonl");
    assert_eq!(handle.into_inner(), "transcript-1.jsonl");
}

#[test]
fn filesystem_appender_can_be_used_through_trait_without_consuming_record() {
    let directory = tempfile::tempdir().unwrap();
    let appender =
        FileSystemTranscriptAppender::from_base_dir(directory.path().join("bground"), 90);
    let record = transcript_record("ownership");

    let handle = appender.append(&record).unwrap();

    assert!(handle.as_path().exists());
    assert_eq!(record.binary_name, "bground");
}

#[test]
fn unsafe_binary_name_fails_before_path_join() {
    let error = FileSystemTranscriptAppender::new("../bground")
        .err()
        .unwrap();

    assert!(matches!(error, BsuiteCoreError::TranscriptPathFailed(_)));
}
