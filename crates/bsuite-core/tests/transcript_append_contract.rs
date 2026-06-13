mod transcript_common;

use bsuite_core::{FileSystemTranscriptAppender, TranscriptAppender, TranscriptRecord};
use transcript_common::transcript_record;

#[test]
fn single_append_produces_ulid_named_jsonl_file() {
    let directory = tempfile::tempdir().unwrap();
    let appender =
        FileSystemTranscriptAppender::from_base_dir(directory.path().join("bground"), 90);
    let record = transcript_record("first");

    let handle = appender.append(&record).unwrap();
    let path = handle.as_path();

    assert_eq!(path.extension().unwrap(), "jsonl");
    assert_eq!(path.file_stem().unwrap().to_string_lossy().len(), 26);
    let content = std::fs::read_to_string(path).unwrap();
    assert_eq!(content.lines().count(), 1);
    let decoded: TranscriptRecord = serde_json::from_str(content.trim_end()).unwrap();
    assert_eq!(decoded, record);
}

#[test]
fn sequential_appends_produce_lexicographically_ordered_ulids() {
    let directory = tempfile::tempdir().unwrap();
    let appender =
        FileSystemTranscriptAppender::from_base_dir(directory.path().join("bground"), 90);

    let first = appender.append(&transcript_record("first")).unwrap();
    let second = appender.append(&transcript_record("second")).unwrap();

    let first_name = first.as_path().file_name().unwrap().to_string_lossy();
    let second_name = second.as_path().file_name().unwrap().to_string_lossy();
    assert!(first_name < second_name);
}

#[test]
fn returned_handle_points_to_the_written_file() {
    let directory = tempfile::tempdir().unwrap();
    let appender =
        FileSystemTranscriptAppender::from_base_dir(directory.path().join("bground"), 90);

    let handle = appender.append(&transcript_record("first")).unwrap();

    assert!(handle.as_path().is_file());
}
