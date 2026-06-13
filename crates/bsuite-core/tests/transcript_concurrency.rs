mod transcript_common;

use bsuite_core::{FileSystemTranscriptAppender, TranscriptAppender};
use std::sync::Arc;
use transcript_common::transcript_record;

#[test]
fn concurrent_appends_preserve_files_and_manifest_entries() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().join("bground");
    let appender = Arc::new(FileSystemTranscriptAppender::from_base_dir(
        base.clone(),
        90,
    ));
    let handles = (0..8)
        .map(|index| {
            let appender = Arc::clone(&appender);
            std::thread::spawn(move || {
                appender
                    .append(&transcript_record(format!("invocation-{index}")))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        assert!(handle.join().unwrap().as_path().exists());
    }

    let transcript_count = std::fs::read_dir(&base)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .count();
    let manifest = std::fs::read_to_string(base.join("manifest-2026-06-13.txt")).unwrap();

    assert_eq!(transcript_count, 8);
    assert_eq!(manifest.lines().count(), 8);
}
