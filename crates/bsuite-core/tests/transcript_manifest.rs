mod transcript_common;

use bsuite_core::{FileSystemTranscriptAppender, TranscriptAppender};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use transcript_common::{today_manifest_name, transcript_record};

#[test]
fn manifest_exists_after_first_append() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().join("bground");
    let appender = FileSystemTranscriptAppender::from_base_dir(base.clone(), 90);

    appender.append(&transcript_record("first")).unwrap();

    assert!(base.join(today_manifest_name()).is_file());
}

#[test]
fn manifest_is_recomputed_after_second_append_with_matching_hashes() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().join("bground");
    let appender = FileSystemTranscriptAppender::from_base_dir(base.clone(), 90);

    appender.append(&transcript_record("first")).unwrap();
    appender.append(&transcript_record("second")).unwrap();

    let manifest = std::fs::read_to_string(base.join(today_manifest_name())).unwrap();
    let entries = manifest
        .lines()
        .map(|line| {
            let (file, hash) = line.split_once(' ').unwrap();
            (file.to_string(), hash.to_string())
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(entries.len(), 2);
    for (file, expected_hash) in entries {
        let bytes = std::fs::read(base.join(file)).unwrap();
        let actual_hash = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(actual_hash, expected_hash);
    }
}
