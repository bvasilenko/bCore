mod transcript_common;

use bsuite_core::{FileSystemTranscriptAppender, TranscriptAppender};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use transcript_common::transcript_record;
use ulid::Ulid;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn write_owned_transcript(base: &Path, age: Duration) -> PathBuf {
    let ulid = Ulid::from_datetime(SystemTime::now() - age);
    let path = base.join(format!("{ulid}.jsonl"));
    fs::write(&path, "{}\n").unwrap();
    path
}

#[test]
fn retention_removes_expired_owned_files_and_preserves_fresh_and_unrelated_files() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().join("bground");
    fs::create_dir_all(&base).unwrap();
    let old_path = write_owned_transcript(&base, Duration::from_secs(3 * 24 * 60 * 60));
    let fresh_path = write_owned_transcript(&base, Duration::ZERO);
    let unrelated_path = base.join("not-owned.txt");
    fs::write(&unrelated_path, "leave me").unwrap();

    let appender = FileSystemTranscriptAppender::from_base_dir(base.clone(), 1);
    appender.append(&transcript_record("fresh")).unwrap();

    assert!(!old_path.exists());
    assert!(fresh_path.exists());
    assert!(unrelated_path.exists());
    let manifest = fs::read_to_string(base.join("manifest-2026-06-13.txt")).unwrap();
    assert!(!manifest.contains("not-owned.txt"));
}

#[test]
fn retention_env_override_changes_cutoff_for_default_appender() {
    let _guard = ENV_LOCK.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().join("bground");
    fs::create_dir_all(&base).unwrap();
    let two_days_old = write_owned_transcript(&base, Duration::from_secs(2 * 24 * 60 * 60));

    unsafe {
        std::env::set_var("BSUITE_TRANSCRIPT_DIR", directory.path());
        std::env::set_var("BSUITE_TRANSCRIPT_RETENTION_DAYS", "3");
    }

    FileSystemTranscriptAppender::new("bground")
        .unwrap()
        .append(&transcript_record("preserve-with-three-day-retention"))
        .unwrap();

    assert!(two_days_old.exists());

    unsafe {
        std::env::set_var("BSUITE_TRANSCRIPT_RETENTION_DAYS", "1");
    }

    FileSystemTranscriptAppender::new("bground")
        .unwrap()
        .append(&transcript_record("remove-with-one-day-retention"))
        .unwrap();

    assert!(!two_days_old.exists());

    unsafe {
        std::env::remove_var("BSUITE_TRANSCRIPT_DIR");
        std::env::remove_var("BSUITE_TRANSCRIPT_RETENTION_DAYS");
    }
}
