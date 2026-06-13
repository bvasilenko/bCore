use bsuite_core::transcript_writer::{
    TranscriptOperatingSystem, TranscriptPathEnvironment, transcript_root_for_environment,
};
use bsuite_core::{BsuiteCoreError, FileSystemTranscriptAppender};
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn environment(operating_system: TranscriptOperatingSystem) -> TranscriptPathEnvironment {
    TranscriptPathEnvironment {
        operating_system,
        home_dir: None,
        xdg_state_home: None,
        local_app_data: None,
    }
}

fn path(value: &str) -> Option<PathBuf> {
    Some(PathBuf::from(value))
}

#[test]
fn transcript_root_resolution_covers_supported_operating_system_defaults() {
    let cases = [
        (
            TranscriptPathEnvironment {
                operating_system: TranscriptOperatingSystem::Linux,
                xdg_state_home: path("/state"),
                ..environment(TranscriptOperatingSystem::Linux)
            },
            PathBuf::from("/state/bsuite/transcripts"),
        ),
        (
            TranscriptPathEnvironment {
                operating_system: TranscriptOperatingSystem::Linux,
                home_dir: path("/home/operator"),
                ..environment(TranscriptOperatingSystem::Linux)
            },
            PathBuf::from("/home/operator/.local/state/bsuite/transcripts"),
        ),
        (
            environment(TranscriptOperatingSystem::Linux),
            PathBuf::from(".local/state/bsuite/transcripts"),
        ),
        (
            TranscriptPathEnvironment {
                operating_system: TranscriptOperatingSystem::Macos,
                home_dir: path("/Users/operator"),
                ..environment(TranscriptOperatingSystem::Macos)
            },
            PathBuf::from("/Users/operator/Library/Application Support/bsuite/transcripts"),
        ),
        (
            environment(TranscriptOperatingSystem::Macos),
            PathBuf::from("Library/Application Support/bsuite/transcripts"),
        ),
        (
            TranscriptPathEnvironment {
                operating_system: TranscriptOperatingSystem::Windows,
                local_app_data: path(r"C:\Users\operator\AppData\Local"),
                ..environment(TranscriptOperatingSystem::Windows)
            },
            PathBuf::from(r"C:\Users\operator\AppData\Local").join("bsuite/transcripts"),
        ),
        (
            environment(TranscriptOperatingSystem::Windows),
            PathBuf::from("AppData/Local/bsuite/transcripts"),
        ),
        (
            environment(TranscriptOperatingSystem::Other),
            PathBuf::from("bsuite/transcripts"),
        ),
    ];

    for (environment, expected) in cases {
        assert_eq!(transcript_root_for_environment(&environment), expected);
    }
}

#[test]
fn env_var_override_controls_transcript_root() {
    let _guard = ENV_LOCK.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();

    unsafe {
        std::env::set_var("BSUITE_TRANSCRIPT_DIR", directory.path());
        std::env::remove_var("BSUITE_TRANSCRIPT_RETENTION_DAYS");
    }

    let appender = FileSystemTranscriptAppender::new("bground").unwrap();

    assert_eq!(appender.directory(), &directory.path().join("bground"));

    unsafe {
        std::env::remove_var("BSUITE_TRANSCRIPT_DIR");
    }
}

#[test]
fn invalid_retention_env_fails_visibly() {
    let _guard = ENV_LOCK.lock().unwrap();

    unsafe {
        std::env::set_var("BSUITE_TRANSCRIPT_RETENTION_DAYS", "abc");
    }

    let error = FileSystemTranscriptAppender::new("bground").err().unwrap();

    assert!(matches!(error, BsuiteCoreError::TranscriptPathFailed(_)));

    unsafe {
        std::env::remove_var("BSUITE_TRANSCRIPT_RETENTION_DAYS");
    }
}

#[test]
fn from_base_dir_keeps_explicit_directory() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().join("custom");

    let appender = FileSystemTranscriptAppender::from_base_dir(base.clone(), 30);

    assert_eq!(appender.directory(), base.as_path());
}
