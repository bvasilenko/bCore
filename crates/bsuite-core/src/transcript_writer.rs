use crate::{BsuiteCoreError, HostContext, RoutingKey};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use ulid::{Generator, Ulid};

const DEFAULT_RETENTION_DAYS: u32 = 90;
const TRANSCRIPT_DIR_ENV: &str = "BSUITE_TRANSCRIPT_DIR";
const RETENTION_DAYS_ENV: &str = "BSUITE_TRANSCRIPT_RETENTION_DAYS";
const MANIFEST_TMP_NAME: &str = "manifest.tmp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptOperatingSystem {
    Linux,
    Macos,
    Windows,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptPathEnvironment {
    pub operating_system: TranscriptOperatingSystem,
    pub home_dir: Option<PathBuf>,
    pub xdg_state_home: Option<PathBuf>,
    pub local_app_data: Option<PathBuf>,
}

impl TranscriptPathEnvironment {
    pub fn current() -> Self {
        Self {
            operating_system: current_operating_system(),
            home_dir: env_path("HOME"),
            xdg_state_home: env_path("XDG_STATE_HOME"),
            local_app_data: env_path("LOCALAPPDATA"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TranscriptRecord {
    pub schema_version: u32,
    pub binary_name: String,
    pub binary_version: String,
    pub invocation_id: String,
    pub timestamp: DateTime<Utc>,
    pub routing_key: RoutingKey,
    pub host_context: HostContext,
    pub exit_code: u8,
    pub directive_emitted: bool,
    pub elapsed_ms: u64,
    pub corpus_version: u32,
    pub additional_fields: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TranscriptHandle {
    path: PathBuf,
}

impl TranscriptHandle {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn as_str(&self) -> &str {
        self.path.to_str().unwrap_or("")
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }

    pub fn into_inner(self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

pub trait TranscriptAppender {
    fn append(&self, record: &TranscriptRecord) -> Result<TranscriptHandle, BsuiteCoreError>;
}

pub struct FileSystemTranscriptAppender {
    directory: PathBuf,
    retention_days: u32,
    ulids: Mutex<Generator>,
    manifest_lock: Mutex<()>,
}

impl FileSystemTranscriptAppender {
    pub fn new(binary_name: &str) -> Result<Self, BsuiteCoreError> {
        validate_binary_name(binary_name)?;
        let retention_days = retention_days_from_env()?;
        let root = transcript_root_from_env()?.unwrap_or_else(|| {
            transcript_root_for_environment(&TranscriptPathEnvironment::current())
        });
        Ok(Self::from_base_dir(root.join(binary_name), retention_days))
    }

    pub fn from_base_dir(base_dir: PathBuf, retention_days: u32) -> Self {
        Self {
            directory: base_dir,
            retention_days,
            ulids: Mutex::new(Generator::new()),
            manifest_lock: Mutex::new(()),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn next_path(&self) -> Result<PathBuf, BsuiteCoreError> {
        for _ in 0..8 {
            let path = self.directory.join(format!("{}.jsonl", self.next_ulid()?));
            if !path.exists() {
                return Ok(path);
            }
        }
        Err(BsuiteCoreError::TranscriptWriteFailed(
            "could not allocate a unique transcript file name".to_string(),
        ))
    }

    fn next_ulid(&self) -> Result<Ulid, BsuiteCoreError> {
        let mut generator = self.ulids.lock().map_err(|_| {
            BsuiteCoreError::TranscriptWriteFailed(
                "transcript id generator lock failed".to_string(),
            )
        })?;
        generator.generate().map_err(|error| {
            BsuiteCoreError::TranscriptWriteFailed(format!(
                "transcript id generation failed: {error}"
            ))
        })
    }
}

impl TranscriptAppender for FileSystemTranscriptAppender {
    fn append(&self, record: &TranscriptRecord) -> Result<TranscriptHandle, BsuiteCoreError> {
        fs::create_dir_all(&self.directory).map_err(path_error)?;
        sweep_retention(&self.directory, self.retention_days)?;
        let final_path = self.next_path()?;
        write_record_atomically(record, &final_path)?;
        verify_record(&final_path, record)?;
        rewrite_daily_manifest(&self.directory, record.timestamp, &self.manifest_lock)?;
        Ok(TranscriptHandle::new(final_path))
    }
}

fn validate_binary_name(binary_name: &str) -> Result<(), BsuiteCoreError> {
    let path = Path::new(binary_name);
    let valid = !binary_name.is_empty()
        && path.file_name() == Some(OsStr::new(binary_name))
        && path.components().count() == 1
        && !binary_name.contains(std::path::MAIN_SEPARATOR)
        && !binary_name.contains('/')
        && !binary_name.contains('\\');
    if valid {
        Ok(())
    } else {
        Err(BsuiteCoreError::TranscriptPathFailed(format!(
            "unsafe binary name: {binary_name:?}"
        )))
    }
}

fn transcript_root_from_env() -> Result<Option<PathBuf>, BsuiteCoreError> {
    match env::var(TRANSCRIPT_DIR_ENV) {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => Ok(Some(PathBuf::from(value))),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(BsuiteCoreError::TranscriptPathFailed(format!(
            "{TRANSCRIPT_DIR_ENV} is invalid: {error}"
        ))),
    }
}

fn retention_days_from_env() -> Result<u32, BsuiteCoreError> {
    match env::var(RETENTION_DAYS_ENV) {
        Ok(value) => value.parse::<u32>().map_err(|error| {
            BsuiteCoreError::TranscriptPathFailed(format!(
                "{RETENTION_DAYS_ENV} must be a non-negative whole number: {error}"
            ))
        }),
        Err(env::VarError::NotPresent) => Ok(DEFAULT_RETENTION_DAYS),
        Err(error) => Err(BsuiteCoreError::TranscriptPathFailed(format!(
            "{RETENTION_DAYS_ENV} is invalid: {error}"
        ))),
    }
}

pub fn transcript_root_for_environment(environment: &TranscriptPathEnvironment) -> PathBuf {
    match environment.operating_system {
        TranscriptOperatingSystem::Linux => environment
            .xdg_state_home
            .clone()
            .or_else(|| {
                environment
                    .home_dir
                    .as_ref()
                    .map(|home| home.join(".local/state"))
            })
            .unwrap_or_else(|| PathBuf::from(".local/state"))
            .join("bsuite")
            .join("transcripts"),
        TranscriptOperatingSystem::Macos => environment
            .home_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(""))
            .join("Library/Application Support")
            .join("bsuite")
            .join("transcripts"),
        TranscriptOperatingSystem::Windows => environment
            .local_app_data
            .clone()
            .unwrap_or_else(|| PathBuf::from("AppData/Local"))
            .join("bsuite")
            .join("transcripts"),
        TranscriptOperatingSystem::Other => PathBuf::from("bsuite").join("transcripts"),
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn current_operating_system() -> TranscriptOperatingSystem {
    if cfg!(target_os = "linux") {
        TranscriptOperatingSystem::Linux
    } else if cfg!(target_os = "macos") {
        TranscriptOperatingSystem::Macos
    } else if cfg!(target_os = "windows") {
        TranscriptOperatingSystem::Windows
    } else {
        TranscriptOperatingSystem::Other
    }
}

fn write_record_atomically(
    record: &TranscriptRecord,
    final_path: &Path,
) -> Result<(), BsuiteCoreError> {
    let payload = serialize_record(record)?;
    let tmp_path = final_path.with_extension("jsonl.tmp");
    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(write_error)?;
    let write_result = tmp
        .write_all(payload.as_bytes())
        .and_then(|()| tmp.sync_all())
        .and_then(|()| drop_file(tmp));
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(write_error(error));
    }
    match fs::rename(&tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&tmp_path);
            Err(write_error(error))
        }
    }
}

fn serialize_record(record: &TranscriptRecord) -> Result<String, BsuiteCoreError> {
    serde_json::to_string(record)
        .map(|line| format!("{line}\n"))
        .map_err(|error| BsuiteCoreError::TranscriptSerializationFailed(error.to_string()))
}

fn drop_file(file: File) -> std::io::Result<()> {
    drop(file);
    Ok(())
}

fn verify_record(path: &Path, expected: &TranscriptRecord) -> Result<(), BsuiteCoreError> {
    let content = fs::read_to_string(path).map_err(write_error)?;
    let mut lines = content.lines();
    let Some(line) = lines.next() else {
        return Err(BsuiteCoreError::TranscriptWriteFailed(
            "transcript file is empty after append".to_string(),
        ));
    };
    if lines.next().is_some() || !content.ends_with('\n') {
        return Err(BsuiteCoreError::TranscriptWriteFailed(
            "transcript file does not contain exactly one JSON line".to_string(),
        ));
    }
    let actual: TranscriptRecord = serde_json::from_str(line)
        .map_err(|error| BsuiteCoreError::TranscriptSerializationFailed(error.to_string()))?;
    if &actual == expected {
        Ok(())
    } else {
        Err(BsuiteCoreError::TranscriptWriteFailed(
            "transcript file content differs from submitted record".to_string(),
        ))
    }
}

fn rewrite_daily_manifest(
    directory: &Path,
    timestamp: DateTime<Utc>,
    lock: &Mutex<()>,
) -> Result<(), BsuiteCoreError> {
    let _guard = lock.lock().map_err(|_| {
        BsuiteCoreError::TranscriptManifestFailed("manifest lock failed".to_string())
    })?;
    let manifest_path = directory.join(format!("manifest-{}.txt", timestamp.format("%Y-%m-%d")));
    let tmp_path = directory.join(MANIFEST_TMP_NAME);
    let content = todays_transcript_hashes(directory, timestamp)?
        .into_iter()
        .map(|(file, hash)| format!("{file} {hash}\n"))
        .collect::<String>();
    let mut tmp = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(manifest_error)?;
    let write_result = tmp
        .write_all(content.as_bytes())
        .and_then(|()| tmp.sync_all())
        .and_then(|()| drop_file(tmp));
    if let Err(error) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(manifest_error(error));
    }
    fs::rename(&tmp_path, manifest_path).map_err(manifest_error)
}

fn todays_transcript_hashes(
    directory: &Path,
    timestamp: DateTime<Utc>,
) -> Result<BTreeMap<String, String>, BsuiteCoreError> {
    let day = timestamp.date_naive();
    let mut entries = BTreeMap::new();
    for entry in fs::read_dir(directory).map_err(manifest_error)? {
        let entry = entry.map_err(manifest_error)?;
        let path = entry.path();
        if !is_transcript_file(&path) || !is_ulid_from_day(&path, day) {
            continue;
        }
        entries.insert(file_name(&path)?, sha256_file(&path)?);
    }
    Ok(entries)
}

fn sweep_retention(directory: &Path, retention_days: u32) -> Result<(), BsuiteCoreError> {
    if !directory.exists() {
        return Ok(());
    }
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(
            u64::from(retention_days) * 24 * 60 * 60,
        ))
        .ok_or_else(|| {
            BsuiteCoreError::TranscriptWriteFailed(
                "retention cutoff calculation failed".to_string(),
            )
        })?;
    for entry in fs::read_dir(directory).map_err(write_error)? {
        let entry = entry.map_err(write_error)?;
        let path = entry.path();
        if !is_transcript_file(&path) || !is_older_than(&path, cutoff) {
            continue;
        }
        fs::remove_file(path).map_err(write_error)?;
    }
    Ok(())
}

fn is_transcript_file(path: &Path) -> bool {
    path.extension() == Some(OsStr::new("jsonl")) && ulid_from_path(path).is_some()
}

fn is_older_than(path: &Path, cutoff: SystemTime) -> bool {
    ulid_from_path(path)
        .map(|ulid| ulid.datetime() < cutoff)
        .unwrap_or(false)
}

fn is_ulid_from_day(path: &Path, day: chrono::NaiveDate) -> bool {
    ulid_from_path(path)
        .map(|ulid| DateTime::<Utc>::from(ulid.datetime()).date_naive() == day)
        .unwrap_or(false)
}

fn ulid_from_path(path: &Path) -> Option<Ulid> {
    path.file_stem()
        .and_then(OsStr::to_str)
        .and_then(|name| Ulid::from_string(name).ok())
}

fn file_name(path: &Path) -> Result<String, BsuiteCoreError> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            BsuiteCoreError::TranscriptManifestFailed(format!(
                "transcript file has no UTF-8 name: {}",
                path.display()
            ))
        })
}

fn sha256_file(path: &Path) -> Result<String, BsuiteCoreError> {
    let mut file = File::open(path).map_err(manifest_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes = file.read(&mut buffer).map_err(manifest_error)?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn path_error(error: std::io::Error) -> BsuiteCoreError {
    BsuiteCoreError::TranscriptPathFailed(error.to_string())
}

fn write_error(error: std::io::Error) -> BsuiteCoreError {
    BsuiteCoreError::TranscriptWriteFailed(error.to_string())
}

fn manifest_error(error: std::io::Error) -> BsuiteCoreError {
    BsuiteCoreError::TranscriptManifestFailed(error.to_string())
}
