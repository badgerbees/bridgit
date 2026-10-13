use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueueStatus {
    Pending,
    InFlight,
    Acknowledged,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedRecord {
    pub id: String,
    pub source_file: String,
    pub payload: Value,
    pub status: QueueStatus,
    pub attempts: u32,
    pub created_at: u64,
    #[serde(default)]
    pub next_attempt_at: u64,
    #[serde(default)]
    pub last_error: Option<String>,
}

pub struct DurableQueue {
    root: PathBuf,
    pending: PathBuf,
    inflight: PathBuf,
    ack: PathBuf,
}

impl DurableQueue {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let queue = Self {
            pending: root.join("pending"),
            inflight: root.join("inflight"),
            ack: root.join("ack"),
            root,
        };
        queue.create_dirs()?;
        queue.recover()?;
        queue.purge_acknowledged_older_than(Duration::from_secs(7 * 24 * 60 * 60))?;
        Ok(queue)
    }

    fn create_dirs(&self) -> Result<()> {
        for path in [&self.root, &self.pending, &self.inflight, &self.ack] {
            fs::create_dir_all(path)
                .with_context(|| format!("creating queue directory {}", path.display()))?;
        }
        Ok(())
    }

    pub fn enqueue(&self, source_file: impl Into<String>, payload: Value) -> Result<QueuedRecord> {
        let now = unix_seconds();
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let id = format!(
            "{}-{}-{:04}",
            millis,
            std::process::id(),
            ID_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let record = QueuedRecord {
            id: id.clone(),
            source_file: source_file.into(),
            payload,
            status: QueueStatus::Pending,
            attempts: 0,
            created_at: now,
            next_attempt_at: now,
            last_error: None,
        };
        atomic_write(&self.pending.join(format!("{id}.json")), &record)?;
        Ok(record)
    }

    pub fn claim_pending(&self, limit: usize) -> Result<Vec<QueuedRecord>> {
        let mut claimed = Vec::new();
        let now = unix_seconds();
        for entry in fs::read_dir(&self.pending)? {
            if claimed.len() >= limit {
                break;
            }
            let source = entry?.path();
            if source.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let mut record: QueuedRecord = read_json(&source)?;
            if !matches!(record.status, QueueStatus::Pending | QueueStatus::Failed)
                || record.next_attempt_at > now
            {
                continue;
            }
            let destination = self.inflight.join(source.file_name().unwrap());
            if fs::rename(&source, &destination).is_err() {
                continue;
            }
            record.status = QueueStatus::InFlight;
            atomic_write(&destination, &record)?;
            claimed.push(record);
        }
        Ok(claimed)
    }

    pub fn ack(&self, id: &str) -> Result<()> {
        let source = self.inflight.join(format!("{id}.json"));
        let destination = self.ack.join(format!("{id}.json"));
        if destination.exists() {
            if source.exists() {
                fs::remove_file(source)?;
            }
            return Ok(());
        }
        let mut record: QueuedRecord = read_json(&source)?;
        record.status = QueueStatus::Acknowledged;
        atomic_write(&source, &record)?;
        fs::rename(source, destination).context("moving acknowledged queue record")?;
        Ok(())
    }

    pub fn nack(&self, id: &str, error: impl Into<String>) -> Result<()> {
        let source = self.inflight.join(format!("{id}.json"));
        let destination = self.pending.join(format!("{id}.json"));
        let mut record: QueuedRecord = read_json(&source)?;
        record.status = QueueStatus::Failed;
        record.attempts = record.attempts.saturating_add(1);
        record.last_error = Some(error.into());
        let delay = 2u64
            .saturating_pow(record.attempts.min(8))
            .saturating_mul(1);
        record.next_attempt_at = unix_seconds().saturating_add(delay.min(300));
        atomic_write(&source, &record)?;
        fs::rename(source, destination).context("returning failed queue record")?;
        Ok(())
    }

    pub fn recover(&self) -> Result<usize> {
        self.create_dirs()?;
        let mut recovered = 0;
        for entry in fs::read_dir(&self.inflight)? {
            let source = entry?.path();
            if source.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let mut record: QueuedRecord = read_json(&source)?;
            let file_name = source.file_name().unwrap();
            let destination = if record.status == QueueStatus::Acknowledged {
                self.ack.join(file_name)
            } else {
                record.status = QueueStatus::Pending;
                record.next_attempt_at = unix_seconds();
                record.last_error = Some("recovered after daemon restart".into());
                self.pending.join(file_name)
            };
            if destination.exists() {
                fs::remove_file(source)?;
            } else {
                if record.status == QueueStatus::Acknowledged {
                    fs::rename(&source, &destination)?;
                } else {
                    atomic_write(&destination, &record)?;
                    fs::remove_file(&source)?;
                }
            }
            recovered += 1;
        }
        Ok(recovered)
    }

    pub fn purge_acknowledged_older_than(&self, age: Duration) -> Result<usize> {
        let cutoff = SystemTime::now().checked_sub(age).unwrap_or(UNIX_EPOCH);
        let mut purged = 0;
        for entry in fs::read_dir(&self.ack)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            if fs::metadata(&path)?.modified().unwrap_or(SystemTime::now()) < cutoff {
                fs::remove_file(path)?;
                purged += 1;
            }
        }
        Ok(purged)
    }

    #[cfg(test)]
    fn path_for(&self, folder: &str, id: &str) -> PathBuf {
        self.root.join(folder).join(format!("{id}.json"))
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading queue record {}", path.display()))?;
    serde_json::from_str(&text).context("parsing queue record")
}

fn atomic_write<T: Serialize>(destination: &Path, value: &T) -> Result<()> {
    let temporary = destination.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, destination)
        .with_context(|| format!("committing queue record {}", destination.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_root(name: &str) -> PathBuf {
        std::env::current_dir()
            .unwrap()
            .join("storage")
            .join(format!(
                "test-{name}-{}",
                ID_COUNTER.fetch_add(1, Ordering::Relaxed)
            ))
    }

    #[test]
    fn enqueue_claim_ack_round_trip() {
        let root = test_root("round-trip");
        let queue = DurableQueue::open(&root).unwrap();
        let record = queue.enqueue("sample.dat", json!({"value": 42})).unwrap();
        assert!(queue.path_for("pending", &record.id).exists());
        let claimed = queue.claim_pending(1).unwrap();
        assert_eq!(claimed.len(), 1);
        queue.ack(&record.id).unwrap();
        assert!(queue.path_for("ack", &record.id).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_returns_inflight_to_pending() {
        let root = test_root("recovery");
        let queue = DurableQueue::open(&root).unwrap();
        let record = queue.enqueue("sample.dat", json!({"value": 1})).unwrap();
        assert_eq!(queue.claim_pending(1).unwrap().len(), 1);
        drop(queue);
        let recovered = DurableQueue::open(&root).unwrap();
        assert!(recovered.path_for("pending", &record.id).exists());
        assert_eq!(recovered.claim_pending(1).unwrap().len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nack_increases_attempts_and_keeps_record_retryable() {
        let root = test_root("nack");
        let queue = DurableQueue::open(&root).unwrap();
        let record = queue.enqueue("sample.dat", json!({"value": 7})).unwrap();
        queue.claim_pending(1).unwrap();
        queue.nack(&record.id, "endpoint unavailable").unwrap();
        let stored: QueuedRecord = read_json(&queue.path_for("pending", &record.id)).unwrap();
        assert_eq!(stored.status, QueueStatus::Failed);
        assert_eq!(stored.attempts, 1);
        assert!(stored.next_attempt_at > unix_seconds());
        fs::remove_dir_all(root).unwrap();
    }
}
