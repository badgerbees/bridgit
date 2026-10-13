use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::info;

mod exporter;
mod interceptor;
mod queue;
mod snapshot_provider;

#[derive(Debug, Parser)]
#[command(name = "bridgit-daemon", about = "Read-only Bridgit edge runtime")]
struct Args {
    /// Driver specification consumed by the runtime.
    #[arg(short, long, alias = "config")]
    driver: PathBuf,
    /// Durable local queue directory. Defaults to an isolated directory derived from the driver.
    #[arg(long)]
    queue_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DriverDocument {
    interceptor: interceptor::InterceptorConfig,
    schema: serde_yaml::Value,
    exporter: ExporterConfig,
}

#[derive(Debug, Deserialize)]
struct ExporterConfig {
    endpoint: String,
    #[serde(default = "default_retries")]
    max_retries: u32,
    #[serde(default = "default_backoff")]
    retry_backoff_ms: u64,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

fn default_retries() -> u32 {
    3
}

fn default_backoff() -> u64 {
    250
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let contents = std::fs::read_to_string(&args.driver)?;
    let mut driver: DriverDocument =
        serde_yaml::from_str(&contents).context("parsing driver YAML")?;
    let queue_dir = args
        .queue_dir
        .unwrap_or_else(|| default_queue_dir(&args.driver));
    ensure_checkpoint_namespace(&mut driver, &args.driver);
    let public_driver = interceptor::DriverDocument {
        interceptor: driver.interceptor,
        schema: driver.schema,
    };
    let exporter = exporter::WebhookExporter::new(
        driver.exporter.endpoint,
        driver.exporter.headers,
        driver.exporter.max_retries,
        driver.exporter.retry_backoff_ms,
    )?;
    let queue = Arc::new(queue::DurableQueue::open(&queue_dir)?);
    write_runtime_status(&queue_dir, &args.driver, "running", None)?;
    append_runtime_log(
        &queue_dir,
        &format!("driver started: {}", args.driver.display()),
    )?;
    let dispatcher_queue = Arc::clone(&queue);
    let dispatcher_exporter = Arc::new(exporter);
    let dispatcher_log_dir = queue_dir.clone();
    thread::spawn(move || loop {
        match dispatcher_queue.claim_pending(16) {
            Ok(records) => {
                for record in records {
                    let result = dispatcher_exporter.send(&record.id, &record.payload);
                    match result {
                        Ok(()) => {
                            if let Err(error) = dispatcher_queue.ack(&record.id) {
                                tracing::error!(record_id = %record.id, %error, "failed to acknowledge delivered record");
                            }
                        }
                        Err(error) => {
                            let _ = append_runtime_log(
                                &dispatcher_log_dir,
                                &format!("delivery failed for {}: {error}", record.id),
                            );
                            if let Err(nack_error) =
                                dispatcher_queue.nack(&record.id, error.to_string())
                            {
                                tracing::error!(record_id = %record.id, %nack_error, "failed to persist webhook failure");
                            }
                        }
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, "queue dispatcher poll failed");
                let _ = append_runtime_log(&dispatcher_log_dir, &format!("queue error: {error}"));
            }
        }
        thread::sleep(Duration::from_millis(500));
    });

    info!(driver = %args.driver.display(), queue = %queue_dir.display(), "loaded Bridgit driver specification");
    info!(driver = %args.driver.display(), "runtime is ready");
    let result = match &public_driver.interceptor {
        interceptor::InterceptorConfig::FileWatcher { .. } => {
            let mut watcher = interceptor::FileWatcher::new(&public_driver);
            watcher.run(|record| enqueue_record(&queue, record))
        }
        interceptor::InterceptorConfig::Sqlite { .. } => {
            let mut watcher = interceptor::SqliteWatcher::new(&public_driver)?;
            watcher.run(|record| enqueue_record(&queue, record))
        }
    };
    match &result {
        Ok(()) => {
            let _ = write_runtime_status(&queue_dir, &args.driver, "stopped", None);
        }
        Err(error) => {
            let _ =
                write_runtime_status(&queue_dir, &args.driver, "error", Some(&error.to_string()));
            let _ = append_runtime_log(&queue_dir, &format!("runtime error: {error}"));
        }
    }
    result
}

fn write_runtime_status(
    queue_dir: &std::path::Path,
    driver_path: &std::path::Path,
    state: &str,
    error: Option<&str>,
) -> Result<()> {
    fs::create_dir_all(queue_dir)?;
    let status = serde_json::json!({
        "driver": driver_path.canonicalize().unwrap_or_else(|_| driver_path.to_path_buf()),
        "queue_dir": queue_dir,
        "state": state,
        "pid": std::process::id(),
        "updated_at": unix_timestamp(),
        "error": error,
    });
    let temporary = queue_dir.join("status.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(&status)?)?;
    fs::rename(temporary, queue_dir.join("status.json"))?;
    Ok(())
}

fn append_runtime_log(queue_dir: &std::path::Path, message: &str) -> Result<()> {
    fs::create_dir_all(queue_dir)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(queue_dir.join("runtime.log"))?;
    writeln!(file, "{} {message}", unix_timestamp())?;
    Ok(())
}

fn unix_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_queue_dir(driver_path: &std::path::Path) -> PathBuf {
    let stem = driver_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("driver");
    let mut hasher = DefaultHasher::new();
    driver_path
        .to_string_lossy()
        .to_lowercase()
        .hash(&mut hasher);
    PathBuf::from("storage/queues").join(format!(
        "{}-{suffix:016x}",
        slugify(stem),
        suffix = hasher.finish()
    ))
}

fn ensure_checkpoint_namespace(driver: &mut DriverDocument, driver_path: &std::path::Path) {
    let interceptor::InterceptorConfig::Sqlite {
        path,
        checkpoint_path,
        ..
    } = &mut driver.interceptor
    else {
        return;
    };
    if checkpoint_path
        .as_deref()
        .is_some_and(|value| value != "storage/checkpoints/sqlite.json")
    {
        return;
    }
    let source = std::path::Path::new(path)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("database");
    let table = driver
        .schema
        .get("table")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or("records");
    let mut hasher = DefaultHasher::new();
    path.to_lowercase().hash(&mut hasher);
    table.to_lowercase().hash(&mut hasher);
    driver_path
        .to_string_lossy()
        .to_lowercase()
        .hash(&mut hasher);
    *checkpoint_path = Some(format!(
        "storage/checkpoints/{}-{}-{suffix:016x}.json",
        slugify(source),
        slugify(table),
        suffix = hasher.finish()
    ));
}

fn slugify(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            result.push(character.to_ascii_lowercase());
        } else if !result.ends_with('-') {
            result.push('-');
        }
    }
    result.trim_matches('-').to_owned()
}

fn enqueue_record(queue: &queue::DurableQueue, record: interceptor::ParsedRecord) -> Result<()> {
    let payload = serde_json::to_value(&record).context("serializing parsed record")?;
    queue
        .enqueue(record.source, payload)
        .map(|_| ())
        .context("durably enqueueing parsed record")
}
