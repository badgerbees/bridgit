use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, types::ValueRef, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::snapshot_provider::{self, Provider};

#[derive(Debug, Deserialize)]
pub struct DriverDocument {
    pub interceptor: InterceptorConfig,
    pub schema: serde_yaml::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptorConfig {
    FileWatcher {
        path: String,
        #[serde(default = "default_poll_interval")]
        poll_interval_ms: u64,
        #[serde(default = "default_stability")]
        stability_ms: u64,
    },
    #[serde(rename = "sqlite", alias = "sqlite_snapshot")]
    Sqlite {
        path: String,
        #[serde(default)]
        table: Option<String>,
        #[serde(default)]
        query: Option<String>,
        #[serde(default)]
        primary_key: Option<String>,
        #[serde(default = "default_poll_interval")]
        poll_interval_ms: u64,
        #[serde(default)]
        read_only: bool,
        #[serde(default)]
        snapshot_dir: Option<String>,
        #[serde(default)]
        snapshot_interval_ms: Option<u64>,
        #[serde(default)]
        snapshot_provider: Option<String>,
        #[serde(default)]
        checkpoint_path: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldSpec {
    pub offset: usize,
    pub length: Option<usize>,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: Option<String>,
    pub endian: Option<String>,
    pub trim: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedRecord {
    pub source: String,
    pub fields: Map<String, Value>,
}

fn default_poll_interval() -> u64 {
    500
}
fn default_stability() -> u64 {
    250
}

pub fn load_driver(path: &Path) -> Result<DriverDocument> {
    let text =
        fs::read_to_string(path).with_context(|| format!("reading driver {}", path.display()))?;
    serde_yaml::from_str(&text).context("parsing driver YAML")
}

fn binary_schema(value: &serde_yaml::Value) -> Result<BTreeMap<String, FieldSpec>> {
    serde_yaml::from_value(value.clone()).context("parsing binary schema")
}

pub fn parse_record(
    path: &Path,
    bytes: &[u8],
    schema: &BTreeMap<String, FieldSpec>,
) -> Result<ParsedRecord> {
    let mut fields = Map::new();
    for (name, spec) in schema {
        let length = spec.length.unwrap_or(match spec.kind.as_str() {
            "float32" => 4,
            "int16" => 2,
            _ => 0,
        });
        let slice = bytes
            .get(spec.offset..spec.offset + length)
            .ok_or_else(|| anyhow!("field {name} is out of bounds"))?;
        if spec.kind == "hex" && spec.value.is_some() {
            let expected = spec.value.as_ref().unwrap().to_ascii_lowercase();
            let actual = hex::encode(slice);
            if actual != expected {
                bail!("field {name} failed magic validation: {actual} != {expected}");
            }
            fields.insert(name.clone(), Value::String(actual));
            continue;
        }
        let value = match spec.kind.as_str() {
            "string" => {
                let mut text = String::from_utf8_lossy(slice).to_string();
                if spec.trim.unwrap_or(false) {
                    text = text.trim_matches(char::from(0)).trim().to_string();
                }
                Value::String(text)
            }
            "float32" if slice.len() == 4 => {
                Value::from(f32::from_le_bytes(slice.try_into().unwrap()))
            }
            "int16" if slice.len() == 2 => {
                Value::from(i16::from_le_bytes(slice.try_into().unwrap()))
            }
            "hex" => Value::String(hex::encode(slice)),
            other => bail!("unsupported field type {other} for {name}"),
        };
        fields.insert(name.clone(), value);
    }
    Ok(ParsedRecord {
        source: path.display().to_string(),
        fields,
    })
}

pub struct FileWatcher {
    path: String,
    poll_interval_ms: u64,
    stability_ms: u64,
    schema: BTreeMap<String, FieldSpec>,
    seen: HashSet<PathBuf>,
}

impl FileWatcher {
    pub fn new(driver: &DriverDocument) -> Self {
        let (path, poll_interval_ms, stability_ms) = match &driver.interceptor {
            InterceptorConfig::FileWatcher {
                path,
                poll_interval_ms,
                stability_ms,
            } => (path.clone(), *poll_interval_ms, *stability_ms),
            InterceptorConfig::Sqlite { .. } => panic!("FileWatcher requires file_watcher driver"),
        };
        Self {
            path,
            poll_interval_ms,
            stability_ms,
            schema: binary_schema(&driver.schema).expect("validated binary schema"),
            seen: HashSet::new(),
        }
    }

    pub fn poll_once(&mut self) -> Result<Vec<ParsedRecord>> {
        let (directory, extension) = split_pattern(&self.path)?;
        let mut records = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|x| x.to_str()) != Some(extension.as_str())
                || self.seen.contains(&path)
            {
                continue;
            }
            if !stable(&path, self.stability_ms)? {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            records.push(parse_record(&path, &bytes, &self.schema)?);
            self.seen.insert(path);
        }
        Ok(records)
    }

    pub fn run<F>(&mut self, mut on_record: F) -> Result<()>
    where
        F: FnMut(ParsedRecord) -> Result<()>,
    {
        loop {
            for record in self.poll_once()? {
                on_record(record)?;
            }
            thread::sleep(Duration::from_millis(self.poll_interval_ms));
        }
    }
}

pub struct SqliteWatcher {
    source_path: PathBuf,
    snapshot_dir: Option<PathBuf>,
    snapshot_provider: Provider,
    checkpoint_path: Option<PathBuf>,
    checkpoint: Option<String>,
    table: Option<String>,
    initial_sync: String,
    pending_checkpoint: Option<String>,
    query: String,
    primary_key: String,
    poll_interval_ms: u64,
    seen: HashSet<String>,
}

impl SqliteWatcher {
    pub fn new(driver: &DriverDocument) -> Result<Self> {
        let InterceptorConfig::Sqlite {
            path,
            query,
            primary_key,
            poll_interval_ms,
            snapshot_dir,
            snapshot_interval_ms,
            snapshot_provider: provider_name,
            checkpoint_path,
            ..
        } = &driver.interceptor
        else {
            bail!("SqliteWatcher requires sqlite driver")
        };
        let schema: serde_json::Value = serde_yaml::from_value(driver.schema.clone())?;
        let table = schema.get("table").and_then(Value::as_str);
        let query = query
            .clone()
            .or_else(|| {
                schema
                    .get("query")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| {
                table.map(|name| format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
            })
            .ok_or_else(|| anyhow!("SQLite driver requires schema.query or schema.table"))?;
        let primary_key = primary_key
            .clone()
            .or_else(|| {
                schema
                    .get("primary_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or_else(|| anyhow!("SQLite driver requires schema.primary_key"))?;
        Ok(Self {
            source_path: PathBuf::from(path),
            snapshot_dir: snapshot_dir.as_ref().map(PathBuf::from),
            snapshot_provider: Provider::parse(provider_name.as_deref())?,
            checkpoint_path: checkpoint_path.as_ref().map(PathBuf::from),
            checkpoint: checkpoint_path
                .as_ref()
                .and_then(|path| fs::read_to_string(path).ok())
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            initial_sync: schema
                .get("initial_sync")
                .and_then(Value::as_str)
                .unwrap_or("all")
                .to_owned(),
            pending_checkpoint: None,
            table: table.map(str::to_owned),
            query,
            primary_key,
            poll_interval_ms: snapshot_interval_ms.unwrap_or(*poll_interval_ms),
            seen: HashSet::new(),
        })
    }

    pub fn poll_once(&mut self) -> Result<Vec<ParsedRecord>> {
        let snapshot = self
            .snapshot_dir
            .as_ref()
            .map(|directory| {
                snapshot_provider::create(&self.source_path, directory, self.snapshot_provider)
            })
            .transpose()?;
        let database_path = snapshot
            .as_ref()
            .map(|value| value.database_path.clone())
            .unwrap_or_else(|| self.source_path.clone());
        let connection =
            Connection::open_with_flags(&database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .with_context(|| {
                    format!(
                        "opening SQLite database {} read-only",
                        database_path.display()
                    )
                })?;
        if let Some(table) = self.table.clone() {
            self.bootstrap_checkpoint(&connection, &table)?;
        }
        let mut statement = connection
            .prepare(&self.effective_query()?)
            .context("preparing SQLite query")?;
        let names: Vec<String> = statement
            .column_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        if !names.iter().any(|name| name == &self.primary_key) {
            bail!(
                "SQLite query does not return primary key {}",
                self.primary_key
            );
        }
        let mut rows = statement.query(params![])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            let mut fields = Map::new();
            for (index, name) in names.iter().enumerate() {
                fields.insert(name.clone(), sqlite_value(row.get_ref(index)?));
            }
            let key = fields
                .get(&self.primary_key)
                .map(|value| value.to_string())
                .unwrap_or_default();
            let fingerprint = format!("{}:{}", key, serde_json::to_string(&fields)?);
            if self.seen.insert(fingerprint) {
                if let Some(value) = fields.get(&self.primary_key) {
                    self.pending_checkpoint = Some(sqlite_checkpoint_value(value));
                }
                records.push(ParsedRecord {
                    source: self.source_path.display().to_string(),
                    fields,
                });
            }
        }
        drop(rows);
        drop(statement);
        drop(connection);
        if let Some(snapshot) = snapshot {
            snapshot.cleanup();
        }
        Ok(records)
    }

    fn effective_query(&self) -> Result<String> {
        let Some(checkpoint) = &self.checkpoint else {
            return Ok(if self.initial_sync == "tail" {
                // The first tail run is initialized by bootstrap_checkpoint.
                String::from("SELECT * FROM (SELECT 1) WHERE 0")
            } else {
                self.query.clone()
            });
        };
        if !self.query.contains(":last_id") {
            return Ok(self.query.clone());
        }
        let escaped = checkpoint.replace('\'', "''");
        if checkpoint.parse::<i64>().is_ok() {
            Ok(self.query.replace(":last_id", checkpoint))
        } else {
            Ok(self.query.replace(":last_id", &format!("'{escaped}'")))
        }
    }

    fn bootstrap_checkpoint(&mut self, connection: &Connection, table: &str) -> Result<()> {
        if self.initial_sync != "tail" || self.checkpoint.is_some() {
            return Ok(());
        }
        let query = format!(
            "SELECT MAX(\"{}\") FROM \"{}\"",
            self.primary_key.replace('"', "\"\""),
            table.replace('"', "\"\"")
        );
        let value: Option<String> = connection.query_row(&query, [], |row| {
            let value = row.get_ref(0)?;
            Ok(match value {
                rusqlite::types::ValueRef::Null => None,
                rusqlite::types::ValueRef::Integer(value) => Some(value.to_string()),
                rusqlite::types::ValueRef::Real(value) => Some(value.to_string()),
                rusqlite::types::ValueRef::Text(value) => {
                    Some(String::from_utf8_lossy(value).into_owned())
                }
                rusqlite::types::ValueRef::Blob(value) => Some(hex::encode(value)),
            })
        })?;
        self.checkpoint = value;
        self.persist_checkpoint()?;
        Ok(())
    }

    fn persist_checkpoint(&self) -> Result<()> {
        let (Some(path), Some(value)) = (&self.checkpoint_path, &self.checkpoint) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, format!("{value}\n"))?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn run<F>(&mut self, mut on_record: F) -> Result<()>
    where
        F: FnMut(ParsedRecord) -> Result<()>,
    {
        loop {
            for record in self.poll_once()? {
                on_record(record)?;
            }
            if let Some(value) = self.pending_checkpoint.take() {
                self.checkpoint = Some(value);
                self.persist_checkpoint()?;
            }
            thread::sleep(Duration::from_millis(self.poll_interval_ms));
        }
    }
}

fn sqlite_checkpoint_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn sqlite_value(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(number) => Value::from(number),
        ValueRef::Real(number) => Value::from(number),
        ValueRef::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => Value::String(hex::encode(bytes)),
    }
}

fn split_pattern(pattern: &str) -> Result<(PathBuf, String)> {
    let path = Path::new(pattern);
    let file = path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow!("invalid watcher path"))?;
    let extension = file
        .strip_prefix("*.")
        .ok_or_else(|| anyhow!("only *.ext watcher patterns are supported"))?;
    Ok((
        path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        extension.to_string(),
    ))
}

fn stable(path: &Path, wait_ms: u64) -> Result<bool> {
    let first = fs::metadata(path)?;
    let first_size = first.len();
    let first_modified = first.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    thread::sleep(Duration::from_millis(wait_ms));
    let second = fs::metadata(path)?;
    Ok(first_size == second.len()
        && first_modified == second.modified().unwrap_or(SystemTime::UNIX_EPOCH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mock_record_and_validates_header() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "header".into(),
            FieldSpec {
                offset: 0,
                length: Some(2),
                kind: "hex".into(),
                value: Some("4252".into()),
                endian: None,
                trim: None,
            },
        );
        schema.insert(
            "id".into(),
            FieldSpec {
                offset: 2,
                length: Some(16),
                kind: "string".into(),
                value: None,
                endian: None,
                trim: Some(true),
            },
        );
        schema.insert(
            "value".into(),
            FieldSpec {
                offset: 18,
                length: Some(4),
                kind: "float32".into(),
                value: None,
                endian: Some("little".into()),
                trim: None,
            },
        );
        schema.insert(
            "status".into(),
            FieldSpec {
                offset: 22,
                length: Some(2),
                kind: "int16".into(),
                value: None,
                endian: Some("little".into()),
                trim: None,
            },
        );
        let mut bytes = b"BRRESULT-1\0\0\0\0\0\0\0\0\0".to_vec();
        bytes.extend_from_slice(&20.5f32.to_le_bytes());
        bytes.extend_from_slice(&0i16.to_le_bytes());
        let record = parse_record(Path::new("result.dat"), &bytes, &schema).unwrap();
        assert_eq!(record.fields["header"], "4252");
        assert_eq!(record.fields["id"], "RESULT-1");
        assert_eq!(record.fields["status"], 0);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut schema = BTreeMap::new();
        schema.insert(
            "header".into(),
            FieldSpec {
                offset: 0,
                length: Some(2),
                kind: "hex".into(),
                value: Some("4252".into()),
                endian: None,
                trim: None,
            },
        );
        let error = parse_record(Path::new("bad.dat"), b"NO", &schema).unwrap_err();
        assert!(error.to_string().contains("magic validation"));
    }
}
