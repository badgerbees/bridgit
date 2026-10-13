use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub enum Provider {
    Auto,
    Vss,
    Sidecar,
}

impl Provider {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("auto").to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "vss" => Ok(Self::Vss),
            "sidecar" | "copy" => Ok(Self::Sidecar),
            other => {
                bail!("unsupported SQLite snapshot provider {other}; use auto, vss, or sidecar")
            }
        }
    }
}

pub struct Snapshot {
    pub database_path: PathBuf,
    cleanup_paths: Vec<PathBuf>,
    #[cfg(windows)]
    shadow_id: Option<String>,
}

impl Snapshot {
    pub fn cleanup(self) {
        drop(self);
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        for path in &self.cleanup_paths {
            let _ = fs::remove_file(path);
        }
        #[cfg(windows)]
        if let Some(shadow_id) = &self.shadow_id {
            let _ = Command::new("vssadmin")
                .args([
                    "delete",
                    "shadows",
                    &format!("/shadow={shadow_id}"),
                    "/quiet",
                ])
                .output();
        }
    }
}

pub fn create(source: &Path, directory: &Path, provider: Provider) -> Result<Snapshot> {
    match provider {
        Provider::Sidecar => sidecar(source, directory),
        Provider::Vss => vss(source),
        Provider::Auto => {
            #[cfg(windows)]
            {
                match vss(source) {
                    Ok(snapshot) => Ok(snapshot),
                    Err(vss_error) => sidecar(source, directory).with_context(|| {
                        format!("VSS unavailable ({vss_error}); sidecar snapshot also failed")
                    }),
                }
            }
            #[cfg(not(windows))]
            {
                sidecar(source, directory)
            }
        }
    }
}

fn sidecar(source: &Path, directory: &Path) -> Result<Snapshot> {
    fs::create_dir_all(directory)
        .with_context(|| format!("creating snapshot directory {}", directory.display()))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let name = source
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("SQLite source has no file name"))?;
    let snapshot = directory.join(format!("{name}.{stamp}.snapshot"));
    fs::copy(source, &snapshot).with_context(|| {
        format!(
            "copying SQLite source {} to snapshot {}",
            source.display(),
            snapshot.display()
        )
    })?;
    let mut cleanup_paths = vec![snapshot.clone()];
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", source.display(), suffix));
        if sidecar.is_file() {
            let snapshot_sidecar = PathBuf::from(format!("{}{}", snapshot.display(), suffix));
            fs::copy(&sidecar, &snapshot_sidecar)
                .with_context(|| format!("copying SQLite sidecar {}", sidecar.display()))?;
            cleanup_paths.push(snapshot_sidecar);
        }
    }
    Ok(Snapshot {
        database_path: snapshot,
        cleanup_paths,
        #[cfg(windows)]
        shadow_id: None,
    })
}

#[cfg(windows)]
fn vss(source: &Path) -> Result<Snapshot> {
    let source_text = source
        .canonicalize()
        .with_context(|| format!("resolving SQLite source {}", source.display()))?
        .to_string_lossy()
        .replace('/', "\\");
    let volume = source_text
        .get(..3)
        .filter(|prefix| prefix.ends_with("\\"))
        .ok_or_else(|| anyhow!("VSS requires a local drive path, got {source_text}"))?;
    let relative = source_text[3..].trim_start_matches('\\');
    let output = Command::new("vssadmin")
        .args(["create", "shadow", &format!("/for={volume}")])
        .output()
        .context("starting vssadmin; VSS may require administrator privileges")?;
    if !output.status.success() {
        bail!(
            "vssadmin create shadow failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let shadow_volume = find_value(&text, "Shadow Copy Volume:")
        .ok_or_else(|| anyhow!("vssadmin output did not contain a shadow volume"))?;
    let shadow_id = find_value(&text, "Shadow Copy ID:")
        .ok_or_else(|| anyhow!("vssadmin output did not contain a shadow ID"))?;
    Ok(Snapshot {
        database_path: PathBuf::from(format!(
            "{}\\{}",
            shadow_volume.trim_end_matches('\\'),
            relative
        )),
        cleanup_paths: Vec::new(),
        shadow_id: Some(shadow_id),
    })
}

#[cfg(windows)]
fn find_value(text: &str, label: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .find(&label.to_ascii_lowercase())
            .map(|index| line[index + label.len()..].trim().to_owned())
    })
}

#[cfg(not(windows))]
fn vss(_source: &Path) -> Result<Snapshot> {
    bail!("VSS snapshots are only supported on Windows")
}
