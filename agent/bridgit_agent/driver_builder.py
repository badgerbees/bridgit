"""Build and validate Rust-compatible Bridgit driver specifications."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

import yaml

from .binary_parser import BinaryStructSpec, parse_binary_evidence


FIELD_TYPES = {"hex", "string", "float32", "int16", "int32", "uint16", "uint32"}
REQUIRED_TOP_LEVEL = {"metadata", "interceptor", "schema", "exporter"}


def _parse_mapping_argument(value: str) -> dict[str, Any]:
    """Parse CLI metadata from JSON, with a friendly YAML fallback for shells."""

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        # YAML also accepts JSON and handles values rewritten by some
        # PowerShell invocation paths, such as {name: GnuCash}.
        parsed = yaml.safe_load(value)
    if not isinstance(parsed, dict):
        raise ValueError("target metadata must be a mapping/object")
    return parsed


def _integer(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not an offset")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"expected integer, got {type(value).__name__}")


def validate_driver(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = REQUIRED_TOP_LEVEL - set(document)
    errors.extend(f"missing top-level key: {key}" for key in sorted(missing))
    if not isinstance(document.get("metadata"), dict):
        errors.append("metadata must be a mapping")
    interceptor = document.get("interceptor")
    if not isinstance(interceptor, dict) or interceptor.get("type") not in {"file_watcher", "sqlite", "sqlite_snapshot"} or not interceptor.get("path"):
        errors.append("interceptor must define type=file_watcher, sqlite, or sqlite_snapshot and path")
    schema = document.get("schema")
    if interceptor.get("type") in {"sqlite", "sqlite_snapshot"}:
        if not isinstance(schema, dict) or not schema.get("table") or not schema.get("columns"):
            errors.append("SQLite schema must define table and non-empty columns")
        if not schema.get("primary_key"):
            errors.append("SQLite schema must define primary_key")
    elif not isinstance(schema, dict) or not schema:
        errors.append("schema must be a non-empty mapping")
    elif interceptor.get("type") == "file_watcher":
        for name, spec in schema.items():
            if not isinstance(spec, dict):
                errors.append(f"schema.{name} must be a mapping")
                continue
            try:
                offset = _integer(spec.get("offset"))
                if offset < 0:
                    errors.append(f"schema.{name}.offset must be non-negative")
            except (TypeError, ValueError) as exc:
                errors.append(f"schema.{name}.offset is invalid: {exc}")
            if spec.get("type") not in FIELD_TYPES:
                errors.append(f"schema.{name}.type must be one of {sorted(FIELD_TYPES)}")
            if "length" in spec:
                try:
                    if _integer(spec["length"]) <= 0:
                        errors.append(f"schema.{name}.length must be positive")
                except (TypeError, ValueError) as exc:
                    errors.append(f"schema.{name}.length is invalid: {exc}")
    exporter = document.get("exporter")
    if not isinstance(exporter, dict) or exporter.get("type") != "webhook" or not exporter.get("endpoint"):
        errors.append("exporter must define type=webhook and endpoint")
    return errors


def infer_binary_schema(sample_path: str | Path) -> dict[str, dict[str, Any]]:
    """Infer the Module 2 mock layout when a BR sample is supplied."""

    path = Path(sample_path)
    data = path.read_bytes()
    if data[:2] != b"BR":
        raise ValueError("sample does not begin with BR magic")
    if len(data) < 24:
        raise ValueError("sample is shorter than the expected BR record")
    return {
        "header": {"offset": 0, "length": 2, "type": "hex", "value": data[:2].hex()},
        "record_id": {"offset": 2, "length": 16, "type": "string", "encoding": "ascii", "trim": True},
        "value": {"offset": 18, "length": 4, "type": "float32", "endian": "little"},
        "status_code": {"offset": 22, "length": 2, "type": "int16", "endian": "little"},
    }


def _sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def infer_sqlite_schema(sample_path: str | Path) -> dict[str, Any]:
    """Discover a useful read-only profile without assuming a vendor schema."""

    path = Path(sample_path).resolve()
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
        try:
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )]
            if not tables:
                raise ValueError("SQLite database contains no application tables")
            preferred = ("transactions", "transaction", "results", "measurements", "entries", "splits")
            table = next((name for name in preferred if name in tables), tables[0])
            columns = list(connection.execute(f"PRAGMA table_info({_sqlite_identifier(table)})"))
            if not columns:
                raise ValueError(f"SQLite table {table!r} has no columns")
            primary = next((row[1] for row in columns if row[5]), None) or columns[0][1]
            names = [row[1] for row in columns]
        finally:
            connection.close()
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower() or "busy" in str(exc).lower():
            raise ValueError(
                "SQLite database is locked; provide a readable sample or an explicit schema_spec "
                "so the generated driver can use sqlite_snapshot"
            ) from exc
        raise ValueError(f"cannot inspect SQLite database {path}: {exc}") from exc
    except sqlite3.Error as exc:
        raise ValueError(f"cannot inspect SQLite database {path}: {exc}") from exc
    table_sql = _sqlite_identifier(table)
    initial_sync = "all"
    query = f"SELECT * FROM {table_sql}"
    if any(row[1] == primary and str(row[2]).upper().startswith(("INT", "NUM")) for row in columns):
        query = f"SELECT * FROM {table_sql} WHERE {_sqlite_identifier(primary)} > :last_id ORDER BY {_sqlite_identifier(primary)}"
        initial_sync = "tail"
    return {
        "table": table,
        "columns": names,
        "primary_key": primary,
        "query": query,
        "initial_sync": initial_sync,
        "deduplication": {"key": primary, "mode": "row_hash"},
    }


def _is_sqlite(sample_path: str | Path) -> bool:
    path = Path(sample_path)
    try:
        return path.read_bytes()[:16] == b"SQLite format 3\x00" or path.suffix.lower() in {".sqlite", ".db", ".gnucash"}
    except OSError:
        return path.suffix.lower() in {".sqlite", ".db", ".gnucash"}


def _state_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-").lower()
    return slug or "driver"


def _default_checkpoint_path(
    target_meta: dict[str, Any],
    schema_spec: dict[str, Any],
    sample_path: str | Path | None,
) -> str:
    source = Path(sample_path or target_meta.get("path", "database")).stem
    table = str(schema_spec.get("table", "records"))
    identity = f"{target_meta.get('path', sample_path or 'database')}\0{table}".encode("utf-8")
    suffix = hashlib.sha256(identity).hexdigest()[:12]
    return f"storage/checkpoints/{_state_slug(source)}-{_state_slug(table)}-{suffix}.json"


def _sqlite_is_locked(sample_path: str | Path) -> bool:
    try:
        connection = sqlite3.connect(f"file:{Path(sample_path).resolve().as_posix()}?mode=ro", uri=True, timeout=0)
        try:
            connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
        finally:
            connection.close()
        return False
    except sqlite3.OperationalError as exc:
        return "locked" in str(exc).lower() or "busy" in str(exc).lower()


def schema_from_binary_spec(spec: BinaryStructSpec | dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Convert normalized static evidence to the driver YAML field shape."""

    if isinstance(spec, dict):
        fields = spec.get("fields", [])
    else:
        fields = [field.__dict__ for field in spec.fields]
    output: dict[str, dict[str, Any]] = {}
    for field in fields:
        name = str(field.get("name", "field"))
        item: dict[str, Any] = {
            "offset": _integer(field.get("offset")),
            "type": str(field.get("type", "hex")),
        }
        if field.get("length") is not None:
            item["length"] = _integer(field["length"])
        for key in ("endian", "encoding", "trim"):
            if field.get(key) is not None:
                item[key] = field[key]
        if field.get("value") is not None:
            item["value"] = field["value"]
        output[name] = item
    magic_values = spec.get("magic_constants", []) if isinstance(spec, dict) else spec.magic_constants
    if magic_values and "header" not in output:
        magic = str(magic_values[0]).replace(" ", "").lower()
        output["header"] = {"offset": 0, "length": len(magic) // 2, "type": "hex", "value": magic}
    return output


def _validate_sample_alignment(sample_path: str | Path, schema: dict[str, dict[str, Any]]) -> None:
    data = Path(sample_path).read_bytes()
    for name, field in schema.items():
        offset = _integer(field.get("offset"))
        length = _integer(field.get("length", {"float32": 4, "int16": 2, "uint16": 2, "int32": 4, "uint32": 4}.get(field.get("type"), 0)))
        if offset is None or length is None or offset < 0 or offset + length > len(data):
            raise ValueError(f"binary field {name} does not fit sample ({offset}+{length} > {len(data)})")
        expected = field.get("value")
        if expected and field.get("type") == "hex" and data[offset:offset + length].hex().lower() != str(expected).replace(" ", "").lower():
            raise ValueError(f"binary field {name} magic does not match sample")


def build_driver(
    target_meta: dict[str, Any],
    schema_spec: dict[str, Any],
    output_yaml_path: str | Path,
    binary_spec: BinaryStructSpec | dict[str, Any] | None = None,
    sample_path: str | Path | None = None,
) -> dict[str, Any]:
    static_schema = schema_from_binary_spec(binary_spec) if binary_spec else {}
    sqlite_source = bool(sample_path and _is_sqlite(sample_path)) or target_meta.get("interceptor_type") in {"sqlite", "sqlite_snapshot"}
    interceptor_type = target_meta.get("interceptor_type")
    if sqlite_source and interceptor_type is None and sample_path and _sqlite_is_locked(sample_path):
        interceptor_type = "sqlite_snapshot"
    if sqlite_source and not schema_spec and sample_path:
        try:
            schema_spec = infer_sqlite_schema(sample_path)
        except ValueError as exc:
            if "locked" not in str(exc).lower():
                raise
            interceptor_type = "sqlite_snapshot"
            raise ValueError(
                f"{exc}. Re-run with --schema-spec using a discovered schema, or temporarily close the application once to generate it."
            ) from exc
    if not sqlite_source and not schema_spec and sample_path:
        schema_spec = infer_binary_schema(sample_path)
    merged_schema = {**static_schema, **schema_spec}
    if sample_path and static_schema and not sqlite_source:
        _validate_sample_alignment(sample_path, merged_schema)
    interceptor_type = ("sqlite" if sqlite_source else target_meta.get("interceptor_type", "file_watcher")) if interceptor_type is None else interceptor_type
    interceptor = {
        "type": interceptor_type,
        "path": target_meta.get("path", str(sample_path) if sqlite_source and sample_path else "./output/*.dat"),
        "poll_interval_ms": target_meta.get("poll_interval_ms", 1000),
    }
    if interceptor_type == "file_watcher":
        interceptor.update({"read_mode": target_meta.get("read_mode", "poll"), "stability_ms": target_meta.get("stability_ms", 250)})
    if sqlite_source:
        interceptor["read_only"] = True
    if interceptor_type == "sqlite_snapshot":
        interceptor["snapshot_dir"] = target_meta.get("snapshot_dir", "storage/snapshots")
        interceptor["snapshot_interval_ms"] = target_meta.get("snapshot_interval_ms", 5000)
        interceptor["snapshot_provider"] = target_meta.get("snapshot_provider", "auto")
    if sqlite_source:
        interceptor["checkpoint_path"] = target_meta.get("checkpoint_path") or _default_checkpoint_path(
            target_meta, merged_schema, sample_path
        )
    document = {
        "metadata": {
            "name": target_meta.get("name", "Bridgit target"),
            "version": target_meta.get("version", "1.0.0"),
            "target_fingerprint": target_meta.get("target_fingerprint", "unknown"),
        },
        "interceptor": interceptor,
        "schema": merged_schema,
        "exporter": {
            "type": "webhook",
            "endpoint": target_meta.get("endpoint", "http://127.0.0.1:8080/ingest"),
            "method": "POST",
            "max_retries": target_meta.get("max_retries", 3),
            "retry_backoff_ms": target_meta.get("retry_backoff_ms", 250),
            "headers": target_meta.get("headers", {"Content-Type": "application/json"}),
        },
    }
    errors = validate_driver(document)
    if errors:
        raise ValueError("invalid driver: " + "; ".join(errors))
    output = Path(output_yaml_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    temporary.replace(output)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--sample")
    parser.add_argument("--target-meta", default="{}", help="JSON object")
    parser.add_argument("--name", help="target display name")
    parser.add_argument("--interceptor-type", choices=["file_watcher", "sqlite", "sqlite_snapshot"])
    parser.add_argument("--snapshot-provider", choices=["auto", "vss", "sidecar"])
    parser.add_argument("--schema-spec", default="", help="JSON object; inferred from --sample when omitted")
    parser.add_argument("--summary-json", help="optional Ghidra summary JSON")
    args = parser.parse_args(argv)
    target_meta = _parse_mapping_argument(args.target_meta)
    if args.name:
        target_meta["name"] = args.name
    if args.interceptor_type:
        target_meta["interceptor_type"] = args.interceptor_type
    if args.snapshot_provider:
        target_meta["snapshot_provider"] = args.snapshot_provider
    schema_spec = _parse_mapping_argument(args.schema_spec) if args.schema_spec else {}
    binary_spec = parse_binary_evidence(args.summary_json) if args.summary_json else None
    document = build_driver(target_meta, schema_spec, args.output, binary_spec, args.sample)
    print(yaml.safe_dump(document, sort_keys=False), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

