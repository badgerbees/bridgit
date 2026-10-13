"""Bridgit's guided setup and inspection commands."""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
from urllib.parse import urlparse
from pathlib import Path
from typing import Any

import yaml

from .driver_builder import build_driver, validate_driver
from .recon import scan
from .rizin_adapter import analyze as analyze_rizin


def catalog_sqlite(database: str | Path) -> dict[str, Any]:
    """Return tables, columns, keys, and relationships using read-only SQLite metadata."""

    path = Path(database).expanduser().resolve()
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=0)
    except sqlite3.Error as exc:
        return {"database": str(path), "status": "unavailable", "error": str(exc), "tables": []}
    try:
        table_names = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        tables: list[dict[str, Any]] = []
        for table in table_names:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = list(connection.execute(f"PRAGMA table_info({quoted})"))
            foreign_keys = [dict(zip(("id", "seq", "table", "from", "to", "on_update", "on_delete", "match"), row))
                            for row in connection.execute(f"PRAGMA foreign_key_list({quoted})")]
            tables.append({
                "name": table,
                "columns": [{"name": row[1], "type": row[2], "not_null": bool(row[3]), "primary_key": bool(row[5])} for row in columns],
                "primary_key": next((row[1] for row in columns if row[5]), None),
                "foreign_keys": foreign_keys,
            })
        return {"database": str(path), "status": "ready", "tables": tables}
    except sqlite3.OperationalError as exc:
        status = "locked" if "locked" in str(exc).lower() or "busy" in str(exc).lower() else "error"
        return {"database": str(path), "status": status, "error": str(exc), "tables": []}
    finally:
        connection.close()


def _table(catalog: dict[str, Any], name: str) -> dict[str, Any]:
    for table in catalog.get("tables", []):
        if table["name"] == name:
            return table
    raise ValueError(f"table not found: {name}")


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _choose(prompt: str, values: list[str], default: int = 0) -> str:
    for index, value in enumerate(values, 1):
        print(f"  [{index}] {value}")
    answer = input(f"{prompt} [{default + 1}]: ").strip()
    index = default if not answer else int(answer) - 1
    if index < 0 or index >= len(values):
        raise ValueError("selection is outside the available choices")
    return values[index]


def configure_sqlite(args: argparse.Namespace) -> dict[str, Any]:
    catalog = catalog_sqlite(args.database)
    if catalog["status"] != "ready":
        raise ValueError(f"database is {catalog['status']}: {catalog.get('error', 'metadata unavailable')}")
    names = [table["name"] for table in catalog["tables"]]
    if not names:
        raise ValueError("database has no application tables")
    table_name = args.table or (_choose("Choose a source table", names) if not args.auto else names[0])
    table = _table(catalog, table_name)
    column_names = [column["name"] for column in table["columns"]]
    primary_key = table["primary_key"] or args.primary_key
    if not primary_key:
        primary_key = _choose("Choose a primary key", column_names)
    fields = [value.strip() for value in args.fields.split(",")] if args.fields else column_names
    unknown = sorted(set(fields) - set(column_names))
    if unknown:
        raise ValueError(f"unknown fields: {', '.join(unknown)}")
    initial_sync = args.initial_sync or ("tail" if any(column["name"] == primary_key and "INT" in column["type"].upper() for column in table["columns"]) else "all")
    schema = {
        "table": table_name,
        "columns": fields,
        "primary_key": primary_key,
        "query": f"SELECT {', '.join(_quote_identifier(field) for field in fields)} FROM {_quote_identifier(table_name)}",
        "initial_sync": initial_sync,
        "deduplication": {"key": primary_key, "mode": "row_hash"},
    }
    metadata = {
        "name": args.name or f"{Path(args.database).stem} {table_name}",
        "path": str(Path(args.database).expanduser().resolve()),
        "interceptor_type": "sqlite_snapshot" if args.snapshot else "sqlite",
        "snapshot_provider": args.snapshot_provider,
        "endpoint": args.endpoint,
    }
    document = build_driver(metadata, schema, args.output)
    return {"driver": document, "catalog": catalog}


def preview(driver_path: str, limit: int) -> dict[str, Any]:
    document = yaml.safe_load(Path(driver_path).read_text(encoding="utf-8"))
    errors = validate_driver(document)
    if errors:
        raise ValueError("invalid driver: " + "; ".join(errors))
    if document["interceptor"]["type"] not in {"sqlite", "sqlite_snapshot"}:
        return {"driver": document, "records": [], "message": "preview currently supports SQLite drivers"}
    schema = document["schema"]
    path = document["interceptor"]["path"]
    connection = sqlite3.connect(f"file:{Path(path).resolve().as_posix()}?mode=ro", uri=True)
    try:
        table = '"' + schema["table"].replace('"', '""') + '"'
        columns = ", ".join('"' + field.replace('"', '""') + '"' for field in schema["columns"])
        rows = connection.execute(f"SELECT {columns} FROM {table} LIMIT ?", (limit,)).fetchall()
        return {"driver": document, "records": [dict(zip(schema["columns"], row)) for row in rows]}
    finally:
        connection.close()


def inspect_target(target: str | Path, analyze_binaries: bool = False) -> dict[str, Any]:
    """Catalog all known source classes without creating a driver implicitly."""

    report = scan(target)
    if not analyze_binaries:
        return report
    root = Path(report["target_dir"])
    analyses: list[dict[str, Any]] = []
    for executable in report["executables"]:
        path = Path(executable["path"])
        try:
            analyses.append(analyze_rizin(path, workspace=root))
        except Exception as exc:
            analyses.append({"available": False, "binary_path": str(path), "message": str(exc)})
    report["binary_analysis"] = analyses
    return report


def _add_configure_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--database", required=True)
    command.add_argument("--output", required=True)
    command.add_argument("--table")
    command.add_argument("--primary-key")
    command.add_argument("--fields", help="comma-separated field names")
    command.add_argument("--name")
    command.add_argument("--endpoint", default="http://127.0.0.1:8080/ingest")
    command.add_argument("--initial-sync", choices=["all", "tail"])
    command.add_argument("--snapshot", action="store_true")
    command.add_argument("--snapshot-provider", choices=["auto", "vss", "sidecar"], default="auto")
    command.add_argument("--auto", action="store_true", help="choose the first catalog table without prompts")


def run_daemon(driver_path: str, queue_dir: str | None = None) -> int:
    """Start the local Rust daemon using the repository's debug build or Cargo."""

    root = Path(__file__).resolve().parents[2]
    executable = root / "daemon" / "target" / "debug" / "bridgit-daemon.exe"
    if executable.exists():
        command = [str(executable), "--driver", str(Path(driver_path).resolve())]
    else:
        command = [
            "cargo",
            "run",
            "--manifest-path",
            str(root / "daemon" / "Cargo.toml"),
            "--",
            "--driver",
            str(Path(driver_path).resolve()),
        ]
    if queue_dir:
        command.extend(["--queue-dir", queue_dir])
    print("Starting Bridgit daemon. Press Ctrl+C to stop.")
    return subprocess.run(command, cwd=root).returncode


def _runtime_states(driver_path: str | None = None) -> list[dict[str, Any]]:
    root = Path.cwd() / "storage" / "queues"
    requested = str(Path(driver_path).expanduser().resolve()) if driver_path else None
    states: list[dict[str, Any]] = []
    if not root.is_dir():
        return states
    for status_path in root.glob("*/status.json"):
        try:
            state = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if requested and str(Path(state.get("driver", "")).resolve()) != requested:
            continue
        queue_dir = Path(state.get("queue_dir", status_path.parent))
        if not queue_dir.is_absolute():
            queue_dir = Path.cwd() / queue_dir
        counts = {}
        for folder in ("pending", "inflight", "ack"):
            counts[folder] = len(list((queue_dir / folder).glob("*.json"))) if (queue_dir / folder).is_dir() else 0
        state["queue_counts"] = counts
        state["queue_dir"] = str(queue_dir)
        states.append(state)
    return states


def runtime_logs(driver_path: str, limit: int = 40) -> dict[str, Any]:
    states = _runtime_states(driver_path)
    if not states:
        return {"driver": str(Path(driver_path).resolve()), "logs": [], "message": "driver is not running or has no runtime history"}
    state = states[0]
    log_path = Path(state["queue_dir"]) / "runtime.log"
    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()[-limit:]
    except OSError:
        lines = []
    return {"driver": state.get("driver"), "state": state.get("state"), "logs": lines}


def _json_type(field: dict[str, Any]) -> dict[str, Any]:
    kind = str(field.get("type", field.get("data_type", "string"))).lower()
    if any(token in kind for token in ("int", "integer", "count")):
        return {"type": "integer"}
    if any(token in kind for token in ("real", "float", "double", "decimal", "numeric")):
        return {"type": "number"}
    if any(token in kind for token in ("bool", "boolean")):
        return {"type": "boolean"}
    if any(token in kind for token in ("blob", "binary", "hex")):
        return {"type": "string", "contentEncoding": "base64"}
    return {"type": "string"}


def export_contract(driver_path: str, output_path: str, contract_format: str) -> dict[str, Any]:
    """Create a JSON Schema or OpenAPI contract from a validated driver."""

    driver = yaml.safe_load(Path(driver_path).read_text(encoding="utf-8"))
    errors = validate_driver(driver)
    if errors:
        raise ValueError("invalid driver: " + "; ".join(errors))
    source_schema = driver["schema"]
    interceptor_type = driver["interceptor"]["type"]
    properties: dict[str, Any] = {
        "source": {"type": "string", "description": "Original source path for the record"},
        "fields": {"type": "object", "properties": {}, "additionalProperties": False},
    }
    required = ["source", "fields"]
    fields = properties["fields"]["properties"]
    if interceptor_type in {"sqlite", "sqlite_snapshot"}:
        for column in source_schema.get("columns", []):
            fields[column] = {"type": ["string", "number", "integer", "boolean", "null"]}
    else:
        for name, spec in source_schema.items():
            fields[name] = _json_type(spec)
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://bridgit.local/contracts/{Path(driver_path).stem}.schema.json",
        "title": driver.get("metadata", {}).get("name", Path(driver_path).stem),
        "description": "Record emitted by Bridgit.",
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
        "x-bridgit-driver": driver.get("metadata", {}),
    }
    if contract_format == "json-schema":
        contract = schema
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
        return contract

    endpoint = urlparse(driver["exporter"]["endpoint"])
    path = endpoint.path or "/ingest"
    openapi = {
        "openapi": "3.1.0",
        "info": {
            "title": driver.get("metadata", {}).get("name", Path(driver_path).stem),
            "version": str(driver.get("metadata", {}).get("version", "1.0.0")),
            "description": "Webhook payload emitted by Bridgit.",
        },
        "servers": [{"url": f"{endpoint.scheme}://{endpoint.netloc}"}] if endpoint.scheme and endpoint.netloc else [],
        "paths": {
            path: {
                "post": {
                    "summary": "Receive a Bridgit record",
                    "operationId": "receiveBridgitRecord",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": schema}},
                    },
                    "responses": {"200": {"description": "Record accepted"}},
                }
            }
        },
        "x-bridgit-driver": driver.get("metadata", {}),
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(yaml.safe_dump(openapi, sort_keys=False), encoding="utf-8")
    return openapi


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bridgit-setup", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="index a target directory")
    scan_parser.add_argument("--target", required=True)
    inspect_parser = commands.add_parser("inspect", help="catalog files, databases, binaries, and routes")
    inspect_parser.add_argument("--target", required=True)
    inspect_parser.add_argument("--analyze-binaries", action="store_true", help="run optional Rizin analysis")
    sources_parser = commands.add_parser("sources", help="find data sources in an application folder")
    sources_parser.add_argument("--target", required=True)
    sources_parser.add_argument("--analyze-binaries", action="store_true", help="run optional Rizin analysis")
    sqlite_parser = commands.add_parser("sqlite", help="catalog SQLite tables and relationships")
    sqlite_parser.add_argument("--database", required=True)
    explore = commands.add_parser("explore", help="show tables and fields in a database")
    explore.add_argument("--database", required=True)
    configure = commands.add_parser("configure", help="create a driver through flags or an interactive wizard")
    _add_configure_arguments(configure)
    create = commands.add_parser("create", help="create a driver for a data source")
    _add_configure_arguments(create)
    preview_parser = commands.add_parser("preview", help="preview records without exporting")
    preview_parser.add_argument("--driver", required=True)
    preview_parser.add_argument("--limit", type=int, default=5)
    validate_parser = commands.add_parser("validate", help="validate a generated driver")
    validate_parser.add_argument("--driver", required=True)
    test_parser = commands.add_parser("test", help="validate a driver and preview sample records")
    test_parser.add_argument("--driver", required=True)
    test_parser.add_argument("--limit", type=int, default=5)
    run_parser = commands.add_parser("run", help="start the Bridgit runtime for a driver")
    run_parser.add_argument("--driver", required=True)
    run_parser.add_argument("--queue-dir", help="optional custom durable queue directory")
    status_parser = commands.add_parser("status", help="show driver and delivery status")
    status_parser.add_argument("--driver")
    logs_parser = commands.add_parser("logs", help="show recent runtime and delivery logs")
    logs_parser.add_argument("--driver", required=True)
    logs_parser.add_argument("--limit", type=int, default=40)
    export_parser = commands.add_parser("export-schema", help="export a JSON Schema or OpenAPI contract")
    export_parser.add_argument("--driver", required=True)
    export_parser.add_argument("--output", required=True)
    export_parser.add_argument("--format", choices=["json-schema", "openapi"], default="json-schema")
    args = parser.parse_args(argv)
    if args.command == "scan":
        print(json.dumps(scan(args.target), indent=2))
    elif args.command in {"inspect", "sources"}:
        print(json.dumps(inspect_target(args.target, args.analyze_binaries), indent=2))
    elif args.command in {"sqlite", "explore"}:
        print(json.dumps(catalog_sqlite(args.database), indent=2))
    elif args.command in {"configure", "create"}:
        result = configure_sqlite(args)
        if args.command == "create":
            print(f"Driver created: {Path(args.output).resolve()}")
            print("Next step: python -m bridgit_agent.setup test --driver", args.output)
        else:
            print(yaml.safe_dump(result["driver"], sort_keys=False), end="")
    elif args.command == "preview":
        print(json.dumps(preview(args.driver, args.limit), indent=2, default=str))
    elif args.command == "test":
        document = yaml.safe_load(Path(args.driver).read_text(encoding="utf-8"))
        errors = validate_driver(document)
        result: dict[str, Any] = {"valid": not errors, "errors": errors}
        if not errors:
            result["preview"] = preview(args.driver, args.limit)
        print(json.dumps(result, indent=2, default=str))
        return 1 if errors else 0
    elif args.command == "run":
        return run_daemon(args.driver, args.queue_dir)
    elif args.command == "status":
        states = _runtime_states(args.driver)
        print(json.dumps({"drivers": states}, indent=2, default=str))
        return 0 if states else 1
    elif args.command == "logs":
        print(json.dumps(runtime_logs(args.driver, args.limit), indent=2, default=str))
        return 0
    elif args.command == "export-schema":
        export_contract(args.driver, args.output, args.format)
        print(f"Contract created: {Path(args.output).resolve()}")
        return 0
    else:
        document = yaml.safe_load(Path(args.driver).read_text(encoding="utf-8"))
        errors = validate_driver(document)
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
        return 1 if errors else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
