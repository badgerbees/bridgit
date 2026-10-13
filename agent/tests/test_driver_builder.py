from pathlib import Path

import yaml

from bridgit_agent.driver_builder import (
    _parse_mapping_argument,
    build_driver,
    infer_binary_schema,
    validate_driver,
)


def test_builder_generates_valid_sample_driver(tmp_path: Path) -> None:
    schema = {
        "header": {"offset": 0, "length": 2, "type": "hex", "value": "4252"},
        "record_id": {"offset": 2, "length": 16, "type": "string", "trim": True},
        "value": {"offset": 18, "length": 4, "type": "float32", "endian": "little"},
        "status_code": {"offset": 22, "length": 2, "type": "int16", "endian": "little"},
    }
    output = tmp_path / "sample_driver.yaml"
    build_driver({"name": "Mock Legacy Diagnostic App", "path": "./examples/output/*.dat"}, schema, output)
    document = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert validate_driver(document) == []
    assert document["interceptor"]["type"] == "file_watcher"
    assert document["schema"]["value"]["offset"] == 18


def test_binary_schema_inference(tmp_path: Path) -> None:
    sample = tmp_path / "result.dat"
    sample.write_bytes(b"BR" + b"RESULT-1\0".ljust(16, b"\0") + (20.5).hex().encode())
    schema = infer_binary_schema(sample)
    assert schema["header"]["value"] == "4252"
    assert schema["value"]["type"] == "float32"


def test_builder_discovers_sqlite_schema_without_id_assumption(tmp_path: Path) -> None:
    import sqlite3

    database = tmp_path / "books.gnucash"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE transactions (guid TEXT PRIMARY KEY, description TEXT, amount REAL)")
    connection.execute("INSERT INTO transactions VALUES ('abc', 'Coffee', 4.5)")
    connection.commit()
    connection.close()

    document = build_driver({}, {}, tmp_path / "driver.yaml", sample_path=database)
    assert document["interceptor"]["type"] == "sqlite"
    assert document["schema"]["table"] == "transactions"
    assert document["schema"]["primary_key"] == "guid"
    assert document["schema"]["query"] == 'SELECT * FROM "transactions"'
    assert validate_driver(document) == []


def test_cli_metadata_accepts_json_and_shell_mapping_forms() -> None:
    assert _parse_mapping_argument('{"name":"GnuCash"}') == {"name": "GnuCash"}
    assert _parse_mapping_argument("{name: GnuCash}") == {"name": "GnuCash"}


def test_builder_emits_adaptive_snapshot_provider(tmp_path: Path) -> None:
    document = build_driver(
        {
            "name": "Brave History",
            "path": "C:/Users/example/History",
            "interceptor_type": "sqlite_snapshot",
            "snapshot_provider": "auto",
        },
        {
            "table": "urls",
            "columns": ["id", "url"],
            "primary_key": "id",
            "query": 'SELECT * FROM "urls"',
        },
        tmp_path / "test_snapshot_driver.yaml",
    )
    assert document["interceptor"]["snapshot_provider"] == "auto"
    assert validate_driver(document) == []

