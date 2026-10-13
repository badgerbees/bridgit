import sqlite3
from argparse import Namespace
from pathlib import Path

from bridgit_agent.setup import catalog_sqlite, configure_sqlite, export_contract


def test_catalog_and_configure_sqlite_without_ai(tmp_path: Path) -> None:
    database = tmp_path / "sample.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, created_at TEXT, payload TEXT)")
    connection.execute("CREATE TABLE event_meta (event_id INTEGER, label TEXT, FOREIGN KEY(event_id) REFERENCES events(id))")
    connection.commit()
    connection.close()

    catalog = catalog_sqlite(database)
    assert catalog["status"] == "ready"
    assert {table["name"] for table in catalog["tables"]} == {"events", "event_meta"}

    output = tmp_path / "driver.yaml"
    result = configure_sqlite(Namespace(
        database=str(database), output=str(output), table="events", primary_key=None,
        fields="id,created_at,payload", name="Events", endpoint="http://127.0.0.1:8080/ingest",
        initial_sync="tail", snapshot=False, snapshot_provider="auto", auto=False,
    ))
    assert result["driver"]["schema"]["primary_key"] == "id"
    assert result["driver"]["interceptor"]["type"] == "sqlite"
    assert result["driver"]["interceptor"]["checkpoint_path"].startswith(
        "storage/checkpoints/sample-events-"
    )
    assert output.is_file()

    contract_path = tmp_path / "events.schema.json"
    contract = export_contract(str(output), str(contract_path), "json-schema")
    assert contract["properties"]["fields"]["properties"]["id"]["type"] == [
        "string", "number", "integer", "boolean", "null"
    ]
    assert contract_path.is_file()

    openapi_path = tmp_path / "events.openapi.yaml"
    openapi = export_contract(str(output), str(openapi_path), "openapi")
    assert "/ingest" in openapi["paths"]
    assert openapi_path.is_file()
