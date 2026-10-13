from pathlib import Path

from bridgit_agent.recon import scan


ROOT = Path(__file__).parents[2]


def test_examples_recon_finds_mock_source_and_output_route() -> None:
    report = scan(ROOT / "examples")
    paths = {item["relative_path"] for item in report["candidate_files"] + report["executables"]}
    assert "mock_target_app.cpp" in paths
    assert "file_watcher" in report["recommended_routes"]


def test_recon_finds_dat_candidate(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    sample = output / "result_1.dat"
    sample.write_bytes(b"BR" + b"RESULT-1\0".ljust(16, b"\0") + (20.5).hex().encode())
    report = scan(tmp_path)
    assert any(item["relative_path"] == "output/result_1.dat" for item in report["candidate_files"])
    assert "output/*.dat" in report["candidate_patterns"]


def test_recon_detects_sqlite_by_magic_without_known_extension(tmp_path: Path) -> None:
    import sqlite3

    database = tmp_path / "accounting.data"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE transactions (guid TEXT PRIMARY KEY)")
    connection.commit()
    connection.close()

    report = scan(tmp_path)
    candidate = next(item for item in report["candidate_files"] if item["relative_path"] == "accounting.data")
    assert candidate["route"] == "sqlite"
    assert candidate["signature"] == "sqlite3"

