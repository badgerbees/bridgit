import json
import struct
from pathlib import Path

from bridgit_agent.binary_parser import parse_ghidra_summary, parse_rizin_export
from bridgit_agent.driver_builder import build_driver


def test_ghidra_summary_extracts_struct_fields() -> None:
    summary = {
        "program": {"entry_point": "0x401000"},
        "structures": [{
            "name": "ResultRecord",
            "size": 24,
            "fields": [
                {"name": "header", "offset": 0, "length": 2, "type": "char[2]"},
                {"name": "value", "offset": 18, "length": 4, "type": "float"},
                {"name": "status", "offset": 22, "length": 2, "type": "int16_t"},
            ],
        }],
        "constants": [0x42, 0x52],
    }
    spec = parse_ghidra_summary(summary)
    assert spec.name == "ResultRecord"
    assert spec.entry_point == "0x401000"
    assert [(field.name, field.offset, field.type) for field in spec.fields] == [
        ("header", 0, "string"), ("value", 18, "float32"), ("status", 22, "int16")
    ]
    assert "4252" in spec.magic_constants


def test_rizin_export_extracts_entry_sections_and_magic() -> None:
    spec = parse_rizin_export({
        "info": {"entry": "0x401000"},
        "sections": [{"name": ".text", "vaddr": "0x1000"}],
        "magic_bytes": "42 52",
    })
    assert spec.entry_point == "0x401000"
    assert spec.sections[0]["name"] == ".text"
    assert spec.magic_constants == ["4252"]


def test_binary_evidence_drives_driver_builder(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps({
        "structures": [{"name": "ResultRecord", "fields": [
            {"name": "header", "offset": 0, "length": 2, "type": "hex", "value": "4252"},
            {"name": "value", "offset": 18, "length": 4, "type": "float32"},
            {"name": "status_code", "offset": 22, "length": 2, "type": "int16"},
        ]}],
    }), encoding="utf-8")
    sample = tmp_path / "result.dat"
    sample.write_bytes(b"BR" + b"RESULT-1\0".ljust(16, b"\0") + struct.pack("<f", 20.5) + struct.pack("<h", 0))
    output = tmp_path / "driver.yaml"
    spec = parse_ghidra_summary(summary_path)
    build_driver({"path": "./output/*.dat"}, {}, output, spec, sample)
    assert "value" in output.read_text(encoding="utf-8")

