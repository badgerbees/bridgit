import json
from pathlib import Path

from bridgit_agent import ghidra_adapter, rizin_adapter
from bridgit_agent.runner import ToolResult


def test_ghidra_adapter_uses_runner_and_returns_summary(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        summary = tmp_path / "exports" / "ghidra" / "target-ghidra-summary.json"
        summary.parent.mkdir(parents=True, exist_ok=True)
        summary.write_text(json.dumps({"structures": []}), encoding="utf-8")
        return ToolResult(tuple(args), 0, "analysis complete", "")

    monkeypatch.setattr(ghidra_adapter, "find_ghidra", lambda _: "analyzeHeadless")
    monkeypatch.setattr(ghidra_adapter, "run_tool", fake_run)
    result = ghidra_adapter.analyze(binary, workspace=tmp_path)
    assert result.returncode == 0
    assert result.artifact_path and result.artifact_path.endswith("target-ghidra-summary.json")
    assert calls[0][1]["workspace"] == tmp_path.resolve()
    assert "-postScript" in calls[0][0]


def test_ghidra_adapter_missing_tool_is_clean(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(ghidra_adapter, "find_ghidra", lambda _: None)
    result = ghidra_adapter.analyze(binary, workspace=tmp_path)
    assert result.details["available"] is False
    assert result.returncode == -1


def test_rizin_adapter_parses_mock_commands(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    responses = {
        "-I": {"info": {"entry": "0x401000"}},
        "-S": {"sections": [{"name": ".text", "vaddr": "0x1000"}]},
        "-i": {"imports": [{"name": "CreateFileW"}]},
    }

    def fake_run(args, **kwargs):
        return ToolResult(tuple(args), 0, json.dumps(responses[args[2]]), "")

    monkeypatch.setattr(rizin_adapter, "find_rz_bin", lambda _: "rz-bin")
    monkeypatch.setattr(rizin_adapter, "run_tool", fake_run)
    result = rizin_adapter.analyze(binary, workspace=tmp_path)
    assert result["available"] is True
    assert result["entry_point"] == "0x401000"
    assert result["sections"][0]["name"] == ".text"
    assert result["imports"][0]["name"] == "CreateFileW"


def test_rizin_adapter_missing_tool_is_clean(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setattr(rizin_adapter, "find_rz_bin", lambda _: None)
    result = rizin_adapter.analyze(binary, workspace=tmp_path)
    assert result["available"] is False

