"""Safe rz-bin adapter for binary identity, sections, imports, and constants."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .binary_parser import parse_rizin_export
from .runner import ToolResult, ensure_workspace_path, run_tool


def find_rz_bin(executable: str | None = None) -> str | None:
    candidates = [executable, os.environ.get("BRIDGIT_RZ_BIN"), "rz-bin", "rz-bin.exe"]
    for candidate in candidates:
        if candidate and (Path(candidate).is_file() or shutil.which(candidate)):
            return str(Path(candidate)) if Path(candidate).is_file() else candidate
    return None


def _json_output(result: ToolResult) -> Any:
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"raw": result.stdout, "error": "rz-bin output was not JSON"}


def analyze(
    binary_path: str | Path,
    *,
    workspace: str | Path | None = None,
    executable: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    root = Path(workspace or Path.cwd()).expanduser().resolve()
    target = ensure_workspace_path(Path(binary_path), root)
    rz_bin = find_rz_bin(executable)
    if not rz_bin:
        return {"available": False, "message": "rz-bin was not found in PATH or BRIDGIT_RZ_BIN", "binary_path": str(target)}

    outputs: dict[str, Any] = {}
    calls: dict[str, ToolResult] = {}
    for name, option in (("info", "-I"), ("sections", "-S"), ("imports", "-i")):
        result = run_tool([rz_bin, "-j", option, str(target)], cwd=root, workspace=root, timeout=timeout)
        calls[name] = result
        outputs[name] = _json_output(result)
    merged = {
        "available": True,
        "binary_path": str(target),
        "info": outputs["info"].get("info", outputs["info"]) if isinstance(outputs["info"], dict) else outputs["info"],
        "sections": outputs["sections"].get("sections", []) if isinstance(outputs["sections"], dict) else [],
        "imports": outputs["imports"].get("imports", []) if isinstance(outputs["imports"], dict) else [],
    }
    evidence = parse_rizin_export(merged)
    merged["entry_point"] = evidence.entry_point
    merged["magic_constants"] = evidence.magic_constants
    merged["evidence"] = evidence.evidence
    merged["commands"] = {name: list(result.command) for name, result in calls.items()}
    merged["errors"] = {name: result.stderr for name, result in calls.items() if result.returncode != 0}
    return merged

