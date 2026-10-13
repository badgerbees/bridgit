"""Safe Ghidra analyzeHeadless adapter for Bridgit setup work."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .runner import ToolResult, ensure_workspace_path, run_tool


EXPORT_SCRIPT = """// Bridgit lightweight Ghidra export.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.FileWriter;

public class BridgitExportSummary extends GhidraScript {
    private String esc(String value) {
        return value.replace("\\\\", "\\\\\\\\").replace("\\\"", "\\\\\"");
    }

    @Override
    public void run() throws Exception {
        String output = getScriptArgs()[0];
        StringBuilder json = new StringBuilder();
        json.append("{\\\"program\\\":{\\\"name\\\":\\\"")
            .append(esc(currentProgram.getName()))
            .append("\\\",\\\"entry_point\\\":\\\"")
            .append(currentProgram.getImageBase())
            .append("\\\"},\\\"functions\\\":[");
        boolean first = true;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!first) json.append(',');
            first = false;
            json.append("{\\\"name\\\":\\\"")
                .append(esc(function.getName()))
                .append("\\\",\\\"entry\\\":\\\"")
                .append(function.getEntryPoint())
                .append("\\\"}");
        }
        json.append("]}");
        FileWriter writer = new FileWriter(output);
        writer.write(json.toString());
        writer.close();
    }
}
"""


def find_ghidra(executable: str | None = None) -> str | None:
    candidates = [executable, os.environ.get("BRIDGIT_GHIDRA_HEADLESS"), "analyzeHeadless", "analyzeHeadless.bat"]
    for candidate in candidates:
        if candidate and (Path(candidate).is_file() or shutil.which(candidate)):
            return str(Path(candidate)) if Path(candidate).is_file() else candidate
    return None


def _write_export_script(workspace: Path) -> Path:
    script_dir = workspace / "scripts" / "ghidra"
    script_dir.mkdir(parents=True, exist_ok=True)
    script = script_dir / "BridgitExportSummary.java"
    script.write_text(EXPORT_SCRIPT, encoding="utf-8")
    return script


def analyze(
    binary_path: str | Path,
    *,
    workspace: str | Path | None = None,
    executable: str | None = None,
    timeout: int = 1800,
) -> ToolResult:
    root = Path(workspace or Path.cwd()).expanduser().resolve()
    target = ensure_workspace_path(Path(binary_path), root)
    ghidra = find_ghidra(executable)
    if not ghidra:
        return ToolResult((), -1, "", "Ghidra analyzeHeadless was not found in PATH or BRIDGIT_GHIDRA_HEADLESS", details={"available": False})
    exports = root / "exports" / "ghidra"
    projects = root / "projects" / "ghidra"
    exports.mkdir(parents=True, exist_ok=True)
    projects.mkdir(parents=True, exist_ok=True)
    script = _write_export_script(root)
    summary = exports / f"{target.stem}-ghidra-summary.json"
    args = [
        ghidra, str(projects), f"bridgit_{target.stem}", "-import", str(target),
        "-scriptPath", str(script.parent), "-postScript", script.name, str(summary), "-overwrite",
    ]
    result = run_tool(args, cwd=root, workspace=root, timeout=timeout)
    return ToolResult(
        result.command, result.returncode, result.stdout, result.stderr, result.timed_out,
        str(summary) if summary.exists() else None,
        {"available": True, "summary_path": str(summary), "project_dir": str(projects)},
    )

