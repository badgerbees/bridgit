"""Bounded, workspace-aware subprocess execution for setup-time tools."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence


@dataclass(frozen=True)
class ToolResult:
    """Stable result envelope returned by every external tool invocation."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    artifact_path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


def _windows_hidden_kwargs() -> dict[str, object]:
    if sys.platform != "win32":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {
        "startupinfo": startupinfo,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


def ensure_workspace_path(path: Path, workspace: Path) -> Path:
    """Resolve a path and reject anything outside the configured workspace."""

    resolved = path.expanduser().resolve()
    root = workspace.expanduser().resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path is outside workspace: {resolved}") from exc
    return resolved


def read_file_sample(path: Path, byte_count: int = 256, *, workspace: Path | None = None) -> bytes:
    """Read a bounded file prefix, optionally enforcing a workspace boundary."""

    if byte_count < 1 or byte_count > 1 << 20:
        raise ValueError("byte_count must be between 1 and 1048576")
    resolved = path.expanduser().resolve()
    if workspace is not None:
        resolved = ensure_workspace_path(resolved, workspace)
    if not resolved.is_file():
        raise FileNotFoundError(resolved)
    with resolved.open("rb") as handle:
        return handle.read(byte_count)


def run_tool(
    args: Sequence[str],
    *,
    cwd: Path,
    workspace: Path | None = None,
    timeout: int = 120,
    stdin_input: str | None = None,
) -> ToolResult:
    """Run a tool without a shell and return normalized UTF-8 output.

    `workspace` is optional for generic callers, but setup tools should provide it
    so the working directory is explicitly bounded. Arguments are never passed
    through a shell.
    """

    if not args:
        raise ValueError("tool command cannot be empty")
    workdir = cwd.expanduser().resolve()
    if workspace is not None:
        workdir = ensure_workspace_path(workdir, workspace)

    command = tuple(str(arg) for arg in args)
    kwargs = {
        "cwd": str(workdir),
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
        "input": stdin_input,
        "shell": False,
        **_windows_hidden_kwargs(),
    }
    try:
        process = subprocess.run(command, **kwargs)
        return ToolResult(command, process.returncode, process.stdout or "", process.stderr or "")
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return ToolResult(command, -1, stdout, f"command timed out after {timeout}s\n{stderr}", True)

