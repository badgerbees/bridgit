from pathlib import Path

import pytest

from bridgit_agent.runner import ensure_workspace_path, run_tool


def test_run_tool_returns_structured_result(tmp_path: Path) -> None:
    result = run_tool(
        ["python", "-c", "print('bridgit-ok')"],
        cwd=tmp_path,
        workspace=tmp_path,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "bridgit-ok"
    assert not result.timed_out


def test_workspace_rejects_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ensure_workspace_path(tmp_path.parent, tmp_path)

