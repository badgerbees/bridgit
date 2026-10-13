"""FastMCP tools for Bridgit setup and driver generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .binary_parser import parse_binary_evidence
from .driver_builder import build_driver
from .recon import scan
from .runner import read_file_sample

mcp = FastMCP("bridgit-agent")

@mcp.tool()
def bridgit_parse_binary(binary_path: str, summary_json_path: str) -> dict[str, Any]:
    """Parse Ghidra and optional Rizin evidence into normalized struct metadata."""
    try:
        binary = Path(binary_path).expanduser().resolve()
        summary = Path(summary_json_path).expanduser().resolve()
        if not binary.is_file():
            raise FileNotFoundError(binary)
        if not summary.is_file():
            raise FileNotFoundError(summary)
        spec = parse_binary_evidence(summary)
        result = spec.to_dict()
        result["binary_path"] = str(binary)
        return result
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def bridgit_recon(target_dir: str) -> dict[str, Any]:
    """Run bounded, read-only reconnaissance against a target directory."""
    try:
        return scan(target_dir)
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def bridgit_inspect_file(file_path: str, byte_count: int = 256) -> dict[str, Any]:
    """Return a bounded hex/ASCII sample from a workspace file."""
    try:
        path = Path(file_path).expanduser().resolve()
        data = read_file_sample(path, byte_count, workspace=Path.cwd())
        return {
            "path": str(path),
            "bytes_read": len(data),
            "hex": data.hex(" "),
            "ascii": "".join(chr(value) if 32 <= value < 127 else "." for value in data),
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def bridgit_generate_driver(
    target_meta: dict[str, Any],
    schema_spec: dict[str, Any],
    output_yaml_path: str,
    binary_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and atomically write a Rust-compatible driver.yaml."""
    try:
        document = build_driver(target_meta, schema_spec, output_yaml_path, binary_analysis)
        return {"path": str(Path(output_yaml_path).expanduser().resolve()), "driver": document, "valid": True}
    except Exception as exc:
        return {"error": str(exc), "valid": False}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()