"""Bounded, read-only reconnaissance for Bridgit targets."""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DEFAULT_EXTENSIONS = {".exe", ".dll", ".dat", ".sqlite", ".db", ".dbf", ".gnucash", ".log", ".spl", ".cpp"}
MAX_FILES = 80_000
MAX_DEPTH = 8
MAX_HEADER_BYTES = 4096
MAX_STRING_BYTES = 1 << 20


@dataclass(frozen=True)
class FileFinding:
    path: str
    relative_path: str
    extension: str
    size: int
    modified_at: float
    kind: str
    route: str
    pe: dict[str, Any] | None = None
    signature: str | None = None


def _ascii_strings(data: bytes, minimum: int = 4, limit: int = 12) -> list[str]:
    values = re.findall(rb"[ -~]{%d,}" % minimum, data[:MAX_STRING_BYTES])
    return [value.decode("ascii", "replace")[:160] for value in values[:limit]]


def inspect_pe(path: Path) -> dict[str, Any] | None:
    """Read PE identity fields without executing the target."""

    try:
        data = path.open("rb").read(MAX_HEADER_BYTES)
    except OSError:
        return None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return {"signature": "MZ", "pe_valid": False, "strings": _ascii_strings(data)}
    machine, sections, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    optional_offset = pe_offset + 24
    optional_magic = struct.unpack_from("<H", data, optional_offset)[0] if optional_offset + 2 <= len(data) else 0
    return {
        "signature": "PE",
        "pe_valid": True,
        "machine": f"0x{machine:04x}",
        "bits": 64 if optional_magic == 0x20B else 32 if optional_magic == 0x10B else None,
        "sections": sections,
        "timestamp": timestamp,
        "optional_magic": f"0x{optional_magic:04x}",
        "characteristics": f"0x{characteristics:04x}",
        "strings": _ascii_strings(data),
    }


def _route_for(path: Path) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix in {".sqlite", ".db", ".gnucash"}:
        return "sqlite", "database"
    if suffix == ".dbf":
        return "dbf", "database"
    if suffix == ".spl":
        return "spooler", "spool"
    if suffix in {".log", ".dat"}:
        return "file_watcher", "output_candidate"
    if suffix in {".exe", ".dll"}:
        return "analysis_only", "executable"
    if suffix in {".cpp", ".h", ".hpp"}:
        return "analysis_only", "source"
    return "unknown", "other"


def _sqlite_signature(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _candidate_pattern(root: Path) -> list[str]:
    patterns: list[str] = []
    for directory in root.rglob("*"):
        if not directory.is_dir() or directory.name.lower() not in {"output", "out", "temp", "tmp", "logs", "spool"}:
            continue
        relative = directory.relative_to(root).as_posix()
        patterns.extend([f"{relative}/*.dat", f"{relative}/*.log"])
    return sorted(set(patterns))


def scan(target_dir: str | os.PathLike[str], *, max_files: int = MAX_FILES, max_depth: int = MAX_DEPTH) -> dict[str, Any]:
    root = Path(target_dir).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)

    findings: list[FileFinding] = []
    visited = 0
    truncated = False
    for directory, dirnames, filenames in os.walk(root):
        relative_dir = Path(directory).relative_to(root)
        if len(relative_dir.parts) >= max_depth:
            dirnames[:] = []
        dirnames[:] = [name for name in dirnames if name not in {".git", "target", "__pycache__"}]
        for name in filenames:
            visited += 1
            if visited > max_files:
                truncated = True
                break
            path = Path(directory) / name
            suffix = path.suffix.lower()
            sqlite_file = _sqlite_signature(path)
            if suffix not in DEFAULT_EXTENSIONS and not sqlite_file:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            route, kind = _route_for(path)
            signature = None
            if sqlite_file:
                route, kind, signature = "sqlite", "database", "sqlite3"
            findings.append(FileFinding(
                path=str(path),
                relative_path=path.relative_to(root).as_posix(),
                extension=suffix,
                size=stat.st_size,
                modified_at=stat.st_mtime,
                kind=kind,
                route=route,
                pe=inspect_pe(path) if suffix in {".exe", ".dll"} else None,
                signature=signature,
            ))
        if truncated:
            break

    findings.sort(key=lambda item: item.modified_at, reverse=True)
    executables = [asdict(item) for item in findings if item.kind == "executable"]
    candidates = [asdict(item) for item in findings if item.kind in {"output_candidate", "database", "spool", "source"}]
    routes = sorted({item.route for item in findings if item.route not in {"unknown", "analysis_only"}})
    if not routes:
        routes = ["file_watcher"]
    return {
        "target_dir": str(root),
        "limits": {"max_files": max_files, "max_depth": max_depth},
        "files_visited": min(visited, max_files),
        "truncated": truncated,
        "executables": executables,
        "candidate_files": candidates,
        "candidate_patterns": _candidate_pattern(root),
        "recommended_routes": routes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="directory to inspect")
    parser.add_argument("--max-files", type=int, default=MAX_FILES)
    parser.add_argument("--max-depth", type=int, default=MAX_DEPTH)
    args = parser.parse_args(argv)
    print(json.dumps(scan(args.target, max_files=args.max_files, max_depth=args.max_depth), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

