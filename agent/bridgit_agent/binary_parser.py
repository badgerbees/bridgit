"""Normalize Ghidra and Rizin evidence into driver-builder input."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class BinaryField:
    name: str
    offset: int
    type: str
    length: int | None = None
    endian: str = "little"
    encoding: str | None = None
    trim: bool = False
    value: str | None = None
    evidence: str = ""


@dataclass
class BinaryStructSpec:
    name: str = "discovered_record"
    size: int | None = None
    fields: list[BinaryField] = field(default_factory=list)
    magic_constants: list[str] = field(default_factory=list)
    entry_point: str | None = None
    sections: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    path = Path(value)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"analysis JSON must contain an object: {path}")
    return data


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            match = re.search(r"0x[0-9a-f]+|\d+", value, re.I)
            return int(match.group(0), 0) if match else None
    return None


def _type_info(raw: Any, length: int | None = None) -> tuple[str, int | None, str | None, bool]:
    text = str(raw or "").strip().lower()
    text = text.replace("const ", "").replace("unsigned ", "u")
    if "float" in text:
        return "float32", length or 4, None, False
    if "double" in text:
        return "float64", length or 8, None, False
    if "int16" in text or "short" in text or text in {"i16", "u16"}:
        return ("uint16" if text.startswith("u") else "int16"), length or 2, None, False
    if "int32" in text or text in {"int", "i32", "u32"}:
        return ("uint32" if text.startswith("u") else "int32"), length or 4, None, False
    array = re.search(r"(?:char|byte).*?\[(\d+)\]", text)
    if "char" in text or "string" in text or "byte" in text:
        return "string", length or (int(array.group(1)) if array else None), "ascii", True
    if "hex" in text or "byte" in text:
        return "hex", length, None, False
    return "hex", length, None, False


def _field_items(structure: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in ("fields", "members", "components", "elements"):
        value = structure.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
        if isinstance(value, Mapping):
            return [dict(item, name=name) if isinstance(item, Mapping) else {"name": name, "type": item} for name, item in value.items()]
    return []


def _structures(summary: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in ("structs", "structures", "data_types", "datatypes", "types"):
        value = summary.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
        if isinstance(value, Mapping):
            return [dict(item, name=name) if isinstance(item, Mapping) else {"name": name, "fields": item} for name, item in value.items()]
    return []


def parse_ghidra_summary(summary: str | Path | Mapping[str, Any]) -> BinaryStructSpec:
    data = _load(summary)
    candidates: list[tuple[int, Mapping[str, Any]]] = []
    for structure in _structures(data):
        fields = _field_items(structure)
        candidates.append((len(fields), structure))
    selected = max(candidates, key=lambda item: item[0])[1] if candidates else {}
    result = BinaryStructSpec(name=str(selected.get("name", "discovered_record")), size=_int(selected.get("size")))
    for raw in _field_items(selected):
        offset = _int(raw.get("offset", raw.get("byteOffset", raw.get("ordinal"))))
        if offset is None:
            continue
        type_name, inferred_length, encoding, trim = _type_info(raw.get("type", raw.get("data_type", raw.get("datatype"))), _int(raw.get("length", raw.get("size"))))
        result.fields.append(BinaryField(
            name=str(raw.get("name", f"field_{offset:x}")),
            offset=offset,
            type=type_name,
            length=inferred_length,
            endian=str(raw.get("endian", "little")),
            encoding=raw.get("encoding", encoding),
            trim=bool(raw.get("trim", trim)),
            value=str(raw.get("value")) if raw.get("value") is not None else None,
            evidence="ghidra-struct",
        ))
    program = data.get("program") if isinstance(data.get("program"), Mapping) else data
    result.entry_point = str(program.get("entry_point", program.get("entry", ""))) or None
    sections = data.get("sections", program.get("sections", []))
    if isinstance(sections, list):
        result.sections = [dict(item) for item in sections if isinstance(item, Mapping)]
    result.magic_constants.extend(_magic_values(data))
    result.evidence.append("ghidra-summary")
    return result


def _magic_values(data: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("magic", "magic_bytes", "constants", "byte_constants"):
        raw = data.get(key)
        if isinstance(raw, str):
            compact = re.sub(r"[^0-9a-f]", "", raw.lower())
            if len(compact) >= 2 and len(compact) % 2 == 0:
                values.append(compact)
        elif isinstance(raw, list) and raw and all(_int(item) is not None for item in raw):
            values.append(bytes((_int(item) or 0) & 0xFF for item in raw).hex())
    for text in data.get("strings", []) if isinstance(data.get("strings"), list) else []:
        if isinstance(text, Mapping):
            text = text.get("value", text.get("string", ""))
        if isinstance(text, str) and text.startswith("BR"):
            values.append(text[:2].encode().hex())
    return sorted(set(values))


def parse_rizin_export(export: str | Path | Mapping[str, Any]) -> BinaryStructSpec:
    data = _load(export)
    info = data.get("info", data)
    result = BinaryStructSpec(
        name="rizin_binary",
        entry_point=str(info.get("entry", info.get("intrp", ""))) or None,
        sections=[dict(item) for item in data.get("sections", []) if isinstance(item, Mapping)],
        evidence=["rizin-export"],
    )
    result.magic_constants.extend(_magic_values(data))
    result.magic_constants.extend(_magic_values(info) if isinstance(info, Mapping) else [])
    return result


def parse_binary_evidence(summary_json_path: str | Path, rizin_json_path: str | Path | None = None) -> BinaryStructSpec:
    result = parse_ghidra_summary(summary_json_path)
    if rizin_json_path:
        rizin = parse_rizin_export(rizin_json_path)
        result.entry_point = result.entry_point or rizin.entry_point
        result.sections = result.sections or rizin.sections
        result.magic_constants = sorted(set(result.magic_constants + rizin.magic_constants))
        result.evidence.extend(item for item in rizin.evidence if item not in result.evidence)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary_json")
    parser.add_argument("--rizin-json")
    args = parser.parse_args(argv)
    print(json.dumps(parse_binary_evidence(args.summary_json, args.rizin_json).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

