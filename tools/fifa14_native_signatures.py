from __future__ import annotations

import ast
import hashlib
import re
import struct
from pathlib import Path

from frida_pc_fut_nav_route_patch_trace import (
    CA_FUNCTION_RVA,
    CA_FUNCTION_SIGNATURE,
    NAV_TARGETS,
    SCREEN_EVENT_DISPATCHER_RVA,
    SCREEN_EVENT_DISPATCHER_SIGNATURE,
    UPDATE_RVA,
    UPDATE_SIGNATURE,
)


def _read_u16(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as error:
        raise ValueError("truncated PE header") from error


def _read_u32(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as error:
        raise ValueError("truncated PE header") from error


def read_pe_sections(data: bytes) -> list[dict[str, int | str]]:
    """Parse the section table of a PE32 or PE32+ image."""
    if not isinstance(data, bytes) or len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("invalid DOS header")

    pe_offset = _read_u32(data, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ValueError("invalid PE header offset")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")

    section_count = _read_u16(data, pe_offset + 6)
    optional_size = _read_u16(data, pe_offset + 20)
    if section_count == 0 or optional_size == 0:
        raise ValueError("PE has no section table")

    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise ValueError("truncated PE optional header")
    optional_magic = _read_u16(data, optional_offset)
    minimum_optional_size = {0x10B: 96, 0x20B: 112}.get(optional_magic)
    if minimum_optional_size is None or optional_size < minimum_optional_size:
        raise ValueError("unsupported PE optional header")

    section_table_end = optional_end + section_count * 40
    if section_table_end > len(data):
        raise ValueError("truncated PE section table")

    sections: list[dict[str, int | str]] = []
    raw_ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        section_offset = optional_end + index * 40
        name_bytes = data[section_offset : section_offset + 8]
        name_bytes = name_bytes.split(b"\0", 1)[0]
        if not name_bytes:
            raise ValueError("PE section has no name")
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("PE section name is not ASCII") from error

        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, section_offset + 8
        )
        raw_end = raw_offset + raw_size
        if raw_size and (raw_offset < section_table_end or raw_end > len(data)):
            raise ValueError("PE section raw data is outside the image")
        if raw_size:
            for previous_start, previous_end in raw_ranges:
                if raw_offset < previous_end and previous_start < raw_end:
                    raise ValueError("PE section raw data overlaps")
            raw_ranges.append((raw_offset, raw_end))

        sections.append(
            {
                "name": name,
                "rawOffset": raw_offset,
                "rawSize": raw_size,
                "virtualAddress": virtual_address,
                "virtualSize": virtual_size,
            }
        )
    return sections


def scan_signature(data: bytes, signature: bytes) -> list[int]:
    """Return every exact, including overlapping, signature match offset."""
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        raise TypeError("data and signature must be bytes")
    if not signature:
        raise ValueError("signature must not be empty")

    matches: list[int] = []
    start = 0
    while True:
        offset = data.find(signature, start)
        if offset < 0:
            return matches
        matches.append(offset)
        start = offset + 1


def raw_offset_to_rva(offset: int, sections: list[dict[str, int | str]]) -> int:
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("raw offset must be a non-negative integer")

    candidates: list[dict[str, int | str]] = []
    for section in sections:
        try:
            raw_offset = section["rawOffset"]
            raw_size = section["rawSize"]
            virtual_address = section["virtualAddress"]
        except KeyError as error:
            raise ValueError("section is missing a required field") from error
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (raw_offset, raw_size, virtual_address)):
            raise ValueError("section offsets and sizes must be integers")
        if raw_size < 0 or raw_offset < 0:
            raise ValueError("section offsets and sizes must be non-negative")
        if raw_offset <= offset < raw_offset + raw_size:
            candidates.append(section)

    if not candidates:
        raise ValueError("raw offset is outside all PE sections")
    if len(candidates) != 1:
        raise ValueError("raw offset is contained by multiple PE sections")
    section = candidates[0]
    return int(section["virtualAddress"]) + offset - int(section["rawOffset"])


def _cards_targets_from_tracer() -> tuple[dict[str, object], ...]:
    source_path = Path(__file__).with_name("frida_pc_fut_nav_route_patch_trace.py")
    source = source_path.read_text(encoding="utf-8")
    match = re.search(r"const CARDS_TARGETS\s*=\s*(\[.*?\]);", source, re.DOTALL)
    if match is None:
        raise ValueError("CARDS_TARGETS is missing from the tracer")

    values: dict[str, int] = {}
    for name in (
        "AUTH_RESPONSE_CONSTRUCTOR_RVA",
        "AUTH_RESPONSE_PARSER_RVA",
        "AUTH_RESPONSE_SCALAR_CALLBACK_RVA",
        "AUTH_RESPONSE_KEY_MAPPER_RVA",
    ):
        rva_match = re.search(rf"const {name}\s*=\s*(0x[0-9a-fA-F]+);", source)
        if rva_match is None:
            raise ValueError(f"{name} is missing from the tracer")
        values[name] = int(rva_match.group(1), 16)
    array_text = match.group(1)
    for name, value in values.items():
        array_text = re.sub(rf"\b{re.escape(name)}\b", str(value), array_text)
    array_text = re.sub(
        r"(?<![A-Za-z0-9_$'\"])([A-Za-z_$][A-Za-z0-9_$]*)\s*:",
        r"'\1':",
        array_text,
    )
    try:
        parsed = ast.literal_eval(array_text)
    except (SyntaxError, ValueError) as error:
        raise ValueError("CARDS_TARGETS cannot be parsed") from error
    if not isinstance(parsed, list):
        raise ValueError("CARDS_TARGETS is not a list")

    targets: list[dict[str, object]] = []
    for item in parsed:
        if not isinstance(item, dict):
            raise ValueError("CARDS_TARGETS contains a non-object")
        name = item.get("name")
        rva = item.get("rva")
        sig_offset = item.get("sigOffset", 0)
        signature = item.get("signature")
        if not isinstance(name, str) or not isinstance(rva, int) or not isinstance(sig_offset, int):
            raise ValueError("CARDS_TARGETS contains invalid target metadata")
        if not isinstance(signature, list) or any(not isinstance(value, int) for value in signature):
            raise ValueError("CARDS_TARGETS contains an invalid signature")
        if sig_offset < 0 or any(value < 0 or value > 0xFF for value in signature):
            raise ValueError("CARDS_TARGETS contains an invalid signature byte")
        targets.append(
            {
                "name": name,
                "rva": rva,
                "sigOffset": sig_offset,
                "signature": bytes(signature),
            }
        )
    return tuple(targets)


CARDS_TARGETS = _cards_targets_from_tracer()
FIFA14_TARGETS = (
    {"name": "CA_FUNCTION", "rva": CA_FUNCTION_RVA, "signature": CA_FUNCTION_SIGNATURE},
    {"name": "UPDATE", "rva": UPDATE_RVA, "signature": UPDATE_SIGNATURE},
    {
        "name": "SCREEN_EVENT_DISPATCHER",
        "rva": SCREEN_EVENT_DISPATCHER_RVA,
        "signature": SCREEN_EVENT_DISPATCHER_SIGNATURE,
    },
) + tuple(
    {"name": name, "rva": rva, "signature": signature}
    for name, rva, signature in NAV_TARGETS
)


def _target_result(data: bytes, sections: list[dict[str, int | str]], target: dict[str, object]) -> dict[str, object]:
    name = target.get("name")
    signature = target.get("signature")
    sig_offset = target.get("sigOffset", 0)
    if not isinstance(name, str) or not isinstance(signature, bytes):
        raise ValueError("target must contain a name and byte signature")
    if not isinstance(sig_offset, int) or isinstance(sig_offset, bool) or sig_offset < 0:
        raise ValueError("target signature offset must be non-negative")

    matches = scan_signature(data, signature)
    result: dict[str, object] = {"name": name, "matches": matches}
    if not matches:
        result["status"] = "missing"
        return result
    if len(matches) > 1:
        result["status"] = "ambiguous"
        return result

    file_offset = matches[0] - sig_offset
    if file_offset < 0:
        result["status"] = "missing"
        return result
    try:
        rva = raw_offset_to_rva(file_offset, sections)
    except ValueError:
        result["status"] = "missing"
        return result
    result["status"] = "unique"
    result["fileOffset"] = file_offset
    result["rva"] = rva
    return result


def scan_native_targets(path: Path, targets: tuple[dict[str, object], ...]) -> dict[str, object]:
    resolved_path = Path(path).expanduser().resolve()
    data = resolved_path.read_bytes()
    sections = read_pe_sections(data)
    return {
        "path": str(resolved_path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "sections": sections,
        "targets": [_target_result(data, sections, target) for target in targets],
    }


__all__ = [
    "CARDS_TARGETS",
    "FIFA14_TARGETS",
    "raw_offset_to_rva",
    "read_pe_sections",
    "scan_native_targets",
    "scan_signature",
]
