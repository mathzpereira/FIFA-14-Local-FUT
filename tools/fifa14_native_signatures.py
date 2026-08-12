from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from fifa14_signature_catalog import CARDS_TARGETS, FIFA14_TARGETS


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
