from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import zlib


BH_MAGIC = b"ViV4"
CHUNKZIP_MAGIC = b"chunkzip"
BIG_MAGICS = {b"BIG4", b"BIGF"}
MAX_DECODED_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
ROUTE_RECORD_INDEX = 16_469
ROUTE_RECORD_SIZE = 1_875
ROUTE_RECORD_PATH_HASH = 0x6471883D373E70C3


def _align(value: int, boundary: int = 16) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_bh_records(bh: bytes) -> list[dict[str, int]]:
    """Read the fixed-width big-endian records from a ViV4 BH index."""
    if len(bh) < 16 or bh[:4] != BH_MAGIC:
        raise ValueError("BH data is not a ViV4 index")
    count = struct.unpack_from(">I", bh, 8)[0]
    table_end = 16 + count * 20
    if table_end > len(bh):
        raise ValueError(f"BH record table truncated: count={count}")
    records: list[dict[str, int]] = []
    for index in range(count):
        position = 16 + index * 20
        offset, size, reserved, hash_hi, hash_lo = struct.unpack_from(">IIIII", bh, position)
        records.append(
            {
                "index": index,
                "offset": offset,
                "size": size,
                "reserved": reserved,
                "pathHash": (hash_hi << 32) | hash_lo,
            }
        )
    return records


def decode_chunkzip(payload: bytes) -> bytes:
    """Decode a FIFA chunkzip v2 payload without modifying the input."""
    if len(payload) < 40 or payload[:8] != CHUNKZIP_MAGIC:
        raise ValueError("payload is not chunkzip")
    version, output_size, chunk_size, count, alignment, flag_a, flag_b, flag_c = struct.unpack_from(
        ">IIIIIIII", payload, 8
    )
    if version != 2 or alignment != 16 or flag_a or flag_b or flag_c:
        raise ValueError("unsupported chunkzip v2 header")
    if output_size > MAX_DECODED_BYTES:
        raise ValueError(f"decoded chunkzip exceeds {MAX_DECODED_BYTES} bytes")
    if not 1 <= count <= 4096:
        raise ValueError(f"unsupported chunk count {count}")
    if count and chunk_size == 0:
        raise ValueError("chunkzip chunk size is zero")
    if chunk_size > MAX_DECODED_BYTES:
        raise ValueError("chunkzip chunk size exceeds decode limit")

    position = 40
    output = bytearray()
    for index in range(count):
        if position + 8 > len(payload):
            raise ValueError(f"truncated chunk descriptor {index}")
        stored_size, compression_type = struct.unpack_from(">II", payload, position)
        start = position + 8
        end = start + stored_size
        if end > len(payload):
            raise ValueError(f"truncated chunk {index}")
        stored = payload[start:end]
        if compression_type == 0:
            decoded = stored
        elif compression_type == 1:
            try:
                decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                decoded = decoder.decompress(stored, MAX_DECODED_BYTES - len(output) + 1)
                decoded += decoder.flush()
                if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                    raise ValueError("incomplete or trailing deflate data")
            except zlib.error as exc:
                raise ValueError(f"invalid deflate chunk {index}: {exc}") from exc
            except ValueError as exc:
                raise ValueError(f"invalid deflate chunk {index}: {exc}") from exc
        else:
            raise ValueError(f"unsupported compression type {compression_type}")
        if len(decoded) > MAX_DECODED_BYTES - len(output):
            raise ValueError("decoded chunkzip exceeds decode limit")
        output.extend(decoded)
        position = _align(end + 8) - 8

    if len(output) != output_size:
        raise ValueError(f"decoded size {len(output)} != declared {output_size}")
    return bytes(output)


def discover_big_entries(decoded: bytes) -> list[dict[str, int | str]]:
    """Parse a strict BIG4/BIGF entry table from decoded package bytes."""
    if len(decoded) < 16 or decoded[:4] not in BIG_MAGICS:
        raise ValueError("data is not a BIG4/BIGF package")
    declared_size, count, header_size = struct.unpack_from(">III", decoded, 4)
    if declared_size < 16 or declared_size > len(decoded):
        raise ValueError(f"invalid BIG declared size {declared_size} for {len(decoded)} bytes")
    if header_size < 16 or header_size > declared_size:
        raise ValueError(f"invalid BIG header size {header_size}")
    if count > (header_size - 16) // 9:
        raise ValueError(f"unreasonable BIG entry count {count}")

    entries: list[dict[str, int | str]] = []
    names: set[str] = set()
    position = 16
    for index in range(count):
        if position + 8 > header_size:
            raise ValueError("truncated BIG entry table")
        offset, size = struct.unpack_from(">II", decoded, position)
        position += 8
        terminator = decoded.find(b"\0", position, header_size)
        if terminator < 0:
            raise ValueError("unterminated BIG entry name")
        try:
            name = decoded[position:terminator].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("BIG entry name is not UTF-8") from exc
        normalized_name = name.replace("\\", "/")
        if not normalized_name or normalized_name in names:
            raise ValueError("ambiguous BIG entry name table")
        names.add(normalized_name)
        position = terminator + 1
        if offset < header_size or size > declared_size - offset:
            raise ValueError(f"BIG entry outside package: {name}")
        entries.append({"index": index, "name": normalized_name, "offset": offset, "size": size})

    if position != header_size:
        raise ValueError("ambiguous BIG entry table")
    return entries


def _public_record(record: dict[str, int]) -> dict[str, int | str]:
    return {
        "index": record["index"],
        "offset": record["offset"],
        "size": record["size"],
        "reserved": record["reserved"],
        "pathHash": f"{record['pathHash']:016X}",
    }


def _marker_names(markers: tuple[bytes, ...]) -> list[str]:
    if not isinstance(markers, tuple) or not markers or any(not isinstance(marker, bytes) or not marker for marker in markers):
        raise ValueError("markers must be a non-empty tuple of non-empty bytes")
    return [marker.decode("ascii", errors="replace") for marker in markers]


def discover_archive_records(
    big_path: Path, bh_path: Path, markers: tuple[bytes, ...]
) -> dict[str, object]:
    """Scan readable BIG records and return metadata for marker-bearing payloads."""
    marker_names = _marker_names(markers)
    big_size = big_path.stat().st_size
    bh_size = bh_path.stat().st_size
    big_hash = _sha256_path(big_path)
    bh_bytes = bh_path.read_bytes()
    bh_hash = _sha256(bh_bytes)
    records = read_bh_records(bh_bytes)
    report: dict[str, object] = {
        "bigPath": str(big_path),
        "bhPath": str(bh_path),
        "bigSize": big_size,
        "bhSize": bh_size,
        "bigSha256": big_hash,
        "bhSha256": bh_hash,
        "recordCount": len(records),
        "matches": [],
        "errors": [],
        "record16469": None,
    }
    matches = report["matches"]
    errors = report["errors"]
    assert isinstance(matches, list)
    assert isinstance(errors, list)

    with big_path.open("rb") as handle:
        for raw_record in records:
            record = _public_record(raw_record)
            if raw_record["index"] == ROUTE_RECORD_INDEX:
                report["record16469"] = record
            size = raw_record["size"]
            offset = raw_record["offset"]
            if offset > big_size or size > big_size - offset:
                errors.append({"record": raw_record["index"], "stage": "read", "error": "record exceeds BIG file"})
                continue
            if size == 0:
                continue
            if size > MAX_RECORD_BYTES:
                errors.append({"record": raw_record["index"], "stage": "read", "error": "record exceeds scan limit"})
                continue
            handle.seek(offset)
            stored = handle.read(size)
            if len(stored) != size:
                errors.append({"record": raw_record["index"], "stage": "read", "error": "short record read"})
                continue

            decoded = stored
            if stored.startswith(CHUNKZIP_MAGIC):
                try:
                    decoded = decode_chunkzip(stored)
                except ValueError as exc:
                    errors.append({"record": raw_record["index"], "stage": "chunkzip", "error": str(exc)})
                    continue
            elif len(decoded) > MAX_DECODED_BYTES:
                errors.append({"record": raw_record["index"], "stage": "decode", "error": "record exceeds decode limit"})
                continue

            is_big = decoded[:4] in BIG_MAGICS
            big_entries: list[dict[str, int | str]] = []
            if is_big:
                try:
                    big_entries = discover_big_entries(decoded)
                except ValueError as exc:
                    errors.append({"record": raw_record["index"], "stage": "big", "error": str(exc)})
                    continue

            matching_entries = []
            for entry in big_entries:
                start = int(entry["offset"])
                end = start + int(entry["size"])
                entry_payload = decoded[start:end]
                if any(marker in entry_payload for marker in markers):
                    matching_entries.append(entry)
            if is_big:
                if not matching_entries:
                    continue
            elif not any(marker in decoded for marker in markers):
                continue
            matches.append(
                {
                    "record": record,
                    "storedSha256": _sha256(stored),
                    "decodedSha256": _sha256(decoded),
                    "decodedSize": len(decoded),
                    "markers": marker_names,
                    "entries": matching_entries,
                    "bigEntries": big_entries,
                }
            )
    return report


def discover_route_record(game_root: Path) -> dict[str, object]:
    """Inspect data1 while keeping the known record observation separate from matches."""
    archive = discover_archive_records(game_root / "data1.big", game_root / "data1.bh", (b"Apt Data",))
    observation = {
        "index": ROUTE_RECORD_INDEX,
        "expectedSize": ROUTE_RECORD_SIZE,
        "expectedPathHash": f"{ROUTE_RECORD_PATH_HASH:016X}",
        "record": archive["record16469"],
    }
    return {
        "archive": archive,
        "record16469": observation,
        "matches": archive["matches"],
        "errors": archive["errors"],
        "recordCount": archive["recordCount"],
    }
