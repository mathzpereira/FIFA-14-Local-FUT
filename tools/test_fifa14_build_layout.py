from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from fifa14_build_layout import (
    decode_chunkzip,
    discover_archive_records,
    discover_big_entries,
    discover_route_record,
    read_bh_records,
)
from fifa14_native_signatures import (
    CARDS_TARGETS,
    FIFA14_TARGETS,
    raw_offset_to_rva,
    read_pe_sections,
    scan_native_targets,
    scan_signature,
)


def align(value: int, boundary: int = 16) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def make_big_fixture(magic: bytes, entries: list[tuple[str, bytes]]) -> bytes:
    table = bytearray()
    payloads = bytearray()
    header_size = 16
    for name, payload in entries:
        header_size += 8 + len(name.encode("utf-8")) + 1
    offset = header_size
    for name, payload in entries:
        table.extend(struct.pack(">II", offset, len(payload)))
        table.extend(name.encode("utf-8"))
        table.append(0)
        payloads.extend(payload)
        offset += len(payload)
    return magic + struct.pack(">III", offset, len(entries), header_size) + bytes(table) + bytes(payloads)


def make_chunkzip(payload: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    stored = compressor.compress(payload) + compressor.flush()
    descriptor_end = 40 + 8 + len(stored)
    chunk_end = align(descriptor_end + 8) - 8
    return (
        b"chunkzip"
        + struct.pack(">IIIIIIII", 2, len(payload), 262144, 1, 16, 0, 0, 0)
        + struct.pack(">II", len(stored), 1)
        + stored
        + b"\0" * (chunk_end - descriptor_end)
    )


def make_chunkzip_archive(record_index: int, path_hash: int, payload: bytes) -> tuple[bytes, bytes]:
    stored = make_chunkzip(payload)
    record_offset = 32
    big = b"\0" * record_offset + stored + b"\0" * 16
    records = record_index + 1
    bh = bytearray(b"ViV4" + b"\0" * 12 + b"\0" * (records * 20))
    struct.pack_into(">I", bh, 8, records)
    struct.pack_into(">IIIII", bh, 16 + record_index * 20, record_offset, len(stored), 0, path_hash >> 32, path_hash & 0xFFFFFFFF)
    return big, bytes(bh)


def make_pe_fixture(section_data: bytes = b"") -> bytes:
    section_offset = 0x400
    section_size = 0x200
    pe_offset = 0x80
    optional_size = 0xE0
    section_table_offset = pe_offset + 4 + 20 + optional_size
    image = bytearray(section_offset + section_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", image, pe_offset + 6, 1)
    struct.pack_into("<H", image, pe_offset + 20, optional_size)
    struct.pack_into("<H", image, pe_offset + 24, 0x10B)
    section = section_table_offset
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, section_size, 0x1000, section_size, section_offset)
    image[section_offset : section_offset + len(section_data)] = section_data
    return bytes(image)


class BuildLayoutTests(unittest.TestCase):
    def test_bigf_and_big4_entry_tables_are_discovered(self):
        for magic in (b"BIGF", b"BIG4"):
            decoded = make_big_fixture(magic, [("0", b"Apt Data:1:5:4"), ("1", b"constants")])
            entries = discover_big_entries(decoded)
            self.assertEqual([entry["name"] for entry in entries], ["0", "1"])
            self.assertEqual([entry["index"] for entry in entries], [0, 1])
            self.assertEqual(entries[0]["size"], len(b"Apt Data:1:5:4"))

    def test_big_entry_table_rejects_truncated_and_ambiguous_data(self):
        fixture = make_big_fixture(b"BIGF", [("0", b"payload")])
        with self.assertRaises(ValueError):
            discover_big_entries(fixture[:-1])

        ambiguous = bytearray(fixture)
        struct.pack_into(">I", ambiguous, 12, len(fixture) + 1)
        ambiguous.insert(len(fixture), 0)
        with self.assertRaises(ValueError):
            discover_big_entries(bytes(ambiguous))

        with self.assertRaises(ValueError):
            discover_big_entries(make_big_fixture(b"BIGF", [("a\\b", b"one"), ("a/b", b"two")]))

    def test_bh_records_preserve_offsets_sizes_reserved_and_path_hash(self):
        path_hash = 0x6471883D373E70C3
        bh = bytearray(b"ViV4" + b"\0" * 12 + b"\0" * 20)
        struct.pack_into(">I", bh, 8, 1)
        struct.pack_into(">IIIII", bh, 16, 32, 123, 7, path_hash >> 32, path_hash & 0xFFFFFFFF)

        self.assertEqual(
            read_bh_records(bytes(bh)),
            [{"index": 0, "offset": 32, "size": 123, "reserved": 7, "pathHash": path_hash}],
        )

    def test_bh_rejects_truncated_header_and_record_table(self):
        with self.assertRaises(ValueError):
            read_bh_records(b"ViV4" + b"\0" * 11)

        bh = bytearray(b"ViV4" + b"\0" * 12)
        struct.pack_into(">I", bh, 8, 1)
        with self.assertRaises(ValueError):
            read_bh_records(bytes(bh))

    def test_chunkzip_decodes_valid_payload_without_mutating_input(self):
        payload = make_chunkzip(b"decoded data")
        original = bytes(payload)
        self.assertEqual(decode_chunkzip(payload), b"decoded data")
        self.assertEqual(payload, original)

    def test_chunkzip_rejects_malformed_headers_chunks_and_output_limit(self):
        valid = make_chunkzip(b"decoded data")
        for malformed in (valid[:39], b"notzip" + valid[6:]):
            with self.assertRaises(ValueError):
                decode_chunkzip(malformed)

        unsupported_version = bytearray(valid)
        struct.pack_into(">I", unsupported_version, 8, 1)
        with self.assertRaises(ValueError):
            decode_chunkzip(bytes(unsupported_version))

        unsupported_compression = bytearray(valid)
        struct.pack_into(">I", unsupported_compression, 44, 2)
        with self.assertRaises(ValueError):
            decode_chunkzip(bytes(unsupported_compression))

        stored_size = struct.unpack_from(">I", valid, 40)[0]
        truncated_chunk = valid[: 48 + stored_size - 1]
        with self.assertRaises(ValueError):
            decode_chunkzip(truncated_chunk)

        oversized = bytearray(valid)
        struct.pack_into(">I", oversized, 12, 8 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            decode_chunkzip(bytes(oversized))

        empty = bytearray(valid[:40])
        struct.pack_into(">I", empty, 20, 0)
        with self.assertRaisesRegex(ValueError, "chunk count"):
            decode_chunkzip(bytes(empty))

        too_many = bytearray(valid)
        struct.pack_into(">I", too_many, 20, 4097)
        with self.assertRaisesRegex(ValueError, "chunk count"):
            decode_chunkzip(bytes(too_many))

    def test_route_search_does_not_require_original_offset(self):
        path_hash = 0x1111222233334444
        big, bh = make_chunkzip_archive(
            record_index=4,
            path_hash=path_hash,
            payload=make_big_fixture(b"BIGF", [("0", b"Apt Data:1:5:4")]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            big_path = root / "data1.big"
            bh_path = root / "data1.bh"
            big_path.write_bytes(big)
            bh_path.write_bytes(bh)
            before = (big_path.read_bytes(), bh_path.read_bytes())

            report = discover_archive_records(big_path, bh_path, (b"Apt Data",))

            self.assertEqual(report["matches"][0]["record"]["index"], 4)
            self.assertEqual(report["matches"][0]["record"]["pathHash"], "1111222233334444")
            self.assertEqual(report["matches"][0]["entries"][0]["name"], "0")
            self.assertEqual(report["recordCount"], 5)
            self.assertEqual(report["bigSha256"], hashlib.sha256(big).hexdigest())
            self.assertEqual((big_path.read_bytes(), bh_path.read_bytes()), before)

    def test_archive_reports_truncated_records_without_writing(self):
        big = b"x" * 20
        bh = bytearray(b"ViV4" + b"\0" * 12 + b"\0" * 20)
        struct.pack_into(">I", bh, 8, 1)
        struct.pack_into(">IIIII", bh, 16, 19, 4, 0, 0, 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            big_path = root / "data1.big"
            bh_path = root / "data1.bh"
            big_path.write_bytes(big)
            bh_path.write_bytes(bh)

            report = discover_archive_records(big_path, bh_path, (b"Apt Data",))

            self.assertEqual(report["matches"], [])
            self.assertEqual(report["errors"][0]["record"], 0)
            self.assertEqual(report["errors"][0]["stage"], "read")

    def test_archive_reports_zero_length_out_of_range_records(self):
        bh = bytearray(b"ViV4" + b"\0" * 12 + b"\0" * 20)
        struct.pack_into(">I", bh, 8, 1)
        struct.pack_into(">IIIII", bh, 16, 21, 0, 0, 0, 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            big_path = root / "data1.big"
            bh_path = root / "data1.bh"
            big_path.write_bytes(b"x" * 20)
            bh_path.write_bytes(bh)

            report = discover_archive_records(big_path, bh_path, (b"Apt Data",))

            self.assertEqual(report["matches"], [])
            self.assertEqual(report["errors"][0]["record"], 0)
            self.assertEqual(report["errors"][0]["stage"], "read")

    def test_archive_ignores_markers_only_in_big_filenames(self):
        big, bh = make_chunkzip_archive(
            record_index=0,
            path_hash=1,
            payload=make_big_fixture(b"BIGF", [("Apt Data filename", b"constants")]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            big_path = root / "data1.big"
            bh_path = root / "data1.bh"
            big_path.write_bytes(big)
            bh_path.write_bytes(bh)

            report = discover_archive_records(big_path, bh_path, (b"Apt Data",))

            self.assertEqual(report["matches"], [])

    def test_route_report_keeps_known_record_observation_explicit(self):
        big, bh = make_chunkzip_archive(
            record_index=4,
            path_hash=0x6471883D373E70C3,
            payload=make_big_fixture(b"BIG4", [("0", b"Apt Data:1:5:4")]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data1.big").write_bytes(big)
            (root / "data1.bh").write_bytes(bh)

            report = discover_route_record(root)

            self.assertEqual(report["record16469"]["index"], 16469)
            self.assertEqual(report["record16469"]["expectedSize"], 1875)
            self.assertEqual(report["record16469"]["expectedPathHash"], "6471883D373E70C3")
            self.assertIsNone(report["record16469"]["record"])
            self.assertEqual(report["matches"][0]["record"]["index"], 4)

    def test_pe_section_table_is_parsed_strictly(self):
        sections = read_pe_sections(make_pe_fixture())
        self.assertEqual(
            sections,
            [
                {
                    "name": ".text",
                    "rawOffset": 0x400,
                    "rawSize": 0x200,
                    "virtualAddress": 0x1000,
                    "virtualSize": 0x200,
                }
            ],
        )
        for malformed in (b"", b"MZ" + b"\0" * 62, make_pe_fixture()[:0x450]):
            with self.assertRaises(ValueError):
                read_pe_sections(malformed)

    def test_signature_scan_distinguishes_unique_and_ambiguous(self):
        data = b"prefix" + b"ABCDEF" + b"middle" + b"ABCDEF"
        self.assertEqual(scan_signature(data, b"XYZ"), [])
        self.assertEqual(scan_signature(data, b"ABCDEF"), [6, 18])

    def test_raw_offset_maps_only_inside_a_pe_section(self):
        sections = [{"name": ".text", "rawOffset": 0x400, "rawSize": 0x200, "virtualAddress": 0x1000, "virtualSize": 0x200}]
        self.assertEqual(raw_offset_to_rva(0x450, sections), 0x1050)
        with self.assertRaises(ValueError):
            raw_offset_to_rva(0x800, sections)

    def test_native_targets_report_only_unique_rvas(self):
        signature = b"ABCDEF"
        ambiguous_signature = b"AMBIGU"
        section_data = b"\0" * 0x20 + signature + b"\0" * 0x10 + ambiguous_signature + b"\0" * 0x10 + ambiguous_signature
        data = make_pe_fixture(section_data)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fifa14.exe"
            path.write_bytes(data)
            report = scan_native_targets(
                path,
                (
                    {"name": "unique", "signature": signature},
                    {"name": "missing", "signature": b"MISSING"},
                    {"name": "ambiguous", "signature": ambiguous_signature},
                    {"name": "header", "signature": b"PE\0\0"},
                    {"name": "offset", "signature": b"ABCDEF", "sigOffset": 2},
                ),
            )

        self.assertEqual(report["size"], len(data))
        self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest().upper())
        targets = {target["name"]: target for target in report["targets"]}
        self.assertEqual(targets["unique"]["status"], "unique")
        self.assertEqual(targets["unique"]["fileOffset"], 0x420)
        self.assertEqual(targets["unique"]["rva"], 0x1020)
        self.assertEqual(targets["missing"], {"name": "missing", "matches": [], "status": "missing"})
        self.assertEqual(targets["ambiguous"]["status"], "ambiguous")
        self.assertNotIn("rva", targets["ambiguous"])
        self.assertNotIn("fileOffset", targets["ambiguous"])
        self.assertEqual(targets["header"]["status"], "missing")
        self.assertNotIn("rva", targets["header"])
        self.assertEqual(targets["offset"]["fileOffset"], 0x41E)
        self.assertEqual(targets["offset"]["rva"], 0x101E)

    def test_milestone_target_catalog_reuses_reviewed_groups(self):
        self.assertEqual(len(FIFA14_TARGETS), 3 + 4)
        self.assertEqual(len(CARDS_TARGETS), 56)
        self.assertEqual(FIFA14_TARGETS[0]["name"], "CA_FUNCTION")
        self.assertEqual(CARDS_TARGETS[0]["name"], "PlugInitialize_")


if __name__ == "__main__":
    unittest.main()
