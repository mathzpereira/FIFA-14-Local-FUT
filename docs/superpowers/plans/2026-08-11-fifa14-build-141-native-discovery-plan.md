# FIFA 14 Build 14.2.1468411 Native Discovery Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a read-only report that locates the user's compiled APT route package and uniquely matching native function signatures so a later build profile can be ported without guessing offsets.

**Architecture:** Extend the existing diagnostic layer with two pure discovery components: a `BIG/BH` record and APT-entry scanner, and a PE section/signature scanner for the native modules. The CLI reports evidence only; it never enables the unknown build, writes to the FIFA installation, or edits archives. A later plan will use only uniquely verified results to implement profile-specific patches and hooks.

**Tech Stack:** Python 3.10+, standard library (`argparse`, `hashlib`, `json`, `pathlib`, `re`, `struct`, `tempfile`, `unittest`), existing FIFA `BIG/BH` and `chunkzip` formats, Windows PowerShell for execution.

## Global Constraints

- Support the user's legitimate FIFA 14 PC build without weakening the exact-build safety guard or changing the existing supported build.
- The original profile remains unchanged. Unknown or partially matching builds remain blocked.
- The diagnostic command must not write to the FIFA installation or alter SQLite state.
- Never use a fuzzy hash match or continue after a failed signature check.
- Do not commit executables, DLLs, archives, credentials, certificates, or diagnostic data copied from the game installation.
- Do not infer a patch target from an RVA alone; every emitted native target must include a unique byte-signature match and the PE-derived RVA.
- Use `.venv/Scripts/python.exe` for project checks after bootstrapping.
- There is no pytest configuration or general test suite; use standalone `unittest`, the compile check, JSON validation, focused verifiers, and the documented FIFA runtime flow.

---

### Task 1: Add Generic BIG/BH and APT Discovery

**Files:**
- Create: `tools/fifa14_build_layout.py`
- Create: `tools/test_fifa14_build_layout.py`

**Interfaces:**
- `read_bh_records(bh: bytes) -> list[dict[str, int]]` returns each record's `index`, `offset`, `size`, `reserved`, and 64-bit `pathHash`.
- `decode_chunkzip(payload: bytes) -> bytes` validates the existing `chunkzip` v2 header and returns decoded bytes without writing.
- `discover_big_entries(decoded: bytes) -> list[dict[str, int | str]]` parses `BIG4` and `BIGF` entry tables and returns each entry's `index`, `name`, `offset`, and `size`.
- `discover_archive_records(big_path: Path, bh_path: Path, markers: tuple[bytes, ...]) -> dict[str, object]` scans bounded, readable records and returns file hashes, record count, matching record metadata, decoded hashes, BIG entry metadata, and errors per record.
- `discover_route_record(game_root: Path) -> dict[str, object]` inspects `data1.big/data1.bh`, includes record index `16469` as an explicit observation, and also searches all chunkzip records for APT/BIG entries without assuming the original offset or path hash.

- [ ] **Step 1: Write failing parser tests**

Build synthetic `BH`, `chunkzip`, `BIGF`, and `BIG4` byte fixtures in memory. Define `make_big_fixture(magic: bytes, entries: list[tuple[str, bytes]]) -> bytes` with the same 16-byte header and null-terminated entry names used by the repository parser, and `make_chunkzip_archive(record_index: int, path_hash: int, payload: bytes) -> tuple[bytes, bytes]` that returns a padded BIG payload plus a `ViV4` BH table containing the requested record. Assert that both BIG header variants parse, malformed headers fail closed, record hashes/offsets are preserved, and matching records report decoded entry names without modifying fixture bytes.

```python
def test_bigf_and_big4_entry_tables_are_discovered(self):
    for magic in (b"BIGF", b"BIG4"):
        decoded = make_big_fixture(magic, [("0", b"Apt Data:1:5:4"), ("1", b"constants")])
        entries = discover_big_entries(decoded)
        self.assertEqual([entry["name"] for entry in entries], ["0", "1"])

def test_route_search_does_not_require_original_offset(self):
    big, bh = make_chunkzip_archive(record_index=4, path_hash=0x6471883D373E70C3, payload=make_big_fixture(b"BIGF", [("0", b"Apt Data:1:5:4")]))
    report = discover_archive_records(big, bh, (b"Apt Data",))
    self.assertEqual(report["matches"][0]["record"]["index"], 4)
    self.assertEqual(report["matches"][0]["record"]["pathHash"], "6471883D373E70C3")
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `python ./tools/test_fifa14_build_layout.py`

Expected: FAIL because `tools/fifa14_build_layout.py` does not exist yet.

- [ ] **Step 3: Implement strict read-only archive discovery**

Reuse the repository's existing format rules: `ViV4` BH records, `chunkzip` version 2/alignment 16, and `BIG4`/`BIGF` name tables. Reject truncated records, out-of-range offsets, unsupported compression, and ambiguous entry tables. Limit decoded records to 8 MiB, record only metadata/hashes, and never write a backup or patch state.

- [ ] **Step 4: Run parser tests and compile checks**

Run: `python ./tools/test_fifa14_build_layout.py`

Expected: all parser tests pass with exit code 0.

Run: `python -m compileall -q server tools`

Expected: exit code 0.

### Task 2: Add PE Signature Discovery

**Files:**
- Create: `tools/fifa14_native_signatures.py`
- Modify: `tools/test_fifa14_build_layout.py`

**Interfaces:**
- `read_pe_sections(data: bytes) -> list[dict[str, int | str]]` parses DOS/PE headers and returns section name, raw offset/size, virtual address, and virtual size; malformed PE data raises `ValueError`.
- `scan_signature(data: bytes, signature: bytes) -> list[int]` returns every raw file offset of an exact signature match.
- `raw_offset_to_rva(offset: int, sections: list[dict[str, int | str]]) -> int` maps a unique section-contained raw offset to an RVA and raises when the offset is outside a section.
- `scan_native_targets(path: Path, targets: tuple[dict[str, object], ...]) -> dict[str, object]` returns module hash/size, PE sections, and for each target `matches`, `status` (`unique`, `missing`, or `ambiguous`), `fileOffset`, and `rva` when unique.

- [ ] **Step 1: Add failing PE/signature tests**

Use a minimal synthetic PE section table fixture and byte arrays containing zero, one, and two copies of a signature. Assert that missing and ambiguous matches never produce an RVA.

```python
def test_signature_scan_distinguishes_unique_and_ambiguous(self):
    data = b"prefix" + b"ABCDEF" + b"middle" + b"ABCDEF"
    self.assertEqual(scan_signature(data, b"XYZ"), [])
    self.assertEqual(scan_signature(data, b"ABCDEF"), [6, 18])

def test_raw_offset_maps_only_inside_a_pe_section(self):
    sections = [{"name": ".text", "rawOffset": 0x400, "rawSize": 0x200, "virtualAddress": 0x1000, "virtualSize": 0x200}]
    self.assertEqual(raw_offset_to_rva(0x450, sections), 0x1050)
    with self.assertRaises(ValueError):
        raw_offset_to_rva(0x800, sections)
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `python ./tools/test_fifa14_build_layout.py`

Expected: FAIL because `tools/fifa14_native_signatures.py` does not exist yet.

- [ ] **Step 3: Implement exact PE/signature scanning**

Parse the PE image using `struct` only. Import the existing reviewed target signatures from `frida_pc_fut_nav_route_patch_trace.py` without copying the full tracer or changing its runtime behavior. Include the Milestone 1 groups: `CA_FUNCTION_SIGNATURE`, `UPDATE_SIGNATURE`, `SCREEN_EVENT_DISPATCHER_SIGNATURE`, `NAV_TARGETS`, and `CARDS_TARGETS`. Report raw file offsets and RVAs only for unique exact matches; do not select the nearest match.

- [ ] **Step 4: Run all focused tests**

Run: `python ./tools/test_fifa14_build_layout.py`

Expected: all archive, APT, PE, and signature tests pass with exit code 0.

### Task 3: Add Combined Discovery CLI

**Files:**
- Create: `tools/discover_fifa14_build.py`
- Modify: `tools/test_fifa14_build_layout.py`

**Interfaces:**
- CLI arguments: required `--game-root`; optional `--output` default `artifacts/fifa14-build-layout-v1.json`.
- `build_layout_report(game_root: Path) -> dict[str, object]` returns schema `fifa14-build-layout-v1`, the existing complete hash tuple, `data1` route observations, `cards0`/`patch` archive observations, and native scan results for `fifa14.exe` and `CardsDLLzf.dll`.
- `write_layout_report(game_root: Path, output: Path) -> dict[str, object]` writes only the report and temporary files outside the FIFA root, using the same hard-link-safe atomic output behavior as the existing diagnostic.
- Unknown, missing, ambiguous, or unsupported results remain report data; the command exits 0 after writing a valid report and never enables a profile.

- [ ] **Step 1: Add failing report tests**

Use the synthetic fixtures from Tasks 1 and 2, create placeholder binary inputs, and assert the report schema, hash tuple, archive sections, native sections, `readOnly: true`, and unchanged input bytes.

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `python ./tools/test_fifa14_build_layout.py`

Expected: FAIL because `tools/discover_fifa14_build.py` does not exist yet.

- [ ] **Step 3: Implement the combined CLI**

Use the existing `fingerprint_game_root` output, call the archive and native scanners independently, and capture each exception as a structured `status: fail` object. Do not import or start FIFA, Frida, the local server, or any patch/restore function. Keep output free of binary payloads and raw executable bytes.

- [ ] **Step 4: Run focused tests and local smoke test**

Run: `python ./tools/test_fifa14_build_layout.py`

Expected: all tests pass.

Run: `python ./tools/discover_fifa14_build.py --game-root . --output /tmp/fifa14-build-layout-v1.json`

Expected: exit code 0 and a valid JSON report with `profile: unknown` and structured missing/ambiguous results.

### Task 4: Document And Publish The Discovery Tool

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Document the read-only command and explain that the report is required before adding the alternate build profile.
- Do not document any command that applies a patch to the unknown build.

- [ ] **Step 1: Add the Windows command**

Document:

```powershell
& ".\.venv\Scripts\python.exe" ".\tools\discover_fifa14_build.py" `
    --game-root "D:\Jogos\FIFA 14\Game" `
    --output ".\artifacts\fifa14-build-layout-v1.json"
```

- [ ] **Step 2: Run repository checks**

Run: `python -m compileall -q server tools` and validate every JSON file using the repository CI rule. Expected: both checks pass.

### Task 5: Run Discovery On The User Build

**Files:**
- Input only: the user's FIFA 14 `Game` directory
- Output: ignored `artifacts/fifa14-build-layout-v1.json`

- [ ] **Step 1: Pull the discovery commit into the Windows fork checkout**

Run `git pull fork main` from the fork clone, then execute the documented command.

- [ ] **Step 2: Review the report before implementing any patch**

Send only the report's hashes, record metadata, target statuses, and errors. Do not send executable bytes or full archive payloads. The next plan may add a profile only for unique archive records and unique native signatures; ambiguous targets remain disabled.

## Handoff To The Next Plan

This plan produces evidence, not a working alternate-build launcher. A later plan may implement the static APT/route port and native hooks only after this report identifies concrete, uniquely verifiable targets. The original supported profile and fail-closed guard remain unchanged.
