# FIFA 14 Build 14.2.1468411 Diagnostic Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a read-only Windows diagnostic that fingerprints the user's FIFA 14 build and reports which existing archive and client contracts differ, without weakening the launcher guard or modifying the game installation.

**Architecture:** Add a small standard-library Python module for complete binary fingerprints and a CLI that emits one versioned JSON report. Reuse the repository's existing archive parsers for read-only inspection where possible; do not make the launcher accept the new build yet. The diagnostic report is the input for a later, separate static-patch/native-hook port plan.

**Tech Stack:** Python 3.10+, standard library (`argparse`, `hashlib`, `json`, `pathlib`, `struct`, `unittest`), Windows PowerShell, FIFA 14 `BIG`/`BH` archive formats.

## Global Constraints

- Support the user's legitimate FIFA 14 PC build without weakening the exact-build safety guard or changing the existing supported build.
- The original profile remains unchanged. Unknown or partially matching builds remain blocked.
- The diagnostic command must not write to the FIFA installation or alter SQLite state.
- Never use a fuzzy hash match or continue after a failed signature check.
- Do not commit executables, DLLs, archives, credentials, certificates, or diagnostic data copied from the game installation.
- Use `.venv/Scripts/python.exe` for project checks after bootstrapping.
- There is no pytest configuration or general test suite; use standalone `unittest`, the compile check, JSON validation, focused verifiers, and the documented FIFA runtime flow.

---

### Task 1: Add Build Fingerprint Module

**Files:**
- Create: `tools/fifa14_build_profiles.py`
- Create: `tools/test_fifa14_build_profiles.py`

**Interfaces:**
- `fingerprint_binary(path: Path, name: str) -> dict[str, object]` returns `name`, absolute `path`, `exists`, `size`, uppercase `sha256`, `fileVersion`, and `productVersion`; missing files return `exists: false` with the other values set to `None`.
- `fingerprint_game_root(game_root: Path) -> dict[str, object]` fingerprints `fifa14.exe`, `CardsDLLzf.dll`, and the first existing `powdllzf.dll` candidate in `dlc/dlc_powdll/dlc/powdll/powdllzf.dll` and `powdllzf.dll`.
- `complete_hash_tuple(fingerprint: dict[str, object]) -> tuple[str, str, str] | None` returns the three hashes only when every binary exists and has a hash.
- `classify_hash_tuple(values: tuple[str, str, str] | None) -> str` returns `supported-v237` only for the repository's current tuple (`034991BCE371BB2D4E802184DC43E423B0FD7B6D06BF0E41EF12CA0DBC623916`, `642B11EF3DA7EF28E55A40965A2F364012FA6090252A84C3D9BFBA5AB1F060E6`, `AC39EE88E8F0D3A90C0C9EB3C01C030110F892EBA38EC52ED8AD05038C2B24F0`) and `unknown` otherwise.

- [ ] **Step 1: Write the failing tests**

Create temporary files with known byte strings and assert the exact uppercase SHA-256, missing-file result, complete tuple behavior, and classification of both the current supported tuple and the user's alternate tuple.

```python
import hashlib
import tempfile
import unittest
from pathlib import Path
from fifa14_build_profiles import SUPPORTED_V237_HASHES, classify_hash_tuple, fingerprint_binary

class BuildFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = Path(tempfile.mkdtemp())

    def test_fingerprint_binary_reports_uppercase_sha256(self):
        path = self.tempdir / "fifa14.exe"
        path.write_bytes(b"fifa-test")
        result = fingerprint_binary(path, "fifa14.exe")
        self.assertTrue(result["exists"])
        self.assertEqual(result["sha256"], hashlib.sha256(b"fifa-test").hexdigest().upper())

    def test_classification_requires_the_complete_supported_tuple(self):
        self.assertEqual(classify_hash_tuple(SUPPORTED_V237_HASHES), "supported-v237")
        self.assertEqual(classify_hash_tuple(("3B8C128CA34F5E1E568740BA8C1E789C5C32779ADC3CECBE171AE4A4658760E2", SUPPORTED_V237_HASHES[1], SUPPORTED_V237_HASHES[2])), "unknown")

    def test_missing_binary_is_reported_without_reading_it(self):
        result = fingerprint_binary(self.tempdir / "missing.dll", "CardsDLLzf.dll")
        self.assertEqual(result["exists"], False)
        self.assertIsNone(result["sha256"])

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `python ./tools/test_fifa14_build_profiles.py`

Expected: FAIL because `tools/fifa14_build_profiles.py` does not exist yet.

- [ ] **Step 3: Implement the minimal fingerprint module**

Use chunked reads of 1 MiB, resolve paths before serializing them, preserve uppercase hashes, and keep the supported tuple in one exported constant. On Windows, obtain `fileVersion` and `productVersion` through read-only `(Get-Item -LiteralPath $path).VersionInfo` metadata; on non-Windows test environments, return `None` for those two fields. Do not import Frida or any game-specific package.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `python ./tools/test_fifa14_build_profiles.py`

Expected: all tests pass with exit code 0.

### Task 2: Add Read-Only Diagnostic CLI

**Files:**
- Create: `tools/diagnose_fifa14_build.py`
- Modify: `tools/test_fifa14_build_profiles.py`

**Interfaces:**
- CLI arguments: required `--game-root`; optional `--output` with default `artifacts/fifa14-build-diagnostic.json`.
- `build_diagnostic(game_root: Path) -> dict[str, object]` returns schema `fifa14-build-diagnostic-v1`, the fingerprint data, profile classification, required-file status, and read-only archive observations.
- `write_diagnostic(game_root: Path, output: Path) -> dict[str, object]` creates only the report's parent directory and writes UTF-8 JSON; it never opens an installation file for writing.
- Process exit is 0 when the report was written, including for an unknown build; malformed arguments or an unreadable game root return nonzero with a JSON error on stderr.

- [ ] **Step 1: Add failing report-shape tests**

Extend the standalone test file with a temporary game root containing the three binary names and minimal empty archive placeholders. Assert that the report contains `schema`, `gameRoot`, `profile`, `binaries`, `requiredFiles`, and `archiveChecks`, and that no input file's bytes change.

```python
from diagnose_fifa14_build import build_diagnostic

report = build_diagnostic(temp_game_root)
self.assertEqual(report["schema"], "fifa14-build-diagnostic-v1")
self.assertEqual(report["profile"], "unknown")
self.assertEqual(set(report["binaries"]), {"fifa14.exe", "CardsDLLzf.dll", "powdllzf.dll"})
self.assertIn("data1.big", report["archiveChecks"])
self.assertEqual(before_bytes, (temp_game_root / "fifa14.exe").read_bytes())
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `python ./tools/test_fifa14_build_profiles.py`

Expected: FAIL because `build_diagnostic` and `tools/diagnose_fifa14_build.py` do not exist yet.

- [ ] **Step 3: Implement the read-only diagnostic**

Record, for each binary, existence, size, file/product version, and SHA-256. Record the user's known values as observations, not as a supported profile. Check presence and byte sizes for `cards0`, `data0`, `data1`, `patch`, and their `.bh` indexes. For `data1.big`/`data1.bh`, call the existing read-only route inspector and capture either its structured result or its exception text under `archiveChecks.data1`; also invoke the existing read-only `scan_fifa14_match_assets.py` path into a temporary report and embed its JSON under `matchAssetCheck`. Never call an apply/restore function.

Use a per-check object with `status` values `pass`, `fail`, or `not-found` and an `error` string when parsing fails. This allows an unknown build to produce useful evidence instead of aborting at the first mismatch.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `python ./tools/test_fifa14_build_profiles.py`

Expected: all fingerprint and report-shape tests pass with exit code 0.

### Task 3: Add Windows Usage Documentation

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Document the exact read-only command and its output path.
- State that the command is required before adding a new client profile and that its JSON output must not contain copied binary data.

- [ ] **Step 1: Add the diagnostic command beside the existing verification commands**

Document:

```powershell
& ".\.venv\Scripts\python.exe" ".\tools\diagnose_fifa14_build.py" `
    --game-root "D:\Jogos\FIFA 14\Game" `
    --output ".\artifacts\fifa14-build-diagnostic.json"
```

Explain that the command is read-only and that the next port stage requires the resulting JSON plus the user's runtime logs.

- [ ] **Step 2: Verify documentation paths and formatting**

Run: `python -m compileall -q server tools`

Expected: exit code 0. Then run the diagnostic command on Windows and confirm that `artifacts/fifa14-build-diagnostic.json` is created while the FIFA installation timestamps and hashes remain unchanged.

### Task 4: Run the Diagnostic Against the User's Installation

**Files:**
- Input only: the user's FIFA 14 `Game` directory
- Output: ignored `artifacts/fifa14-build-diagnostic.json`

**Interfaces:**
- The user runs the command from the repository root in an elevated PowerShell only if required by file permissions; the diagnostic itself must not patch the game.
- The user returns the JSON report and any captured error text. No executable, DLL, archive, credential, certificate, or SQLite database is uploaded.

- [ ] **Step 1: Run the diagnostic**

Run from the repository root:

```powershell
& ".\.venv\Scripts\python.exe" ".\tools\diagnose_fifa14_build.py" `
    --game-root "D:\Jogos\FIFA 14\Game" `
    --output ".\artifacts\fifa14-build-diagnostic.json"
```

Expected: JSON summary reports `profile: unknown`, preserves the observed three hashes, and lists the archive checks that can or cannot be mapped to the existing profile.

- [ ] **Step 2: Review the report before any patch code changes**

Use the report to decide whether the next plan is static archive portability, native hook portability, or both. Do not add the user's hashes to the launcher until the archive and native checks have concrete verified identities.

## Handoff To The Next Plan

This plan ends after the report is produced and reviewed. The next plan must add the new profile only with verified archive identities and native signatures, then port one feature group at a time. It must preserve the existing profile and keep unknown or partially matching builds blocked.
