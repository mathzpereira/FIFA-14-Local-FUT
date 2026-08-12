from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import diagnose_fifa14_build as diagnostic
from diagnose_fifa14_build import build_diagnostic, write_diagnostic
from fifa14_build_profiles import (
    SUPPORTED_V237_HASHES,
    classify_hash_tuple,
    complete_hash_tuple,
    fingerprint_binary,
    fingerprint_game_root,
)


class BuildFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.outputdir = tempfile.TemporaryDirectory()
        self.output_root = Path(self.outputdir.name)

    def tearDown(self):
        self.outputdir.cleanup()
        self.tempdir.cleanup()

    def _populate_minimal_install(self):
        contents = {
            "fifa14.exe": b"game",
            "CardsDLLzf.dll": b"cards",
            "powdllzf.dll": b"pow",
        }
        for name, data in contents.items():
            (self.root / name).write_bytes(data)
        for name in (
            "cards0.big", "cards0.bh", "data0.big", "data0.bh",
            "data1.big", "data1.bh", "patch.big", "patch.bh",
        ):
            contents[name] = b""
            (self.root / name).write_bytes(b"")
        return {self.root / name: data for name, data in contents.items()}

    def test_fingerprint_binary_reports_uppercase_sha256(self):
        path = self.root / "fifa14.exe"
        path.write_bytes(b"fifa-test")

        result = fingerprint_binary(path, "fifa14.exe")

        self.assertTrue(result["exists"])
        self.assertEqual(result["name"], "fifa14.exe")
        self.assertEqual(result["path"], str(path.resolve()))
        self.assertEqual(result["size"], len(b"fifa-test"))
        self.assertEqual(result["sha256"], hashlib.sha256(b"fifa-test").hexdigest().upper())

    def test_classification_requires_the_complete_supported_tuple(self):
        self.assertEqual(classify_hash_tuple(SUPPORTED_V237_HASHES), "supported-v237")
        self.assertEqual(
            classify_hash_tuple(
                (
                    "3B8C128CA34F5E1E568740BA8C1E789C5C32779ADC3CECBE171AE4A4658760E2",
                    SUPPORTED_V237_HASHES[1],
                    SUPPORTED_V237_HASHES[2],
                )
            ),
            "unknown",
        )
        self.assertEqual(classify_hash_tuple(None), "unknown")

    def test_missing_binary_is_reported_without_reading_it(self):
        result = fingerprint_binary(self.root / "missing.dll", "CardsDLLzf.dll")

        self.assertEqual(result["name"], "CardsDLLzf.dll")
        self.assertEqual(result["path"], str((self.root / "missing.dll").resolve()))
        self.assertEqual(result["exists"], False)
        self.assertIsNone(result["size"])
        self.assertIsNone(result["sha256"])
        self.assertIsNone(result["fileVersion"])
        self.assertIsNone(result["productVersion"])

    def test_fingerprint_binary_reports_hash_read_failure(self):
        path = self.root / "fifa14.exe"
        path.write_bytes(b"fifa-test")

        with mock.patch.object(Path, "open", side_effect=PermissionError("denied")):
            result = fingerprint_binary(path, "fifa14.exe")

        self.assertTrue(result["exists"])
        self.assertEqual(result["status"], "fail")
        self.assertIn("denied", result["error"])

    def test_game_root_uses_first_existing_powdll_candidate(self):
        (self.root / "fifa14.exe").write_bytes(b"game")
        (self.root / "CardsDLLzf.dll").write_bytes(b"cards")
        nested = self.root / "dlc" / "dlc_powdll" / "dlc" / "powdll" / "powdllzf.dll"
        nested.parent.mkdir(parents=True)
        nested.write_bytes(b"nested-pow")
        (self.root / "powdllzf.dll").write_bytes(b"root-pow")

        result = fingerprint_game_root(self.root)

        self.assertEqual(result["powdllzf.dll"]["path"], str(nested.resolve()))
        self.assertEqual(
            result["powdllzf.dll"]["sha256"],
            hashlib.sha256(b"nested-pow").hexdigest().upper(),
        )

    def test_complete_hash_tuple_requires_three_existing_hashed_binaries(self):
        for name, contents in (
            ("fifa14.exe", b"game"),
            ("CardsDLLzf.dll", b"cards"),
            ("powdllzf.dll", b"pow"),
        ):
            (self.root / name).write_bytes(contents)

        fingerprint = fingerprint_game_root(self.root)

        self.assertEqual(
            complete_hash_tuple(fingerprint),
            tuple(
                hashlib.sha256(contents).hexdigest().upper()
                for contents in (b"game", b"cards", b"pow")
            ),
        )

        (self.root / "CardsDLLzf.dll").unlink()
        self.assertIsNone(complete_hash_tuple(fingerprint_game_root(self.root)))

    def test_build_diagnostic_reports_unknown_install_without_modifying_inputs(self):
        input_files = self._populate_minimal_install()
        before_bytes = {path: path.read_bytes() for path in input_files}

        report = build_diagnostic(self.root)

        self.assertEqual(report["schema"], "fifa14-build-diagnostic-v1")
        self.assertEqual(report["profile"], "unknown")
        self.assertEqual(set(report["binaries"]), {"fifa14.exe", "CardsDLLzf.dll", "powdllzf.dll"})
        self.assertIn("requiredFiles", report)
        self.assertIn("data1.big", report["archiveChecks"])
        self.assertIn("data1", report["archiveChecks"])
        self.assertIn("matchAssetCheck", report)
        self.assertEqual(report["matchAssetCheck"]["schema"], "fifa14-local-fut-v2.41.1-beta2.22-match-assets")
        self.assertEqual(report["archiveChecks"]["data1"]["status"], "fail")
        self.assertIn("error", report["archiveChecks"]["data1"])
        self.assertEqual(report["matchAssetCheck"]["status"], "fail")
        self.assertIn("error", report["matchAssetCheck"])
        self.assertEqual(before_bytes, {path: path.read_bytes() for path in input_files})

    def test_match_asset_check_uses_system_temporary_directory(self):
        self._populate_minimal_install()

        with mock.patch.object(
            diagnostic.tempfile,
            "TemporaryDirectory",
            wraps=diagnostic.tempfile.TemporaryDirectory,
        ) as temporary_directory:
            diagnostic._match_asset_check(self.root)

        self.assertIsNone(temporary_directory.call_args.kwargs.get("dir"))

    def test_write_diagnostic_creates_report_and_preserves_inputs(self):
        input_files = self._populate_minimal_install()
        output = self.output_root / "nested" / "diagnostic.json"
        before_bytes = {path: path.read_bytes() for path in input_files}

        report = write_diagnostic(self.root, output)

        self.assertEqual(report["schema"], "fifa14-build-diagnostic-v1")
        self.assertTrue(output.is_file())
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema"], report["schema"])
        self.assertEqual(before_bytes, {path: path.read_bytes() for path in input_files})

    def test_write_diagnostic_does_not_follow_hardlinked_output(self):
        self._populate_minimal_install()
        installation_file = self.root / "fifa14.exe"
        output = self.output_root / "diagnostic.json"
        try:
            os.link(installation_file, output)
        except OSError as error:
            self.skipTest(f"hard links unavailable: {error}")
        before_bytes = installation_file.read_bytes()

        write_diagnostic(self.root, output)

        self.assertEqual(installation_file.read_bytes(), before_bytes)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema"],
                         "fifa14-build-diagnostic-v1")

    def test_write_diagnostic_rejects_output_inside_game_root(self):
        self._populate_minimal_install()
        output = self.root / "diagnostic.json"

        with self.assertRaises(ValueError):
            write_diagnostic(self.root, output)

        self.assertFalse(output.exists())

    def test_cli_reports_malformed_arguments_as_json(self):
        script = Path(__file__).with_name("diagnose_fifa14_build.py")

        completed = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stderr)["type"], "ArgumentError")

    def test_cli_reports_unreadable_game_root_as_json(self):
        script = Path(__file__).with_name("diagnose_fifa14_build.py")

        completed = subprocess.run(
            [sys.executable, str(script), "--game-root", str(self.root / "missing")],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stderr)["type"], "NotADirectoryError")


if __name__ == "__main__":
    unittest.main()
