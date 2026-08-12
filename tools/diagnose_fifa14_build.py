#!/usr/bin/env python3
"""Collect read-only evidence about a FIFA 14 installation."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from fifa14_build_profiles import (
    classify_hash_tuple,
    complete_hash_tuple,
    fingerprint_game_root,
)
from patch_fifa14_fut_dynamic_route import read_install


ARCHIVE_NAMES = ("cards0", "data0", "data1", "patch")
SCHEMA = "fifa14-build-diagnostic-v1"
MATCH_ASSET_SCANNER = Path(__file__).resolve().with_name("scan_fifa14_match_assets.py")


def _resolved(path: Path) -> Path:
    return Path(path).expanduser().resolve()


def _validate_game_root(game_root: Path) -> Path:
    root = _resolved(game_root)
    try:
        if not root.is_dir():
            raise NotADirectoryError(f"game root is not a directory: {root}")
        with os.scandir(root):
            pass
    except OSError as error:
        if isinstance(error, NotADirectoryError):
            raise
        raise OSError(f"game root is unreadable: {root}: {error}") from error
    return root


def _file_check(path: Path) -> dict[str, object]:
    result: dict[str, object] = {
        "path": str(path),
        "exists": False,
        "size": None,
        "status": "not-found",
    }
    try:
        if not path.is_file():
            return result
        result["exists"] = True
        result["size"] = path.stat().st_size
        result["status"] = "pass"
    except OSError as error:
        result["status"] = "fail"
        result["error"] = str(error)
    return result


def _archive_pair_status(big: dict[str, object], bh: dict[str, object]) -> str:
    if big["status"] == "fail" or bh["status"] == "fail":
        return "fail"
    if big["status"] != "pass" or bh["status"] != "pass":
        return "not-found"
    return "pass"


def _route_check(root: Path, big: dict[str, object], bh: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {
        "files": {"data1.big": big, "data1.bh": bh},
    }
    if big["status"] == "not-found" or bh["status"] == "not-found":
        result.update({"status": "not-found", "error": "data1.big/data1.bh is incomplete"})
        return result
    if big["status"] == "fail" or bh["status"] == "fail":
        result.update({"status": "fail", "error": "could not read data1.big/data1.bh"})
        return result
    try:
        install, _payload, _decoded, _bh = read_install(root)
    except FileNotFoundError as error:
        result.update({"status": "not-found", "error": str(error)})
    except Exception as error:
        result.update({"status": "fail", "error": f"{type(error).__name__}: {error}"})
    else:
        result.update({"status": "pass", "result": install})
    return result


def _match_asset_check(root: Path) -> dict[str, object]:
    try:
        with tempfile.TemporaryDirectory(prefix="fifa14-build-diagnostic-") as temporary_directory:
            output = Path(temporary_directory) / "match-assets.json"
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(MATCH_ASSET_SCANNER),
                        "--game-root",
                        str(root),
                        "--output",
                        str(output),
                    ],
                    capture_output=True,
                    check=False,
                    encoding="utf-8",
                    errors="replace",
                    timeout=120,
                )
            except (OSError, subprocess.SubprocessError) as error:
                return {"status": "fail", "error": f"{type(error).__name__}: {error}"}
            try:
                document = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                if completed.returncode != 0:
                    message = (completed.stderr or completed.stdout).strip()
                    return {
                        "status": "fail",
                        "error": message or f"scanner exited with code {completed.returncode}",
                        "exitCode": completed.returncode,
                    }
                return {"status": "fail", "error": f"{type(error).__name__}: {error}"}
            if not isinstance(document, dict):
                return {"status": "fail", "error": "match asset scanner returned non-object JSON"}
            document["status"] = "pass" if completed.returncode == 0 else "fail"
            if completed.returncode != 0:
                message = (completed.stderr or completed.stdout).strip()
                document["error"] = message or f"scanner exited with code {completed.returncode}"
                document["exitCode"] = completed.returncode
            return document
    except OSError as error:
        return {"status": "fail", "error": f"{type(error).__name__}: {error}"}


def build_diagnostic(game_root: Path) -> dict[str, object]:
    root = _validate_game_root(game_root)
    binaries = fingerprint_game_root(root)
    hash_tuple = complete_hash_tuple(binaries)

    required_files: dict[str, dict[str, object]] = {}
    archive_checks: dict[str, dict[str, object]] = {}
    for archive_name in ARCHIVE_NAMES:
        big_name = f"{archive_name}.big"
        bh_name = f"{archive_name}.bh"
        big_check = _file_check(root / big_name)
        bh_check = _file_check(root / bh_name)
        required_files[big_name] = big_check
        required_files[bh_name] = bh_check
        archive_checks[big_name] = dict(big_check)
        archive_checks[bh_name] = dict(bh_check)
        if archive_name != "data1":
            archive_checks[archive_name] = {
                "status": _archive_pair_status(big_check, bh_check),
                "files": {big_name: big_check, bh_name: bh_check},
            }

    archive_checks["data1"] = _route_check(
        root,
        required_files["data1.big"],
        required_files["data1.bh"],
    )
    return {
        "schema": SCHEMA,
        "gameRoot": str(root),
        "readOnly": True,
        "profile": classify_hash_tuple(hash_tuple),
        "hashTuple": list(hash_tuple) if hash_tuple is not None else None,
        "binaries": binaries,
        "requiredFiles": required_files,
        "archiveChecks": archive_checks,
        "matchAssetCheck": _match_asset_check(root),
    }


def write_diagnostic(game_root: Path, output: Path) -> dict[str, object]:
    root = _validate_game_root(game_root)
    destination = _resolved(output)
    if destination == root or root in destination.parents:
        raise ValueError("diagnostic output must not be inside the FIFA game root")
    report = build_diagnostic(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=destination.name + ".",
            suffix=".tmp",
            dir=str(destination.parent),
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
    return report


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        print(json.dumps({"error": message, "type": "ArgumentError"}), file=sys.stderr)
        raise SystemExit(2)


def main() -> int:
    parser = _JsonArgumentParser(description="Read-only FIFA 14 build diagnostic")
    parser.add_argument("--game-root", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/fifa14-build-diagnostic.json"),
    )
    args = parser.parse_args()
    try:
        report = write_diagnostic(args.game_root, args.output)
    except Exception as error:
        print(
            json.dumps({"error": str(error), "type": type(error).__name__}),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"output": str(_resolved(args.output)), "profile": report["profile"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
