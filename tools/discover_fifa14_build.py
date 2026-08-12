#!/usr/bin/env python3
"""Collect read-only archive and native layout evidence for a FIFA 14 build."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from fifa14_build_layout import discover_archive_records, discover_route_record
from fifa14_build_profiles import classify_hash_tuple, complete_hash_tuple, fingerprint_game_root
from fifa14_native_signatures import CARDS_TARGETS, FIFA14_TARGETS, scan_native_targets


SCHEMA = "fifa14-build-layout-v1"


def _resolved(path: Path) -> Path:
    return Path(path).expanduser().resolve()


def _validate_game_root(game_root: Path) -> Path:
    root = _resolved(game_root)
    if not root.is_dir():
        raise NotADirectoryError(f"game root is not a directory: {root}")
    try:
        with os.scandir(root):
            pass
    except OSError as error:
        raise OSError(f"game root is unreadable: {root}: {error}") from error
    return root


def _error_result(status: str, error: Exception | str, **metadata: object) -> dict[str, object]:
    message = str(error)
    if isinstance(error, Exception):
        message = f"{type(error).__name__}: {message}"
    return {"status": status, **metadata, "error": message}


def _archive_paths(root: Path, name: str) -> tuple[Path, Path]:
    return root / f"{name}.big", root / f"{name}.bh"


def _archive_missing(root: Path, name: str) -> dict[str, object] | None:
    big_path, bh_path = _archive_paths(root, name)
    missing = [path.name for path in (big_path, bh_path) if not path.is_file()]
    if not missing:
        return None
    return _error_result(
        "not-found",
        f"missing archive file(s): {', '.join(missing)}",
        files={
            big_path.name: {"path": str(big_path), "exists": big_path.is_file()},
            bh_path.name: {"path": str(bh_path), "exists": bh_path.is_file()},
        },
    )


def _scan_archive(root: Path, name: str) -> dict[str, object]:
    missing = _archive_missing(root, name)
    if missing is not None:
        return missing
    big_path, bh_path = _archive_paths(root, name)
    try:
        result = discover_archive_records(big_path, bh_path, (b"Apt Data",))
    except Exception as error:
        return _error_result("fail", error, files={"big": str(big_path), "bh": str(bh_path)})
    return {"status": "pass", "result": result}


def _scan_route(root: Path) -> dict[str, object]:
    missing = _archive_missing(root, "data1")
    if missing is not None:
        return missing
    try:
        result = discover_route_record(root)
    except Exception as error:
        big_path, bh_path = _archive_paths(root, "data1")
        return _error_result("fail", error, files={"big": str(big_path), "bh": str(bh_path)})
    return {"status": "pass", "result": result}


def _scan_native(root: Path, name: str) -> dict[str, object]:
    path = root / name
    if not path.is_file():
        return _error_result("not-found", f"native module was not found: {path}", path=str(path), exists=False)
    targets = FIFA14_TARGETS if name == "fifa14.exe" else CARDS_TARGETS
    try:
        result = scan_native_targets(path, targets)
    except Exception as error:
        return _error_result("fail", error, path=str(path), exists=True)
    result["status"] = "pass"
    return result


def build_layout_report(game_root: Path) -> dict[str, object]:
    root = _validate_game_root(game_root)
    binaries = fingerprint_game_root(root)
    hash_tuple = complete_hash_tuple(binaries)
    return {
        "schema": SCHEMA,
        "gameRoot": str(root),
        "readOnly": True,
        "profile": classify_hash_tuple(hash_tuple),
        "hashTuple": list(hash_tuple) if hash_tuple is not None else None,
        "binaries": binaries,
        "route": _scan_route(root),
        "archives": {
            "cards0": _scan_archive(root, "cards0"),
            "patch": _scan_archive(root, "patch"),
        },
        "native": {
            "fifa14.exe": _scan_native(root, "fifa14.exe"),
            "CardsDLLzf.dll": _scan_native(root, "CardsDLLzf.dll"),
        },
    }


def write_layout_report(game_root: Path, output: Path) -> dict[str, object]:
    root = _validate_game_root(game_root)
    destination = _resolved(output)
    if destination == root or root in destination.parents:
        raise ValueError("layout report output must not be inside the FIFA game root")
    report = build_layout_report(root)
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
    parser = _JsonArgumentParser(description="Read-only FIFA 14 build layout discovery")
    parser.add_argument("--game-root", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/fifa14-build-layout-v1.json"),
    )
    args = parser.parse_args()
    try:
        report = write_layout_report(args.game_root, args.output)
    except Exception as error:
        print(json.dumps({"error": str(error), "type": type(error).__name__}), file=sys.stderr)
        return 1
    print(json.dumps({"output": str(_resolved(args.output)), "profile": report["profile"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
