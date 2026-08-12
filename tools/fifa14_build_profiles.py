from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys


SUPPORTED_V237_HASHES: tuple[str, str, str] = (
    "034991BCE371BB2D4E802184DC43E423B0FD7B6D06BF0E41EF12CA0DBC623916",
    "642B11EF3DA7EF28E55A40965A2F364012FA6090252A84C3D9BFBA5AB1F060E6",
    "AC39EE88E8F0D3A90C0C9EB3C01C030110F892EBA38EC52ED8AD05038C2B24F0",
)

_HASH_CHUNK_SIZE = 1024 * 1024
_POWDLL_RELATIVE_CANDIDATES = (
    Path("dlc") / "dlc_powdll" / "dlc" / "powdll" / "powdllzf.dll",
    Path("powdllzf.dll"),
)
_POWERSHELL_VERSION_INFO_COMMAND = (
    "$path = $args[0]; $item = Get-Item -LiteralPath $path; "
    "[PSCustomObject]@{ "
    "fileVersion = $item.VersionInfo.FileVersion; "
    "productVersion = $item.VersionInfo.ProductVersion "
    "} | ConvertTo-Json -Compress"
)


def _empty_result(name: str, path: Path, exists: bool) -> dict[str, object]:
    return {
        "name": name,
        "path": str(path),
        "exists": exists,
        "size": None,
        "sha256": None,
        "fileVersion": None,
        "productVersion": None,
    }


def _windows_version_info(path: Path) -> tuple[str | None, str | None]:
    if sys.platform != "win32":
        return None, None

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _POWERSHELL_VERSION_INFO_COMMAND,
                str(path),
            ],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None

    if completed.returncode != 0:
        return None, None

    try:
        version_info = json.loads(completed.stdout)
    except (TypeError, ValueError):
        return None, None
    if not isinstance(version_info, dict):
        return None, None

    def value(name: str) -> str | None:
        item = version_info.get(name)
        if item is None:
            return None
        text = str(item).strip()
        return text or None

    return value("fileVersion"), value("productVersion")


def fingerprint_binary(path: Path, name: str) -> dict[str, object]:
    resolved_path = Path(path).expanduser().resolve()
    try:
        is_file = resolved_path.is_file()
    except OSError:
        is_file = False
    if not is_file:
        return _empty_result(name, resolved_path, False)

    result = _empty_result(name, resolved_path, True)
    try:
        result["size"] = resolved_path.stat().st_size
        digest = hashlib.sha256()
        with resolved_path.open("rb") as stream:
            while chunk := stream.read(_HASH_CHUNK_SIZE):
                digest.update(chunk)
        result["sha256"] = digest.hexdigest().upper()
    except OSError as error:
        result["status"] = "fail"
        result["error"] = f"{type(error).__name__}: {error}"
        return result

    file_version, product_version = _windows_version_info(resolved_path)
    result["fileVersion"] = file_version
    result["productVersion"] = product_version
    return result


def fingerprint_game_root(game_root: Path) -> dict[str, object]:
    root = Path(game_root).expanduser().resolve()
    powdll_candidates = [root / relative for relative in _POWDLL_RELATIVE_CANDIDATES]
    powdll_path = next(
        (candidate for candidate in powdll_candidates if candidate.is_file()),
        powdll_candidates[0],
    )
    return {
        "fifa14.exe": fingerprint_binary(root / "fifa14.exe", "fifa14.exe"),
        "CardsDLLzf.dll": fingerprint_binary(root / "CardsDLLzf.dll", "CardsDLLzf.dll"),
        "powdllzf.dll": fingerprint_binary(powdll_path, "powdllzf.dll"),
    }


def complete_hash_tuple(fingerprint: dict[str, object]) -> tuple[str, str, str] | None:
    hashes: list[str] = []
    for name in ("fifa14.exe", "CardsDLLzf.dll", "powdllzf.dll"):
        binary = fingerprint.get(name)
        if not isinstance(binary, dict) or binary.get("exists") is not True:
            return None
        digest = binary.get("sha256")
        if not isinstance(digest, str) or not digest:
            return None
        hashes.append(digest)
    return hashes[0], hashes[1], hashes[2]


def classify_hash_tuple(values: tuple[str, str, str] | None) -> str:
    if values == SUPPORTED_V237_HASHES:
        return "supported-v237"
    return "unknown"
