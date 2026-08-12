# Repository Instructions

## Project Shape

- This is a Windows-first project; the root `.cmd` files wrap PowerShell, and the runtime depends on a legitimate FIFA 14 PC installation.
- `server/probe.py` is the local Blaze/TDF and FUT HTTP backend. It imports the identity stores and serves the localhost services used by the game.
- `server/local_identity.py` owns the stable FUT catalog, SQLite identity/club/items/market state, and catalog-derived payloads.
- `server/beta_identity.py` extends that store with the beta wallet, match settlement, offline seasons, and tournament progression. Its SQLite state is persistent across builds.
- Versioned JSON files under `server/` are runtime catalogs/fixtures. Preserve their FIFA 14 `assetId`/`resourceId`/`definitionId` relationships when editing them.
- `tools/*.ps1` handles Windows setup, launching, archive/database patching, restoration, and orchestration; `tools/*.py` handles state preparation, scans, patch helpers, and verifiers.

## Setup And Commands

- Run `INSTALL_PREREQUISITES.cmd` as Administrator to install/check Python 3.10+, Git/OpenSSL, and the project environment.
- Run `RUN_FIFA14_LOCAL_BETA.cmd` as Administrator for the normal flow. It resolves the FIFA 14 `Game` directory, creates/repairs `.venv`, validates the client build, starts the local backend, and launches FIFA.
- For manual setup, use `./tools/setup.ps1` and then `./tools/bootstrap.ps1`. A local path can be stored in the ignored `config.local.psd1` or supplied through `FIFA14_GAME_ROOT`.
- Use `.venv/Scripts/python.exe` for project checks after bootstrapping; dependencies are defined only in `requirements.txt` (`cryptography` and `frida`).
- The repository check is `python -m compileall -q server tools`. CI runs it on Windows with Python 3.13 and also parses every JSON file in the checkout outside `.git`, `.venv`, `artifacts`, and `dist`.
- The main source/catalog verifier is `python ./tools/verify_fifa14_v237_install.py`. Selected standalone `tools/verify_*.py` scripts are the focused checks used by the beta runner.
- There is no pytest configuration or general test suite; use the compile check, JSON validation, focused verifiers, and the documented FIFA runtime flow.

## Build Diagnostics

- Before adding a new client profile, run this read-only Windows diagnostic with the user's `Game` path:
  ```powershell
  & ".\.venv\Scripts\python.exe" ".\tools\diagnose_fifa14_build.py" `
      --game-root "D:\Jogos\FIFA 14\Game" `
      --output ".\artifacts\fifa14-build-diagnostic.json"
  ```
- Replace the example `--game-root` value as needed. The command writes `artifacts\fifa14-build-diagnostic.json`, does not make the launcher accept the new build, and the next port stage requires the JSON plus the user's runtime logs. Never copy binary data into the JSON output or the repository.

## Runtime Safety

- The launcher patches files in the installed FIFA directory. `tools/run_fifa14_local_beta.ps1` refuses unsupported `fifa14.exe`, `CardsDLLzf.dll`, or `powdllzf.dll` hashes; do not bypass that guard for an unknown client build.
- FIFA must be closed before direct archive/database patch or restore operations. The launcher also stops stale `fifa14.exe`/local helper processes and refuses conflicts on ports `42129`, `42128`, `8080`, `8099`, `8306`, and `44125`.
- The launcher temporarily changes `cl.ini` and restores it during cleanup. Investigate failed cleanup before starting another session rather than layering manual edits.
- `config.local.psd1`, `.venv`, `artifacts`, `logs`, `runtime`, `certs`, `state`, `reports`, `captures`, and `dist` are local/generated state and must not be committed.
- `tools/prepare_fifa14_beta_state.py --reset` deletes the selected persistent SQLite database. Use it only when an intentional fresh profile is required.
- `GIVE_100M_TEST_COINS.cmd` is an explicit developer test operation, not part of the normal/shared build. Do not use it when testing the default zero-coin economy.

## Change And Release Rules

- Treat server response shapes and catalog identities as retail-client contracts. Change them only with focused verifier coverage or an exact documented runtime test.
- For gameplay/runtime changes, record the exact FIFA/FUT flow tested and whether the client stayed connected afterward, as required by `CONTRIBUTING.md`.
- Never add FIFA executables, EA DLLs, game archives, credentials, private keys, certificates, or files copied from a user's installation.
- Run `PACKAGE_RELEASE.cmd` to create a clean ZIP under `dist/`; follow `RELEASING.md` for tagging and GitHub upload, and do not commit the generated ZIP.
