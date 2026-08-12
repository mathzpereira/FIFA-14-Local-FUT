# Design: FIFA 14 Build 14.2.1468411 Port

## Goal

Support the user's legitimate FIFA 14 PC build without weakening the exact-build safety guard or changing the existing supported build. Milestone 1 is the normal local launch through the FUT hub with a stable local connection. Milestone 2 adds matches and tournaments only after their native contracts are verified.

## Current Findings

- The user's `fifa14.exe` has SHA-256 `3B8C128CA34F5E1E568740BA8C1E789C5C32779ADC3CECBE171AE4A4658760E2`, file version `1,2,0,0`, and product version `14.2.1468411`.
- The user's `CardsDLLzf.dll` and `powdllzf.dll` also differ from the repository's validated hashes. This is a complete alternate client build, not an isolated executable mismatch.
- `tools/run_fifa14_local_beta.ps1` currently fails closed before patching when any of the three hashes is unknown.
- The Frida tracer contains build-specific RVAs and byte signatures. Archive patchers also contain exact record indexes, offsets, capacities, and content hashes.
- The local server and catalog/SQLite layers are mostly independent of native client addresses and can remain shared.

## Architecture

Add a separate client-build profile selected by the complete hash tuple, never by the executable hash alone. A profile contains the three binary hashes, file/module metadata, validated archive identities, and the native RVA/signature data required by each enabled patch or hook.

The launcher flow becomes:

1. Resolve and validate the FIFA `Game` directory.
2. Fingerprint `fifa14.exe`, `CardsDLLzf.dll`, and `powdllzf.dll`.
3. Select a known profile or stop with an actionable unsupported-build report.
4. Run read-only archive and signature checks for the features requested by that profile.
5. Apply only verified archive patches, retaining the existing backup/restore behavior.
6. Start the local backend and Frida helper with the selected profile.
7. Refuse to attach if any runtime signature check fails.

The original profile remains unchanged. Unknown or partially matching builds remain blocked.

## Implementation Stages

### Stage 1: Read-only diagnostics

Add a Windows-compatible diagnostic command that writes an ignored JSON report under `artifacts/`. It records binary hashes and versions, archive/BH layouts, required FUT asset records, and the signature results needed by each candidate feature group. It must not write to the FIFA installation or alter SQLite state.

### Stage 2: Static patch profile

Use the diagnostic results to add profile-specific identities for the branch route, login popup, dynamic route, and other archive patches. Each patch must support scan, verify, apply, and restore modes and must fail closed on an unrecognized record.

### Stage 3: Native hook profile

Port the tracer one hook group at a time. Each group gets a profile-specific RVA and signature check, with disabled groups reported explicitly rather than silently using offsets from the original build. The Milestone 1 profile requires authentication, redirector, FUT HTTP, and FUT navigation hooks; it must not claim match or tournament support until the gameplay hooks are validated.

### Stage 4: Runtime verification

Run the existing source/catalog checks first, then the selected static verifiers, then a real Windows flow: launch, reach the normal menu, enter FUT, confirm backend ownership, and close FIFA cleanly. For gameplay changes, record the exact FUT flow and whether the client stayed connected afterward.

## Safety And Failure Handling

- Never replace the expected hashes with the user's hashes without validating all dependent offsets and signatures.
- Never use a fuzzy hash match or continue after a failed signature check.
- Keep all game-file backups and temporary `cl.ini` restoration behavior intact.
- Do not commit executables, DLLs, archives, credentials, certificates, or diagnostic data copied from the game installation.
- Do not reset the persistent SQLite profile while diagnosing the client build.

## Success Criteria

- The original supported build still passes its existing guard and verifiers.
- The user's full hash tuple selects the new profile only after all required static checks pass.
- The launcher produces a clear report for unsupported or partially ported feature groups.
- Milestone 1: the user's client reaches the local FUT hub without an unsupported-hook error, archive corruption, or forced bypass of the safety guard, and remains connected after entering FUT.
- Milestone 2: a documented match/tournament flow settles correctly and remains connected after returning to FUT.

## Non-Goals

- Supporting every FIFA 14 distribution automatically.
- Making the launcher run by disabling the exact-build guard.
- Guessing RVAs from version numbers or copying offsets from the original profile.
- Shipping or requesting proprietary game binaries in the repository.
