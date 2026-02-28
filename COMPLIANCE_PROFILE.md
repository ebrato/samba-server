# Compliance Profile (MISRA + DbC + ISO-Oriented Baseline)

## Scope
- Applies to `smb.cpp`, `build.zig`, `quality_gate.sh`, `qca.sh`, and deploy examples in `deploy/`.
- Goal is a hardened engineering baseline for portable SMB2/SMB3 negotiation services.

## Design by Contract (DbC)
- Contracts are enabled with `SMB_ENABLE_CONTRACTS=1`.
- Preconditions, postconditions, and invariants:
  - `SMB_EXPECT(...)`
  - `SMB_ENSURE(...)`
  - `SMB_INVARIANT(...)`
- Contract violations fail fast via `contract_fail(...)` to prevent undefined behavior propagation.

## MISRA-Oriented Practices (C++ baseline)
- Enforced through strict compiler diagnostics in `quality_gate.sh`:
  - `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror`
- Defensive programming controls:
  - Explicit bounds checks before parsing SMB structures.
  - Checked integer conversion paths for protocol fields.
  - Fixed-size packed protocol structures with `static_assert`.
  - Explicit endianness conversions for all wire-visible integers.
  - Size-limited framing (`kSmbMaxFrameBytes`) and connection/request caps.

## Security Hardening Baseline
- Protocol parser rejects invalid structure sizes and malformed buffers.
- Compound requests (`next_command != 0`) are rejected to reduce parser complexity.
- Unsupported commands return explicit SMB status, then close the connection.
- `SESSION_SETUP` enforces NTLMv2 and rejects legacy auth paths (NTLMv1/NTLM2-session).
- `SESSION_SETUP` with plaintext blob (`USER=...;PASS=...`) is rejected.
- Runtime rejects weak credentials in auth mode (minimum password length policy).
- Failed authentication attempts are tracked per IP with temporary blocking windows.
- Per-IP concurrent connection limits are enforced before request processing.
- Signed authenticated sessions apply replay protection (`message_id` duplicate rejection).
- Server challenge and GUID generation use OS CSPRNG sources.
- CSPRNG failures are handled in fail-secure mode (auth denied / connection closed or startup aborted).
- File-serving operations implemented with state validation: `TREE_CONNECT`, `CREATE`, `WRITE`, `READ`, `CLOSE`.
- Share path handling is constrained to `--share-dir` with path normalization and traversal rejection.
- Dotfiles are denied by default and overwrite dispositions are opt-in to reduce risky write paths.
- Per-connection/file limits (`max-open-files`, `max-file-size`) are enforced to reduce resource exhaustion risk.
- Socket receive/send timeouts and keepalive are enabled to mitigate resource exhaustion.
- Concurrent client limit is enforced (`kMaxConcurrentClients`).

## Verification Baseline
- `quality_gate.sh` validates strict build, self-test and sanitizer execution.
- `qca.sh` validates negative config checks and runtime security scenarios:
  - signing required vs unsigned client;
  - brute-force temporary blocking by IP;
  - per-IP concurrent connection limit.
- Runtime/interop checks are environment-dependent and can be marked required via `QCA_REQUIRE_RUNTIME=1`.

## ISO / Defense-Oriented Mapping (engineering baseline)
- `ISO/IEC 14882` (C++ language conformance): modern C++17 subset and strict diagnostics.
- `ISO/IEC/IEEE 12207` (lifecycle): scripted build/test gate (`quality_gate.sh`) for repeatable verification.
- `ISO/IEC 27001` (security management alignment): secure defaults and minimized attack surface.
- `ISO/IEC 25010` (quality model): focus on reliability, security, and maintainability attributes.

## Important Certification Note
- This repository now has a stronger compliance-oriented baseline, but it is **not certified** against MISRA, ISO, or military standards by patch alone.
- Formal compliance/certification still requires:
  - Independent static analysis tool qualification and reports.
  - Full threat modeling, secure SDLC evidence, and traceability matrices.
  - Third-party audit/certification process with documented test coverage.
- Security posture still depends on operational controls outside this repository (network segmentation, firewall allowlist, hardened host, centralized logging).
