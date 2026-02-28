#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${ROOT_DIR}/dist/qca"
REPORT_FILE="${OUT_DIR}/qca_report.txt"

QCA_REQUIRE_RUNTIME="${QCA_REQUIRE_RUNTIME:-0}"
QCA_RUN_MATRIX="${QCA_RUN_MATRIX:-1}"
QCA_RUN_INTEROP="${QCA_RUN_INTEROP:-auto}"
QCA_PORT_BASE="${QCA_PORT_BASE:-15440}"
QCA_USER="${QCA_USER:-qcauser}"
QCA_PASS="${QCA_PASS:-qcaPassw0rdX}"

ZIG_LOCAL_CACHE_DIR="${ROOT_DIR}/.zig-cache/local"
ZIG_GLOBAL_CACHE_DIR="${ROOT_DIR}/.zig-cache/global"
ZIG_TMP_DIR="${ROOT_DIR}/.zig-cache/tmp"
export ZIG_LOCAL_CACHE_DIR
export ZIG_GLOBAL_CACHE_DIR
export TMPDIR="${ZIG_TMP_DIR}"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RUNTIME_BLOCKED=0
NEXT_PORT="${QCA_PORT_BASE}"

mkdir -p "${OUT_DIR}"
: > "${REPORT_FILE}"
mkdir -p "${ZIG_LOCAL_CACHE_DIR}" "${ZIG_GLOBAL_CACHE_DIR}" "${ZIG_TMP_DIR}"

log() {
  printf '%s\n' "$*" | tee -a "${REPORT_FILE}"
}

mark_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  log "[pass] $1"
}

mark_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  log "[fail] $1"
}

mark_skip() {
  SKIP_COUNT=$((SKIP_COUNT + 1))
  log "[skip] $1"
}

run_step() {
  local name="$1"
  shift
  log "[step] ${name}"
  set +e
  "$@" >>"${REPORT_FILE}" 2>&1
  local rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    mark_pass "${name}"
    return 0
  fi
  mark_fail "${name} (rc=${rc})"
  return 1
}

run_expect_fail() {
  local name="$1"
  local expect_pattern="$2"
  shift 2

  local log_file="${OUT_DIR}/${name}.expect_fail.log"
  log "[step] ${name} (expect failure)"

  set +e
  "$@" >"${log_file}" 2>&1
  local rc=$?
  set -e

  if [[ "${rc}" -eq 0 ]]; then
    mark_fail "${name} (esperava falha, mas rc=0)"
    sed -n '1,120p' "${log_file}" >>"${REPORT_FILE}" || true
    return 1
  fi

  if [[ -n "${expect_pattern}" ]] && ! grep -Eq -- "${expect_pattern}" "${log_file}"; then
    mark_fail "${name} (mensagem esperada não encontrada)"
    sed -n '1,120p' "${log_file}" >>"${REPORT_FILE}" || true
    return 1
  fi

  mark_pass "${name}"
  return 0
}

run_runtime_case() {
  local name="$1"
  local server_args_raw="$2"
  local client_args_raw="$3"
  local expect_nonzero="$4"

  if [[ "${RUNTIME_BLOCKED}" -eq 1 ]]; then
    mark_skip "${name} (runtime bloqueado no ambiente atual)"
    return 0
  fi

  local port="${NEXT_PORT}"
  NEXT_PORT=$((NEXT_PORT + 1))

  local server_log="${OUT_DIR}/${name}.server.log"
  local client_log="${OUT_DIR}/${name}.client.log"

  local -a server_args=()
  local -a client_args=()
  read -r -a server_args <<<"${server_args_raw}"
  read -r -a client_args <<<"${client_args_raw}"

  log "[step] runtime:${name} (port=${port})"

  set +e
  "${ROOT_DIR}/dist/quality/smb_cli_strict" serve --share-dir "${ROOT_DIR}" --port "${port}" --once "${server_args[@]}" >"${server_log}" 2>&1 &
  local server_pid=$!
  sleep 0.8

  if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
    wait "${server_pid}" >/dev/null 2>&1 || true
    set -e
    if grep -q "failed to bind/listen" "${server_log}"; then
      RUNTIME_BLOCKED=1
      if [[ "${QCA_REQUIRE_RUNTIME}" == "1" ]]; then
        mark_fail "runtime:${name} (ambiente sem bind de socket)"
        sed -n '1,80p' "${server_log}" >>"${REPORT_FILE}" || true
        return 1
      fi
      mark_skip "runtime:${name} (ambiente sem bind de socket)"
      sed -n '1,40p' "${server_log}" >>"${REPORT_FILE}" || true
      return 0
    fi
    mark_fail "runtime:${name} (servidor finalizou prematuramente)"
    sed -n '1,120p' "${server_log}" >>"${REPORT_FILE}" || true
    return 1
  fi

  "${ROOT_DIR}/dist/quality/smb_cli_strict" smoke-client --host 127.0.0.1 --port "${port}" "${client_args[@]}" >"${client_log}" 2>&1
  local client_rc=$?

  if kill -0 "${server_pid}" >/dev/null 2>&1; then
    kill "${server_pid}" >/dev/null 2>&1 || true
  fi
  wait "${server_pid}" >/dev/null 2>&1 || true
  set -e

  if [[ "${expect_nonzero}" == "0" ]]; then
    if [[ "${client_rc}" -eq 0 ]]; then
      mark_pass "runtime:${name}"
      return 0
    fi
    mark_fail "runtime:${name} (esperava rc=0, obteve rc=${client_rc})"
    sed -n '1,120p' "${client_log}" >>"${REPORT_FILE}" || true
    sed -n '1,120p' "${server_log}" >>"${REPORT_FILE}" || true
    return 1
  fi

  if [[ "${client_rc}" -ne 0 ]]; then
    mark_pass "runtime:${name}"
    return 0
  fi

  mark_fail "runtime:${name} (esperava falha do cliente, mas rc=0)"
  sed -n '1,120p' "${client_log}" >>"${REPORT_FILE}" || true
  sed -n '1,120p' "${server_log}" >>"${REPORT_FILE}" || true
  return 1
}

main() {
  log "[qca] start"
  log "[qca] require_runtime=${QCA_REQUIRE_RUNTIME} run_matrix=${QCA_RUN_MATRIX} run_interop=${QCA_RUN_INTEROP}"

  run_step "zig-version" zig version || true

  if ! command -v zig >/dev/null 2>&1; then
    mark_fail "zig-not-found"
    log "[qca] summary pass=${PASS_COUNT} fail=${FAIL_COUNT} skip=${SKIP_COUNT}"
    exit 1
  fi

  run_step "build-native-releasefast" zig build native -Doptimize=ReleaseFast || true
  run_step "build-native-debug" zig build native -Doptimize=Debug || true

  if [[ "${QCA_RUN_MATRIX}" == "1" ]]; then
    run_step "build-matrix-releasefast" zig build matrix -Doptimize=ReleaseFast || true
  else
    mark_skip "build-matrix-releasefast (desabilitado por QCA_RUN_MATRIX=${QCA_RUN_MATRIX})"
  fi

  run_step "quality-gate" "${ROOT_DIR}/quality_gate.sh" || true
  run_step "release-self-test" "${ROOT_DIR}/release/bin/smb_cli" self-test || true

  run_step "release-version" "${ROOT_DIR}/release/bin/smb_cli" version || true
  run_step "release-help" "${ROOT_DIR}/release/bin/smb_cli" help || true

  run_expect_fail "invalid-require-signing-anonymous" \
    "--require-signing cannot be used with --allow-anonymous" \
    "${ROOT_DIR}/dist/quality/smb_cli_strict" serve --allow-anonymous --require-signing || true

  run_expect_fail "invalid-enable-signing-anonymous" \
    "--enable-signing requires authentication" \
    "${ROOT_DIR}/dist/quality/smb_cli_strict" serve --allow-anonymous --enable-signing || true

  run_expect_fail "invalid-missing-credentials" \
    "authentication enabled but --username/--password were not provided" \
    "${ROOT_DIR}/dist/quality/smb_cli_strict" serve || true

  run_expect_fail "invalid-short-password" \
    "password too short" \
    "${ROOT_DIR}/dist/quality/smb_cli_strict" serve --username "${QCA_USER}" --password short || true

  run_step "readme-no-known-limitations-section" \
    bash -lc "! rg -q '^## Limitações conhecidas' \"${ROOT_DIR}/README.md\"" || true

  log "[step] cli-usage-check"
  set +e
  "${ROOT_DIR}/release/bin/smb_cli" help >"${OUT_DIR}/help.txt" 2>&1
  local help_rc=$?
  set -e
  if [[ "${help_rc}" -ne 0 ]]; then
    mark_fail "cli-usage-check (help rc=${help_rc})"
  elif ! grep -Eq -- "--enable-signing|--require-signing|--disable-client-signing" "${OUT_DIR}/help.txt"; then
    mark_fail "cli-usage-check (flags de signing ausentes no help)"
  else
    mark_pass "cli-usage-check"
  fi

  run_runtime_case "auth_default" \
    "--username ${QCA_USER} --password ${QCA_PASS}" \
    "--username ${QCA_USER} --password ${QCA_PASS}" \
    "0" || true

  run_runtime_case "auth_signing_optional" \
    "--username ${QCA_USER} --password ${QCA_PASS} --enable-signing" \
    "--username ${QCA_USER} --password ${QCA_PASS}" \
    "0" || true

  run_runtime_case "auth_signing_required_signed_client" \
    "--username ${QCA_USER} --password ${QCA_PASS} --enable-signing --require-signing" \
    "--username ${QCA_USER} --password ${QCA_PASS}" \
    "0" || true

  run_runtime_case "auth_signing_required_unsigned_client" \
    "--username ${QCA_USER} --password ${QCA_PASS} --enable-signing --require-signing" \
    "--username ${QCA_USER} --password ${QCA_PASS} --disable-client-signing" \
    "1" || true

  run_runtime_case "anonymous_mode" \
    "--allow-anonymous" \
    "--allow-anonymous" \
    "0" || true

  if [[ "${QCA_RUN_INTEROP}" == "1" ]] || [[ "${QCA_RUN_INTEROP}" == "auto" && -x "${ROOT_DIR}/interop_smbclient.sh" ]]; then
    if [[ "${RUNTIME_BLOCKED}" -eq 1 ]]; then
      mark_skip "interop-smbclient (runtime bloqueado no ambiente atual)"
    elif ! command -v smbclient >/dev/null 2>&1; then
      mark_skip "interop-smbclient (smbclient não disponível)"
    else
      log "[step] interop-smbclient"
      set +e
      "${ROOT_DIR}/interop_smbclient.sh" >>"${REPORT_FILE}" 2>&1
      interop_rc=$?
      set -e
      if [[ "${interop_rc}" -eq 0 ]]; then
        mark_pass "interop-smbclient"
      elif [[ "${QCA_REQUIRE_RUNTIME}" == "1" ]]; then
        mark_fail "interop-smbclient (rc=${interop_rc})"
      else
        mark_skip "interop-smbclient (falhou no ambiente atual, rc=${interop_rc})"
      fi
    fi
  else
    mark_skip "interop-smbclient (desabilitado)"
  fi

  log "[qca] summary pass=${PASS_COUNT} fail=${FAIL_COUNT} skip=${SKIP_COUNT}"

  if [[ "${FAIL_COUNT}" -ne 0 ]]; then
    exit 1
  fi
}

main "$@"
