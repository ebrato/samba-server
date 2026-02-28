#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${ROOT_DIR}/release/bin/smb_cli"
if [[ ! -x "${BIN}" ]]; then
  BIN="${ROOT_DIR}/dist/bin/smb_cli"
fi
PORT="${SMB_TEST_PORT:-14570}"
WORK_DIR="${SMB_TEST_WORKDIR:-/tmp/smb_interop_test}"
AUTH_USER="${SMB_TEST_USERNAME:-operador}"
AUTH_PASS="${SMB_TEST_PASSWORD:-senhaForte123}"

if [[ ! -x "${BIN}" ]]; then
  echo "[error] missing binary: ${BIN} (run 'zig build native' first)"
  exit 1
fi

if ! command -v smbclient >/dev/null 2>&1; then
  echo "[error] smbclient not found in PATH"
  exit 1
fi

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"
printf 'hello-from-smbclient\n' > "${WORK_DIR}/local.txt"

run_case() {
  local label="$1"
  local server_args="$2"
  local client_cmd="$3"

  "${BIN}" serve --share-dir "${WORK_DIR}" --once --port "${PORT}" ${server_args} > "${WORK_DIR}/${label}.server.log" 2>&1 &
  local pid=$!
  sleep 0.35
  set +e
  bash -lc "${client_cmd}" > "${WORK_DIR}/${label}.client.log" 2>&1
  local rc=$?
  set -e
  wait "${pid}" || true

  if [[ "${rc}" -ne 0 ]]; then
    echo "[fail] ${label} rc=${rc}"
    echo "--- ${label}.client.log ---"
    sed -n '1,200p' "${WORK_DIR}/${label}.client.log" || true
    echo "--- ${label}.server.log ---"
    sed -n '1,200p' "${WORK_DIR}/${label}.server.log" || true
    return 1
  fi

  echo "[ok] ${label}"
}

echo "[suite] anonymous"
run_case "anon_list" "--allow-anonymous" "smbclient -L //127.0.0.1 -p ${PORT} -N -m SMB3"
run_case "anon_ls" "--allow-anonymous" "smbclient //127.0.0.1/share -p ${PORT} -N -m SMB3 -c 'ls'"
run_case "anon_put" "--allow-anonymous" "smbclient //127.0.0.1/share -p ${PORT} -N -m SMB3 -c 'put ${WORK_DIR}/local.txt uploaded-anon.txt'"
run_case "anon_get" "--allow-anonymous" "smbclient //127.0.0.1/share -p ${PORT} -N -m SMB3 -c 'get uploaded-anon.txt ${WORK_DIR}/downloaded-anon.txt'"

echo "[suite] authenticated"
run_case "auth_ls" "--username ${AUTH_USER} --password ${AUTH_PASS}" "smbclient //127.0.0.1/share -p ${PORT} -U '${AUTH_USER}%${AUTH_PASS}' -m SMB3 -c 'ls'"
run_case "auth_put" "--username ${AUTH_USER} --password ${AUTH_PASS}" "smbclient //127.0.0.1/share -p ${PORT} -U '${AUTH_USER}%${AUTH_PASS}' -m SMB3 -c 'put ${WORK_DIR}/local.txt uploaded-auth.txt'"
run_case "auth_get" "--username ${AUTH_USER} --password ${AUTH_PASS}" "smbclient //127.0.0.1/share -p ${PORT} -U '${AUTH_USER}%${AUTH_PASS}' -m SMB3 -c 'get uploaded-auth.txt ${WORK_DIR}/downloaded-auth.txt'"

if [[ "${SMB_TEST_LEGACY_NTLM:-1}" == "1" ]]; then
  echo "[suite] authenticated-legacy-ntlm"
  run_case "auth_legacy_ls" "--username ${AUTH_USER} --password ${AUTH_PASS}" \
    "smbclient //127.0.0.1/share -p ${PORT} -U '${AUTH_USER}%${AUTH_PASS}' -m SMB3 --option=clientntlmv2auth=no -c 'ls'"
fi

echo "[ok] smbclient interoperability suite passed"
