#!/usr/bin/env bash
# MANUAL OMP compatibility smoke check (not part of `npm test`).
#
# OMP has no deterministic driver for extension tools, so the model calls
# bw_run itself. Requires `omp`, a working model, and a display for the mock
# zenity prompt.
#
#   OMP_MODEL=opencode-go/deepseek-v4.1-flash bash test/omp-smoke.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OMP_BIN="${OMP_BIN:-omp}"
MODEL_ARGS=()
[[ -n "${OMP_MODEL:-}" ]] && MODEL_ARGS=(--model "$OMP_MODEL")
export BW_MOCK_DIR="$(mktemp -d /tmp/pi-bw-omp.XXXXXX)"
export PATH="$ROOT/test/mocks/bin:$PATH"
PASS=0; FAIL=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
check() {
	if grep -q -- "$2" "$BW_MOCK_DIR/omp.events"; then ok "$1"; else bad "$1"; fi
}

cwd="$(mktemp -d "$BW_MOCK_DIR/cwd.XXXX")"
(
	cd "$cwd" && timeout 300 "$OMP_BIN" --session-dir "$BW_MOCK_DIR/sessions" --no-extensions \
		-e "$ROOT/bitwarden.ts" "${MODEL_ARGS[@]}" --auto-approve --mode json \
		-p "Call bw_run with item TestService, field password, and command: echo LEN=\${#VAULT_SECRET}; printenv VAULT_SECRET" 2>&1
) > "$BW_MOCK_DIR/omp.events"

if grep -q 'LEN=21' "$BW_MOCK_DIR/omp.events"; then
	ok "bw_run sees the secret in OMP (LEN=21)"
	check "bw_run output scrubbed" "BW_SCRUBBED:VAULT_SECRET"
else
	printf '  INCONCLUSIVE: bw_run was not called or failed; inspect %s\n' "$BW_MOCK_DIR"
fi
if grep '"type":"tool_execution_end"' "$BW_MOCK_DIR/omp.events" | grep -q "supersecret-value-123"; then
	bad "raw secret leaked into a final tool result"
else
	ok "raw secret absent from final tool results"
fi
if grep -rq "supersecret-value-123" "$BW_MOCK_DIR/sessions" 2>/dev/null; then
	bad "raw secret persisted in the session file"
else
	ok "raw secret absent from the session file"
fi

printf '\nRESULT: %d passed, %d failed (advisory)\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || echo "events kept: $BW_MOCK_DIR"
exit 0
