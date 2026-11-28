#!/usr/bin/env bash
# End-to-end tests for the pi-bitwarden extension, fully headless:
# mock bw CLI + mock zenity + mock clipboard (see test/mocks/).
#
# Each scenario runs a real `pi --no-session --mode json` session in a fresh
# temp dir and asserts on TOOL RESULT EVENTS, never on the model's prose
# (models paraphrase or hallucinate summaries; tool events are authoritative).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export BW_MOCK_DIR="$(mktemp -d /tmp/pi-bw-test.XXXXXX)"
export PATH="$ROOT/test/mocks/bin:$PATH"
PI="${PI_BIN:-pi}"
MODEL_ARGS=()
[[ -n "${PI_MODEL:-}" ]] && MODEL_ARGS=(--model "$PI_MODEL")
PASS=0; FAIL=0

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
check() { # check <description> <haystack-file> <grep-args...>
	local desc="$1" hay="$2"; shift 2
	if grep -q "$@" "$hay"; then ok "$desc"; else bad "$desc (wanted: $*)"; fi
}
count_eq() { # count_eq <description> <file> <expected> <pattern>
	local desc="$1" file="$2" want="$3" pat="$4"
	local got; got=$(grep -c -- "$pat" "$file" 2>/dev/null || true)
	[[ -z "$got" ]] && got=0
	[[ "$got" == "$want" ]] && ok "$desc ($got)" || bad "$desc (got $got, want $want)"
}

# pi --mode json output -> normalized tool-result lines: "TOOL <name> OK|ERR <text>"
normalize_events() {
	python3 "$ROOT/test/normalize_events.py"
}

# run_scenario <name> <env-passthrough (may be empty)> <prompt...>
run_scenario() {
	local name="$1" envs="$2"; shift 2
	local cwd; cwd="$(mktemp -d "$BW_MOCK_DIR/cwd-$name.XXXX")"
	( cd "$cwd" && env $envs timeout 300 "$PI" --no-session --no-extensions \
		-e "$ROOT/bitwarden.ts" "${MODEL_ARGS[@]}" --mode json -p "$*" 2>&1 ) \
		| normalize_events > "$BW_MOCK_DIR/$name.events"
	# An empty event stream would make every negative assertion pass vacuously.
	if ! grep -q '^TOOL ' "$BW_MOCK_DIR/$name.events"; then
		bad "scenario $name produced no tool events (extension load or provider failure?)"
	fi
}

# ---------------------------------------------------------------- S0: unit
say "S0: scrubber unit tests (deterministic)"
if command -v bun >/dev/null 2>&1; then
	if bun test "$ROOT/test/scrub.test.ts"; then ok "scrubber unit tests"; else bad "scrubber unit tests"; fi
else
	printf '  SKIP bun not found (install bun to run the unit tests)\n'
fi

# ---------------------------------------------------------------- S1: load
say "S1: extension loads, bash override intact"
run_scenario s1 "" "Use the bash tool to run exactly: echo BWEXT_OK"
check "extension loads + bash works" "$BW_MOCK_DIR/s1.events" -q "TOOL bash OK .*BWEXT_OK"

# ------------------------------------------------- S2: unauthenticated hint
say "S2: friendly hint when bw CLI not logged in (no password prompt)"
rm -f "$BW_MOCK_DIR/pw-prompts"
run_scenario s2 "BW_MOCK_UNAUTH=1" "Call bw_list"
check "friendly not-logged-in hint" "$BW_MOCK_DIR/s2.events" -q "TOOL bw_list ERR .*not logged in"
count_eq "no master-password prompt" "$BW_MOCK_DIR/pw-prompts" "0" "."

# ------------------------------------------------- S3: happy path, one unlock
say "S3: list → inject → env → clipboard (ONE unlock)"
rm -f "$BW_MOCK_DIR/pw-prompts" "$BW_MOCK_DIR/unlocks" "$BW_MOCK_DIR/clipboard" "$BW_MOCK_DIR/clipboard.copies"
# Scrubber encodings are covered deterministically by test/scrub.test.ts; this
# scenario proves the real bash tool sees the injected variable.
run_scenario s3 "" "Do exactly these steps in order:
1) bw_list
2) bw_inject item TestService field password env T1
3) bash: echo LEN=\${#T1}
4) bw_clipboard item TestService"
check "bw_list shows items, not passwords" "$BW_MOCK_DIR/s3.events" -q "TOOL bw_list OK .*user: alice"
check "bw_list leaks no password" "$BW_MOCK_DIR/s3.events" -v -q "supersecret-value-123"
check "inject confirms env var" "$BW_MOCK_DIR/s3.events" -q "TOOL bw_inject OK .*Injected \$T1"
check "env var really injected (LEN=21)" "$BW_MOCK_DIR/s3.events" -q "TOOL bash OK .*LEN=21"
check "clipboard tool confirms" "$BW_MOCK_DIR/s3.events" -q "TOOL bw_clipboard OK .*Copied \"TestService\""
check "clipboard really received secret" "$BW_MOCK_DIR/clipboard.copies" -q "supersecret-value-123"
count_eq "master password prompted ONCE per session" "$BW_MOCK_DIR/pw-prompts" "1" "."
count_eq "bw unlock ran ONCE per session" "$BW_MOCK_DIR/unlocks" "1" "."

# ------------------------------------------------- S4: deny path fail-closed
say "S4: user declines → fail closed"
run_scenario s4 "BW_MOCK_DENY=1" "Call bw_inject item TestService field password env D1"
check "inject declined" "$BW_MOCK_DIR/s4.events" -q "TOOL bw_inject ERR .*User declined the injection"
check "nothing injected on deny" "$BW_MOCK_DIR/s4.events" -v -q "TOOL bw_inject OK"

say "S4b: reveal declined"
run_scenario s4b "BW_MOCK_DENY=1" "Call bw_reveal item TestService field password reason test"
check "reveal declined" "$BW_MOCK_DIR/s4b.events" -q "TOOL bw_reveal ERR .*User declined the reveal"

# ------------------------------------------------- S5: reveal allow path
say "S5: bw_reveal allow path (confirmation mocked to allow)"
run_scenario s5 "" "Call bw_reveal item TestService field field:API_KEY reason citest"
check "reveal returned secret in tags" "$BW_MOCK_DIR/s5.events" -q "TOOL bw_reveal OK .*<secret>hf_sk-abc987xyz456</secret>"

# ------------------------------------------------- S6: bw_run one-shot env
say "S6: bw_run runs one command with \$VAULT_SECRET"
rm -f "$BW_MOCK_DIR/pw-prompts" "$BW_MOCK_DIR/unlocks"
run_scenario s6 "" 'Call bw_run with item TestService, field password, and command: echo LEN=${#VAULT_SECRET}; printenv VAULT_SECRET'
check "bw_run sees the secret" "$BW_MOCK_DIR/s6.events" -q "TOOL bw_run OK .*LEN=21"
# Output scrubbing is deterministic in test/scrub.test.ts; models sometimes
# rewrite "printenv" into a non-printing check of their own.
check "no raw secret from bw_run" "$BW_MOCK_DIR/s6.events" -v -q "supersecret-value-123"

# ------------------------------------------------- summary
say "RESULT: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
	echo "events and mocks kept for debugging: $BW_MOCK_DIR"
else
	rm -rf "$BW_MOCK_DIR"
fi
[[ "$FAIL" -eq 0 ]]
