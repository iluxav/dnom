#!/usr/bin/env bash
# Tests dnom's webhook alerts end to end on this machine: a local listener (127.0.0.1) and
# the synthetic fake-exfil recording replayed with --notify. No sudo, no model, nothing
# leaves the machine. Exit 1 on any FAIL.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO"
BIN=target/release/dnom
T=$(mktemp -d /tmp/dnom-notify-test.XXXXXX)
listener=
cleanup() { [[ -n $listener ]] && kill "$listener" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
fail=0
check() { if eval "$2"; then echo "PASS: $1"; else echo "FAIL: $1"; fail=1; fi; }

start_listener() { # extra listener args...
  [[ -n $listener ]] && kill "$listener" 2>/dev/null && wait "$listener" 2>/dev/null
  rm -f "$T/port" "$T/alerts.jsonl"
  python3 -I lab/notify/listener.py --port 0 --port-file "$T/port" --token test-token --out "$T/alerts.jsonl" "$@" > "$T/listener.log" 2>&1 &
  listener=$!
  for _ in $(seq 50); do [[ -s $T/port ]] && break; sleep 0.1; done
  sed -e "s|^  url: \"\".*|  url: \"http://127.0.0.1:$(cat "$T/port")/events/dnom_threat\"|" dnom.yaml > "$T/dnom.yaml"
  grep -q '^  url: "http://127.0.0.1:' "$T/dnom.yaml" || { echo "FAIL: could not set notify.url in a copy of dnom.yaml"; exit 1; }
}
replay() { # name token extra classify args...
  local name=$1 token=$2; shift 2
  DNOM_NOTIFY_TOKEN=$token "$BIN" classify --config "$T/dnom.yaml" --backend none --input lab/replay/fake-exfil.jsonl \
    --learn 0 --remote-source --state-dir "$T/state-$name" "$@" > "$T/$name.out" 2> "$T/$name.err"
}
alerts() { [[ -f $T/alerts.jsonl ]] && wc -l < "$T/alerts.jsonl" || echo 0; }

# 1. Delivered, with the token; the listener rejects the first request, so dnom has to retry.
start_listener --fail 1
replay ok test-token --notify; rc=$?
check "the alert arrives after one failed attempt (retry), and dnom exits 0" '[[ $rc == 0 && $(alerts) == 1 ]] && grep -q "will retry" "$T/ok.err"'
check "payload: path, event, rules, summary, readable report, episode" \
  'jq -e ".path == \"/events/dnom_threat\" and .alert.source == \"dnom\" and .alert.event == \"threat\" and .alert.dry_run == true
          and (.alert.rules | index(\"credentials-then-new-destination\") != null) and (.alert.summary | test(\"fake-exfil.sh\"))
          and (.alert.report | test(\"What happened\")) and (.alert.episode.tree | length > 0) and (.alert.pid | type == \"number\")" "$T/alerts.jsonl" >/dev/null'

# 2. A replay without --notify sends nothing.
start_listener
replay quiet test-token
check "a replay without --notify sends nothing" '[[ $(alerts) == 0 ]]'

# 3. Wrong token: rejected by the receiver, reported by dnom, and dnom still exits 0.
replay wrong wrong-token --notify; rc=$?
check "a wrong token is rejected and reported; dnom still exits 0" '[[ $rc == 0 && $(alerts) == 0 ]] && grep -q "HTTP 401" "$T/wrong.err" && grep -q "not delivered" "$T/wrong.err"'

# 4. The token variable is named but not set: refuse to start rather than send without one.
(unset DNOM_NOTIFY_TOKEN; cd "$T" && "$REPO/$BIN" classify --config "$T/dnom.yaml" --backend none --input "$REPO/lab/replay/fake-exfil.jsonl" \
  --learn 0 --remote-source --state-dir "$T/state-unset" --notify > /dev/null 2> "$T/unset.err"); rc=$?
check "a missing token variable stops dnom at startup" '[[ $rc != 0 ]] && grep -q "DNOM_NOTIFY_TOKEN is not set" "$T/unset.err"'

# 5. Receiver down: dnom carries on, and the alert is still in the audit log.
kill "$listener" 2>/dev/null; wait "$listener" 2>/dev/null; listener=
replay down test-token --notify; rc=$?
check "receiver down: dnom exits 0, says so, and the alert is in the audit log" \
  '[[ $rc == 0 ]] && grep -q "not delivered" "$T/down.err" && "$BIN" audit --threats --state-dir "$T/state-down" | grep -q "THREAT credentials-then-new-destination"'

[[ $fail == 0 ]] && echo "all passed" || { echo "some checks FAILED (logs were in $T)"; exit 1; }
