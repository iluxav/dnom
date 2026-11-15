#!/usr/bin/env bash
# dnom on this machine as a background service, for a measurement over a day or more.
#
#   local.sh start    start collecting and classifying (asks for your password once)
#   local.sh status   is it running, what it uses, how much it has assessed
#   local.sh report   counts, and every episode a rule matched
#   local.sh stop     stop it (no password); the generated decoys are removed
#
# One transient systemd unit, dnom-local, with the same split as `make run`: the collector
# runs as root, the classifier as you. It is capped (1 GB memory, half a CPU core, low
# priority) and does not come back after a reboot: run `start` again.
#
# Everything lives in ~/.local/state/dnom/trial/:
#   dnom, dnom.yaml   the binary and the config as they were at `start`. Later builds and
#                     edits in the repo don't change the run, and opening the repo's
#                     dnom.yaml is not reported as config-touched.
#   baseline.json     known programs and destinations, seeded from the main state folder
#   assessments.jsonl the audit trail of this run only (kept across restarts)
#   classify.log      status lines; classify.out: the reports of matched episodes
#
# Env for start: BACKEND (default: the one in dnom.yaml), ONLY (limit a hosted model to
# episodes whose command contains this text). The key is read from the repo's .env.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
CMD=${1:-}
UNIT=dnom-local
T=$HOME/.local/state/dnom/trial
BIN=$T/dnom

say() { printf 'local: %s\n' "$*" >&2; }
running() { systemctl is-active --quiet "$UNIT"; }

start() {
  [[ -x $REPO/target/release/dnom ]] || { say "build first: make build"; exit 1; }
  running && { say "already running (local.sh status)"; exit 0; }
  mkdir -p "$T" && chmod 700 "$T"
  install -m 755 "$REPO/target/release/dnom" "$BIN"
  install -m 600 "$REPO/dnom.yaml" "$T/dnom.yaml"
  [[ -e $T/baseline.json || ! -e $HOME/.local/state/dnom/baseline.json ]] \
    || install -m 600 "$HOME/.local/state/dnom/baseline.json" "$T/baseline.json"

  local flags=(--matches-only --config "$T/dnom.yaml" --state-dir "$T")
  [[ -n ${BACKEND:-} ]] && flags+=(--backend "$BACKEND")
  if [[ -n ${ONLY:-} ]]; then flags+=(--only "$ONLY"); else flags+=(--allow-all-remote); fi
  # Run by the classifier's own user, after root is dropped. cwd is the repo for its .env.
  {
    printf '#!/bin/sh\ncd %q || exit 1\n' "$REPO"
    printf 'exec %q classify' "$BIN"; printf ' %q' "${flags[@]}"
    printf ' >> %q 2>> %q\n' "$T/classify.out" "$T/classify.log"
  } > "$T/classify.sh"
  chmod 700 "$T/classify.sh"

  local unit=(systemd-run --unit="$UNIT" --collect --quiet
    --description="dnom local trial (collector as root, classifier as $USER)"
    -p KillSignal=SIGINT -p TimeoutStopSec=20 -p MemoryMax=1G -p CPUQuota=50% -p Nice=10
    /bin/sh -c "$(printf '%q collect | setpriv --reuid=%d --regid=%d --init-groups --reset-env %q' \
      "$BIN" "$(id -u)" "$(id -g)" "$T/classify.sh")")
  # sudo where a password can be typed, otherwise the desktop's password dialog.
  if [[ -t 0 ]]; then sudo "${unit[@]}"; else pkexec "${unit[@]}"; fi
  for _ in $(seq 10); do
    grep -q 'sensors attached' <(journalctl -u "$UNIT" -n 20 --no-pager -o cat 2>/dev/null) && break
    sleep 1
  done
  status
}

status() {
  if running; then
    local m p c
    m=$(systemctl show "$UNIT" -p MemoryCurrent --value); p=$(systemctl show "$UNIT" -p MemoryPeak --value)
    c=$(systemctl show "$UNIT" -p CPUUsageNSec --value)
    [[ $m =~ ^[0-9]+$ ]] || m=0; [[ $p =~ ^[0-9]+$ ]] || p=0; [[ $c =~ ^[0-9]+$ ]] || c=0
    echo "running since $(systemctl show "$UNIT" -p ActiveEnterTimestamp --value)"
    echo "memory: $((m / 1048576)) MB now, $((p / 1048576)) MB peak (limit 1024 MB); CPU used: $((c / 1000000000)) s"
  else
    echo "not running"
  fi
  [[ -e $T/classify.log ]] && { echo "last status lines:"; tail -3 "$T/classify.log" | cut -c1-220 | sed 's/^/  /'; }
  return 0
}

report() {
  [[ -s $T/assessments.jsonl ]] || { say "nothing assessed yet in $T"; exit 0; }
  python3 -I - "$T/assessments.jsonl" <<'PY'
import collections, json, sys
last, ever = {}, collections.defaultdict(set)
first = final = None
for line in open(sys.argv[1], errors="replace"):
    try:
        r = json.loads(line)
    except ValueError:
        continue
    first = first or r["ts"]; final = r["ts"]
    last[r["episode_id"]] = r
    for m in r.get("policy") or []:
        ever[r["episode_id"]].add(m["rule"])
rules = collections.Counter(rule for s in ever.values() for rule in s)
print(f"{first} to {final}")
print(f"episodes assessed: {len(last)}; a rule matched in {len(ever)}")
for rule, n in rules.most_common():
    print(f"  {n:4d}  {rule}")
PY
  "$BIN" audit --threats --state-dir "$T"
}

stop() {
  running || { say "not running"; exit 0; }
  # The classifier is ours: on Ctrl-C it finishes, removes its decoys and exits. The
  # collector then stops on its closed pipe, and the unit ends.
  pkill -INT -u "$(id -u)" -f "^$BIN classify " || true
  for _ in $(seq 20); do running || break; sleep 1; done
  if running; then say "still running; stop it with: sudo systemctl stop $UNIT"; exit 1; fi
  say "stopped. State stays in $T"
}

case $CMD in
  start) start ;;
  status) status ;;
  report) report ;;
  stop) stop ;;
  *) sed -n '2,8p' "$0"; exit 2 ;;
esac
