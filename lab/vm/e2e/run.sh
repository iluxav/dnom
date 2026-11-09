#!/usr/bin/env bash
# dnom end-to-end test in the lab VM.
#
# 1. Copies the release binary, the unit-test binary, the workloads, dnom.yaml and the
#    replay fixtures into the VM ($VMDIR).
# 2. Runs the unit tests inside the VM.
# 3. Runs `dnom collect` in the VM for $ROUNDS rounds; each round runs the benign workload
#    and the harmless fake-exfil simulation, then stops the collector with SIGINT.
# 4. Classifies round 1 on the host: without a model, and with Jev if a key is available
#    (only the two test episodes are sent; the key never enters the VM).
# 5. Replays the synthetic fixtures inside the VM.
# 6. verify.py checks everything and writes report.json.
#
# Results: ~/.local/state/dnom/vm-e2e/<timestamp>/ (outside the repo). Exit 1 on any FAIL.
# Env: ROUNDS (default 2), E2E_JEV=0 to skip Jev.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$REPO"
VM=lab/vm/vm.sh
VMDIR=/tmp/dnom-e2e
ROUNDS=${ROUNDS:-2}
R=$HOME/.local/state/dnom/vm-e2e/$(date -u +%Y%m%dT%H%M%SZ)
BIN=target/release/dnom

say() { printf 'e2e: %s\n' "$*" >&2; }
vm() { "$VM" ssh "$@"; }

stop_collector() {
  # Anchored so it matches only the collector, never this command or the ssh wrapper.
  vm "sudo pkill -INT -f '^$VMDIR/dnom collect' || true" </dev/null >/dev/null 2>&1 || true
}
cleanup() {
  stop_collector
  vm "rm -rf $VMDIR" </dev/null >/dev/null 2>&1 || true
}
trap cleanup EXIT

status=$("$VM" status 2>&1 || true)
[[ $status == *"vm: running"* ]] || { say "starting the VM"; "$VM" start; }

say "building"
cargo build --release --quiet
UNIT=$(cargo test -p dnom --no-run --message-format=json 2>/dev/null |
  jq -r 'select(.profile.test == true and .target.name == "dnom" and .executable != null) | .executable')
[[ -x $UNIT ]] || { say "unit-test binary not found"; exit 1; }

mkdir -p "$R"
say "results: $R"
stage=$(mktemp -d)
cp "$BIN" "$stage/dnom"
cp "$UNIT" "$stage/unit-tests"
cp lab/vm/e2e/benign.sh scripts/fake-exfil.sh dnom.yaml lab/replay/fake-exfil.jsonl lab/replay/fake-lateral.jsonl "$stage/"
say "copying to the VM ($VMDIR)"
tar -C "$stage" -cf - . | vm "rm -rf $VMDIR && mkdir -p $VMDIR && tar -C $VMDIR -xf -"
rm -rf "$stage"
vm "uname -r" </dev/null > "$R/kernel.txt"

say "unit tests in the VM"
vm "cd $VMDIR && ./unit-tests" </dev/null > "$R/unit-tests.log" 2>&1 || true

for n in $(seq 1 "$ROUNDS"); do
  d=$R/round$n
  mkdir -p "$d"
  say "round $n: collector + workloads"
  # timeout is only a safety net; the collector is stopped with SIGINT below.
  vm "sudo timeout --foreground --signal=INT --kill-after=5s 180s $VMDIR/dnom collect" \
    </dev/null > "$d/events.jsonl" 2> "$d/collector.log" &
  collector=$!
  for _ in $(seq 50); do grep -q 'snapshot of' "$d/collector.log" 2>/dev/null && break; sleep 0.2; done
  vm "exec bash $VMDIR/benign.sh" </dev/null > "$d/benign.log" 2>&1
  vm "exec bash $VMDIR/fake-exfil.sh" </dev/null > "$d/fake-exfil.log" 2>&1
  vm "cat $VMDIR/benign-result.json" </dev/null > "$d/benign-result.json"
  sleep 2   # the collector drains at least once a second
  stop_collector
  wait "$collector" || true
done

say "classifying round 1 on the host"
in=$R/round1/events.jsonl
common=(--remote-source --home /home/lab --input "$in" --learn 0 --json)
"$BIN" classify "${common[@]}" --backend none --state-dir "$R/state-none" \
  > "$R/episodes-none.jsonl" 2> "$R/classify-none.log"
if [[ ${E2E_JEV:-1} != 0 ]] && { [[ -n ${TYPESAFE_API_KEY:-} ]] || grep -q '^TYPESAFE_API_KEY=..*' .env 2>/dev/null; }; then
  "$BIN" classify "${common[@]}" --backend jev --only fake-exfil.sh --state-dir "$R/state-jev" \
    > "$R/episodes-jev.jsonl" 2> "$R/classify-jev.log" || true
  "$BIN" classify "${common[@]}" --backend jev --only benign.sh --state-dir "$R/state-jev-benign" \
    > "$R/episodes-jev-benign.jsonl" 2> "$R/classify-jev-benign.log" || true
else
  say "no Jev key (or E2E_JEV=0): Jev checks will be skipped"
fi

say "replaying the synthetic fixtures in the VM"
for fx in exfil lateral; do
  vm "cd $VMDIR && ./dnom classify --remote-source --backend none --input fake-$fx.jsonl --learn 0 --json \
      --state-dir replay-$fx > replay-$fx.jsonl 2> replay-$fx.log" </dev/null || true
  vm "cat $VMDIR/replay-$fx.jsonl" </dev/null > "$R/replay-$fx.jsonl"
  vm "cat $VMDIR/replay-$fx.log" </dev/null > "$R/replay-$fx.log"
done

git rev-parse HEAD > "$R/commit.txt"
git status --porcelain | grep -q . && echo dirty >> "$R/commit.txt" || true
python3 -I lab/vm/e2e/verify.py "$R" "$VMDIR" "$ROUNDS"
