#!/usr/bin/env bash
# dnom end-to-end test in the lab VM.
#
# 1. Copies the release binary, the unit-test binary, the workloads, dnom.yaml and the
#    replay fixtures into the VM ($VMDIR).
# 2. Runs the unit tests inside the VM.
# 3. Runs `dnom collect` in the VM for $ROUNDS rounds. Each round runs the benign workload,
#    the syscall-coverage workload (local files and loopback only), the harmless fake-exfil
#    simulation, one read of a decoy file, a few connection attempts to decoy addresses
#    (probe.sh), then a marker command after 8 s without workload, and stops the collector
#    with SIGINT.
# 4. Classifies round 1 on the host, with the decoy folder listed in a copy of dnom.yaml:
#    without a model (while `dnom monitor` watches the log), and with Jev if a key is
#    available (only the two test episodes are sent; the key never enters the VM).
#    `dnom audit` then prints the list and two episodes in full.
# 5. Replays the synthetic fixtures inside the VM.
# 6. Runs `dnom collect | dnom classify` live inside the VM, where classify generates decoys
#    (ssh, aws, env) in the lab user's home. Reads each one and the list of them, stops the
#    run, and checks the alerts and that every generated file is gone.
# 7. verify.py checks everything and writes report.json.
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
cp lab/vm/e2e/benign.sh lab/vm/e2e/syscalls.py lab/vm/e2e/probe.sh scripts/fake-exfil.sh dnom.yaml lab/replay/fake-exfil.jsonl lab/replay/fake-lateral.jsonl "$stage/"
# A decoy: planted before the collector starts, with a name no credential pattern matches,
# so only the decoy list can catch a read of it.
mkdir "$stage/decoy"
printf 'DECOY-NOT-A-REAL-CREDENTIAL\n' > "$stage/decoy/backup-credentials.txt"
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
  vm "exec python3 -I $VMDIR/syscalls.py $VMDIR" </dev/null > "$d/syscalls.log" 2>&1
  vm "exec bash $VMDIR/fake-exfil.sh" </dev/null > "$d/fake-exfil.log" 2>&1
  vm "exec cat $VMDIR/decoy/backup-credentials.txt" </dev/null > /dev/null
  vm "exec bash $VMDIR/probe.sh" </dev/null > /dev/null 2>&1
  vm "cat $VMDIR/benign-result.json" </dev/null > "$d/benign-result.json"
  vm "cat $VMDIR/syscalls-result.json" </dev/null > "$d/syscalls-result.json"
  # The collector must still deliver after a quiet period (regression: a lost ring buffer
  # wakeup once stalled it for good).
  vm "sleep 8; exec /usr/bin/true dnom-after-idle" </dev/null
  sleep 2   # the collector drains at least once a second
  stop_collector
  wait "$collector" || true
done

say "classifying round 1 on the host"
in=$R/round1/events.jsonl
sed -e "s|^  paths: \[.*|  paths: [\"$VMDIR/decoy/\"]|" \
    -e 's|^  addresses: \[.*|  addresses: ["127.0.0.1:6379", "198.51.100.77", "198.51.100.78"]|' dnom.yaml > "$R/dnom-e2e.yaml"
grep -q '^  addresses: \["127.0.0.1:6379", "198.51.100.77", "198.51.100.78"\]' "$R/dnom-e2e.yaml" || { say "could not list the decoy addresses"; exit 1; }
grep -q "^  paths: \[\"$VMDIR/decoy/\"\]" "$R/dnom-e2e.yaml" || { say "could not list the decoy folder"; exit 1; }
common=(--remote-source --home /home/lab --input "$in" --learn 0 --json --config "$R/dnom-e2e.yaml")
mkdir -p "$R/state-none"
"$BIN" monitor --state-dir "$R/state-none" > "$R/monitor.txt" 2> "$R/monitor.log" &
monitor=$!
"$BIN" classify "${common[@]}" --backend none --state-dir "$R/state-none" \
  > "$R/episodes-none.jsonl" 2> "$R/classify-none.log"
sleep 2   # the monitor polls the log twice a second
kill "$monitor" 2>/dev/null || true
wait "$monitor" 2>/dev/null || true
"$BIN" audit --state-dir "$R/state-none" > "$R/audit-list.txt" 2>&1 || true
decoy_ep=$(jq -r 'select(any(.policy[]; .rule == "decoy-touched")) | .episode.episode_id' "$R/episodes-none.jsonl" | tail -1)
"$BIN" audit "${decoy_ep:-none}" --state-dir "$R/state-none" > "$R/audit-decoy.txt" 2>&1 || true
if [[ ${E2E_JEV:-1} != 0 ]] && { [[ -n ${TYPESAFE_API_KEY:-} ]] || grep -q '^TYPESAFE_API_KEY=..*' .env 2>/dev/null; }; then
  "$BIN" classify "${common[@]}" --backend jev --only fake-exfil.sh --state-dir "$R/state-jev" \
    > "$R/episodes-jev.jsonl" 2> "$R/classify-jev.log" || true
  "$BIN" classify "${common[@]}" --backend jev --only benign.sh --state-dir "$R/state-jev-benign" \
    > "$R/episodes-jev-benign.jsonl" 2> "$R/classify-jev-benign.log" || true
  "$BIN" audit last --state-dir "$R/state-jev" > "$R/audit-jev.txt" 2>&1 || true
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

say "live run in the VM: generated decoys"
L=$VMDIR/live
vm "mkdir -p $L && ls -A ~ ~/.ssh | sort" </dev/null > "$R/live-home-before.txt"
vm "sudo timeout --foreground --signal=INT --kill-after=5s 120s $VMDIR/dnom collect 2> $L/collector.log |
    $VMDIR/dnom classify --backend none --config $VMDIR/dnom.yaml --state-dir $L/state --learn 0 --interval 2 --json \
      > $L/episodes.jsonl 2> $L/classify.log" </dev/null &
live=$!
for _ in $(seq 100); do
  vm "grep -q 'snapshot of' $L/collector.log && grep -q 'decoys planted' $L/classify.log" </dev/null 2>/dev/null && break
  sleep 0.3
done
# The harness needs the paths, and reading the list is itself something dnom must report.
vm "exec cat $L/state/decoys.json" </dev/null > "$R/live-decoys.json" || true
generated=$(jq -r '.files[].path' "$R/live-decoys.json" 2>/dev/null || true)
for path in $generated; do
  vm "exec cat $path" </dev/null > /dev/null || true
done
sleep 6   # a few assessment ticks
stop_collector
wait "$live" || true
for f in episodes.jsonl classify.log collector.log; do
  vm "cat $L/$f" </dev/null > "$R/live-$f" || true
done
# Whatever is still there of the generated files, their list, or a ~/.aws dnom created.
vm "for p in $(echo $generated) $L/state/decoys.json; do test -e \$p && echo \$p; done; true" </dev/null > "$R/live-leftovers.txt"
vm "ls -A ~ ~/.ssh | sort" </dev/null > "$R/live-home-after.txt"

git rev-parse HEAD > "$R/commit.txt"
git status --porcelain | grep -q . && echo dirty >> "$R/commit.txt" || true
python3 -I lab/vm/e2e/verify.py "$R" "$VMDIR" "$ROUNDS"
