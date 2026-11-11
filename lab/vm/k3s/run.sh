#!/usr/bin/env bash
# dnom on Kubernetes in the lab VM: single-node k3s, Falco as a DaemonSet with the dnom
# catch-all rules, three harmless test pods (workload.yaml).
#
# 1. Copies guest.sh, the manifests and the catch-all rules into the VM ($VMDIR).
# 2. guest.sh installs k3s if missing (pinned version, checksum verified), starts it, deploys
#    Falco and the pods, collects Falco's alerts, then deletes everything and stops k3s.
# 3. Classifies the alerts on the host without a model, with a namespace-scoped test rule
#    (rules.yaml) and two decoy addresses added to a copy of dnom.yaml; with Jev too if a
#    key is available (only the two web-pod episodes are sent; the key never enters the VM).
# 4. verify.py checks that episodes and policies see the pod and namespace, and writes
#    report.json.
#
# Results: ~/.local/state/dnom/vm-k3s/<timestamp>/ (outside the repo). Exit 1 on any FAIL.
# Env: K3S_VERSION (default in guest.sh), K3S_JEV=0 to skip Jev.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$REPO"
VM=lab/vm/vm.sh
VMDIR=/tmp/dnom-k3s   # also the hostPath in falco.yaml
R=$HOME/.local/state/dnom/vm-k3s/$(date -u +%Y%m%dT%H%M%SZ)
BIN=target/release/dnom

say() { printf 'k3s: %s\n' "$*" >&2; }
vm() { "$VM" ssh "$@"; }

cleanup() {
  vm "test -f $VMDIR/guest.sh && bash $VMDIR/guest.sh $VMDIR stop; sudo rm -rf $VMDIR" </dev/null >/dev/null 2>&1 || true
}
trap cleanup EXIT

status=$("$VM" status 2>&1 || true)
[[ $status == *"vm: running"* ]] || { say "starting the VM"; "$VM" start; }

say "building"
cargo build --release --quiet
mkdir -p "$R"
say "results: $R"

stage=$(mktemp -d)
cp lab/vm/k3s/guest.sh lab/vm/k3s/falco.yaml lab/vm/k3s/workload.yaml integrations/falco/dnom-catchall.yaml "$stage/"
tar -C "$stage" -cf - . | vm "sudo rm -rf $VMDIR && mkdir -p $VMDIR && tar -C $VMDIR -xf -"
rm -rf "$stage"

say "k3s, Falco and the test pods in the VM (first run downloads k3s, ~70 MB; 2-4 min)"
vm "K3S_VERSION=${K3S_VERSION:-} bash $VMDIR/guest.sh $VMDIR run" </dev/null 2>&1 | tee "$R/guest.log" >&2
for f in falco.json falco.log node.txt pods.json; do
  vm "cat $VMDIR/out/$f" </dev/null > "$R/$f"
done
vm "uname -r" </dev/null > "$R/kernel.txt"

say "classifying on the host"
sed -e '/^  rules:$/r lab/vm/k3s/rules.yaml' \
    -e 's|^  addresses: \[.*|  addresses: ["198.51.100.77", "198.51.100.78"]|' dnom.yaml > "$R/dnom-k3s.yaml"
grep -q '^  addresses: \["198.51.100.77", "198.51.100.78"\]' "$R/dnom-k3s.yaml" || { say "could not list the decoy addresses"; exit 1; }
grep -q k8s-test-namespace-credentials "$R/dnom-k3s.yaml" || { say "could not add the test rule"; exit 1; }
common=(--source falco --remote-source --home /home/lab --input "$R/falco.json" --learn 0 --json
        --config "$R/dnom-k3s.yaml")
"$BIN" classify "${common[@]}" --backend none --state-dir "$R/state-none" \
  > "$R/episodes-none.jsonl" 2> "$R/classify-none.log"
if [[ ${K3S_JEV:-1} != 0 ]] && { [[ -n ${TYPESAFE_API_KEY:-} ]] || grep -q '^TYPESAFE_API_KEY=..*' .env 2>/dev/null; }; then
  "$BIN" classify "${common[@]}" --backend jev --only 203.0.113.7 --state-dir "$R/state-jev" \
    > "$R/episodes-jev.jsonl" 2> "$R/classify-jev.log" || true
else
  say "no Jev key (or K3S_JEV=0): the Jev check will be skipped"
fi

git rev-parse HEAD > "$R/commit.txt"
git status --porcelain | grep -q . && echo dirty >> "$R/commit.txt" || true
python3 -I lab/vm/k3s/verify.py "$R"
