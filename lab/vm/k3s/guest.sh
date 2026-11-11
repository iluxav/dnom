#!/usr/bin/env bash
# Runs inside the lab VM (user lab, with sudo), started by lab/vm/k3s/run.sh.
#
#   guest.sh DIR run    install k3s if missing (pinned, checksum verified), start it, deploy
#                       Falco as a DaemonSet with the dnom catch-all rules, run the test pods,
#                       then delete everything and stop k3s. Results in DIR/out/.
#   guest.sh DIR stop   delete the test namespaces and stop k3s (safe to run twice)
#
# k3s runs as a transient systemd unit (dnom-k3s), never enabled at boot. What it leaves
# behind until the next reboot: its network interfaces (cni0, flannel.1) and iptables rules.
set -euo pipefail

DIR=${1:?usage: guest.sh DIR run|stop}
K3S_VERSION=${K3S_VERSION:-v1.37.2+k3s1}
NODE=dnom-lab
OUT=$DIR/out
UNPACK_IMAGE=dnom-unpack:test   # built and removed by each run

say() { printf 'guest: %s\n' "$*" >&2; }
kc() { sudo k3s kubectl "$@"; }
k3s_up() { systemctl is-active --quiet dnom-k3s; }

install_k3s() {
  if k3s --version 2>/dev/null | grep -qF "$K3S_VERSION"; then return; fi
  local base=https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION//+/%2B} tmp
  tmp=$(mktemp -d)
  say "downloading k3s $K3S_VERSION"
  curl -fsSL -o "$tmp/k3s" "$base/k3s"
  curl -fsSL -o "$tmp/sums" "$base/sha256sum-amd64.txt"
  local want
  want=$(awk '$2 == "k3s" {print $1}' "$tmp/sums")
  [[ -n $want && $(sha256sum "$tmp/k3s" | cut -d' ' -f1) == "$want" ]] || { say "k3s checksum mismatch"; exit 1; }
  sudo install -m 755 "$tmp/k3s" /usr/local/bin/k3s
  rm -rf "$tmp"
}

start_k3s() {
  if ! k3s_up; then
    sudo systemctl reset-failed dnom-k3s 2>/dev/null || true
    # Only the API server, kubelet and containerd: no ingress, load balancer, DNS or storage.
    sudo systemd-run --quiet --unit=dnom-k3s --collect \
      /usr/local/bin/k3s server --node-name=$NODE --write-kubeconfig-mode=600 \
      --disable=traefik,servicelb,metrics-server,local-storage,coredns
  fi
  say "waiting for the node"
  for _ in $(seq 120); do kc get node $NODE >/dev/null 2>&1 && break; sleep 1; done
  kc wait --for=condition=Ready node/$NODE --timeout=180s >/dev/null
  until kc get serviceaccount default >/dev/null 2>&1; do sleep 1; done
}

run() {
  install_k3s
  start_k3s
  sudo rm -rf "$OUT" && mkdir -p "$OUT"
  { k3s --version | head -1; kc get node $NODE -o wide --no-headers; } > "$OUT/node.txt"

  # The VM's Docker already has both images (pulled once); otherwise the kubelet pulls them.
  sudo docker save falcosecurity/falco:0.45.2 alpine:3.20 2>/dev/null | sudo k3s ctr images import - >/dev/null 2>&1 \
    || say "image import from Docker failed; the kubelet will pull from the registry"

  say "deploying Falco (DaemonSet)"
  kc create namespace dnom-falco --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc -n dnom-falco create configmap dnom-rules --from-file="$DIR/dnom-catchall.yaml" \
    --dry-run=client -o yaml | kc apply -f - >/dev/null
  kc apply -f "$DIR/falco.yaml" >/dev/null
  kc -n dnom-falco rollout status ds/falco --timeout=180s >/dev/null
  for _ in $(seq 60); do kc -n dnom-falco logs ds/falco 2>/dev/null | grep -q 'Opening' && break; sleep 1; done
  sleep 8   # let the rules load and the container plugin connect to containerd

  # Image unpacking (lab/notes/kubernetes.md, finding 5): containerd writes each image's
  # /etc/shadow and /etc/profile into its storage, which must not count as credential access
  # or persistence. A one-layer image, unique per run, so its layer is always unpacked anew
  # (a pulled image can share layers that are already on disk).
  say "importing a fresh one-layer image"
  local root
  root=$(mktemp -d)
  mkdir -p "$root/etc"
  printf 'root:*:20000:0:99999:7:::\n' > "$root/etc/shadow"
  printf 'export DNOM_LAB=1\n' > "$root/etc/profile"
  date +%s%N > "$root/dnom-stamp"
  tar -C "$root" -cf - . | sudo docker import - $UNPACK_IMAGE >/dev/null
  rm -rf "$root"
  sudo docker save $UNPACK_IMAGE | sudo k3s ctr -n k8s.io images import - >/dev/null
  sleep 2

  say "test pods"
  kc apply -f "$DIR/workload.yaml" >/dev/null
  kc -n dnom-test wait --for=condition=Ready pod/db --timeout=120s >/dev/null
  # Like `docker exec`: a new process inside a running pod.
  kc -n dnom-test exec db -- cat /etc/shadow >/dev/null
  for ns in dnom-test dnom-other; do
    kc -n $ns wait --for=jsonpath='{.status.phase}'=Succeeded pod/web --timeout=120s >/dev/null
  done
  kc -n dnom-test wait --for=jsonpath='{.status.phase}'=Succeeded pod/probe --timeout=120s >/dev/null
  sleep 3
  kc get pods -A -o json > "$OUT/pods.json"
  kc -n dnom-falco logs ds/falco > "$OUT/falco.log" 2>&1 || true

  stop
  sudo chown -R "$(id -u):$(id -g)" "$OUT"
  say "falco alerts: $(wc -l < "$OUT/falco.json")"
}

stop() {
  if k3s_up; then
    say "deleting the test namespaces and Falco"
    # Falco exits on SIGTERM and closes its output file.
    kc delete namespace dnom-test dnom-other dnom-falco --ignore-not-found --timeout=90s >/dev/null || true
    sudo k3s ctr -n k8s.io images rm --sync "docker.io/library/$UNPACK_IMAGE" >/dev/null 2>&1 || true
    sudo systemctl stop dnom-k3s
  fi
  sudo docker rmi $UNPACK_IMAGE >/dev/null 2>&1 || true
}

case ${2:-} in
  run) run ;;
  stop) stop ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
