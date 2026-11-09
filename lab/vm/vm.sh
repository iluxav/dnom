#!/usr/bin/env bash
# dnom lab VM: Ubuntu 26.04 cloud image under QEMU/KVM.
#
# Networking goes through passt with --no-map-gw: the guest reaches the internet (apt, Jev)
# but NOT services on the host's loopback (Ollama, Docker ports, desl...). SSH from the host
# only, on 127.0.0.1:$SSH_PORT. Disks, keys and logs live in $STATE, outside the repo.
#
# Usage: vm.sh fetch|setup|start|wait|ssh [cmd...]|check|stop|snapshot NAME|reset NAME|
#              snapshots|status|destroy --yes
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
STATE=${DNOM_LAB_DIR:-$HOME/.local/share/dnom-lab/vm}
RELEASE=resolute   # Ubuntu 26.04 LTS
IMAGE=$RELEASE-server-cloudimg-amd64.img
IMAGE_URL=https://cloud-images.ubuntu.com/$RELEASE/current/$IMAGE
SUMS_URL=https://cloud-images.ubuntu.com/$RELEASE/current/SHA256SUMS
BASE=$STATE/$IMAGE
DISK=$STATE/disk.qcow2
SEED=$STATE/seed.iso
KEY=$STATE/id_ed25519
SSH_PORT=${DNOM_LAB_SSH_PORT:-2222}
CPUS=${DNOM_LAB_CPUS:-4}
MEM=${DNOM_LAB_MEM:-8G}
DISK_SIZE=${DNOM_LAB_DISK:-40G}

mkdir -p "$STATE"
SSH_OPTS=(-i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new
          -o UserKnownHostsFile="$STATE/known_hosts" -o ConnectTimeout=5 -o LogLevel=ERROR)

say() { printf 'vm: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }
need() {
  for c in "$@"; do
    command -v "$c" >/dev/null || die "missing '$c'. Install: sudo pacman -S qemu-base libisoburn passt"
  done
}
pid_alive() { [[ -f $1 ]] && kill -0 "$(cat "$1")" 2>/dev/null; }
running() { pid_alive "$STATE/qemu.pid"; }
require_stopped() { ! running || die "the VM is running; stop it first: make vm-stop"; }
guest() { ssh "${SSH_OPTS[@]}" lab@127.0.0.1 "$@"; }

cmd_fetch() {
  need curl sha256sum
  local want
  want=$(curl -fsS "$SUMS_URL" | awk -v f="*$IMAGE" '$2 == f {print $1}')
  [[ -n $want ]] || die "no checksum for $IMAGE in $SUMS_URL"
  if [[ -f $BASE ]] && [[ $(sha256sum "$BASE" | cut -d' ' -f1) == "$want" ]]; then
    say "image already downloaded and verified: $BASE"
    return
  fi
  say "downloading $IMAGE_URL"
  curl -fL --progress-bar -o "$BASE.part" "$IMAGE_URL"
  [[ $(sha256sum "$BASE.part" | cut -d' ' -f1) == "$want" ]] || { rm -f "$BASE.part"; die "checksum mismatch"; }
  mv "$BASE.part" "$BASE"
  say "verified sha256 $want"
}

cmd_setup() {
  need qemu-img xorriso ssh-keygen
  [[ -f $DISK ]] && die "already set up ($DISK). To start over: make vm-destroy"
  cmd_fetch
  [[ -f $KEY ]] || ssh-keygen -q -t ed25519 -N '' -C dnom-lab -f "$KEY"
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  sed "s|__PUBKEY__|$(cat "$KEY.pub")|" "$HERE/cloud-init/user-data.tmpl" > "$tmp/user-data"
  cp "$HERE/cloud-init/network-config" "$tmp/network-config"
  printf 'instance-id: dnom-lab-%s\nlocal-hostname: dnom-lab\n' "$(date +%s)" > "$tmp/meta-data"
  xorriso -as mkisofs -quiet -output "$SEED" -volid cidata -joliet -rock \
    "$tmp/user-data" "$tmp/meta-data" "$tmp/network-config"
  qemu-img create -q -f qcow2 -b "$BASE" -F qcow2 "$DISK" "$DISK_SIZE"
  say "ready: $DISK ($DISK_SIZE, backed by the cloud image), seed $SEED, key $KEY"
  say "next: make vm-start"
}

cmd_start() {
  need qemu-system-x86_64 passt
  [[ -f $DISK ]] || die "not set up yet: make vm-setup"
  running && { say "already running (pid $(cat "$STATE/qemu.pid"))"; return; }
  [[ -r /dev/kvm && -w /dev/kvm ]] || die "no access to /dev/kvm"
  rm -f "$STATE/passt.sock"
  pid_alive "$STATE/passt.pid" && kill "$(cat "$STATE/passt.pid")" 2>/dev/null || true
  passt --socket "$STATE/passt.sock" --no-map-gw -t "127.0.0.1/$SSH_PORT:22" -u none \
    -P "$STATE/passt.pid" -l "$STATE/passt.log" --quiet
  for _ in $(seq 50); do [[ -S $STATE/passt.sock ]] && break; sleep 0.1; done
  [[ -S $STATE/passt.sock ]] || die "passt did not start; see $STATE/passt.log"
  qemu-system-x86_64 -name dnom-lab -machine q35,accel=kvm -cpu host -smp "$CPUS" -m "$MEM" \
    -drive file="$DISK",if=virtio,format=qcow2 \
    -drive file="$SEED",if=virtio,format=raw,readonly=on \
    -netdev stream,id=net0,server=off,addr.type=unix,addr.path="$STATE/passt.sock" \
    -device virtio-net-pci,netdev=net0 \
    -display none -serial file:"$STATE/serial.log" \
    -monitor unix:"$STATE/monitor.sock",server,nowait \
    -daemonize -pidfile "$STATE/qemu.pid"
  say "booting (pid $(cat "$STATE/qemu.pid")); console log: $STATE/serial.log"
  cmd_wait
}

cmd_wait() {
  say "waiting for the guest (first boot installs packages and may reboot once; ~3-8 min)"
  # Ready = provisioned, no reboot pending (/run is cleared by the reboot), cloud-init done.
  local state
  for _ in $(seq 300); do
    running || die "QEMU exited; see $STATE/serial.log"
    state=$(guest 'if ! test -f /var/lib/dnom-lab-provisioned; then echo provisioning;
                   elif test -f /run/dnom-lab-reboot; then echo rebooting;
                   else cloud-init status 2>/dev/null | sed -n "s/^status: //p"; fi' 2>/dev/null || echo booting)
    case $state in
      done) say "up: make vm-ssh   (checks: make vm-check)"; return ;;
      error|degraded*) die "cloud-init reported '$state'; inspect with: make vm-ssh, then cloud-init status --long" ;;
    esac
    sleep 3
  done
  die "guest not ready after 15+ min (last state: ${state:-none}); see $STATE/serial.log"
}

cmd_check() {
  running || die "not running: make vm-start"
  guest 'test -f /var/lib/dnom-lab-provisioned' 2>/dev/null \
    || die "still provisioning (first boot installs packages and reboots once); wait for 'make vm-start' to print 'up'"
  guest 'bash -s' <<'EOF'
ok() { printf '  ok    %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; fail=1; }
fail=0
test -f /var/lib/dnom-lab-provisioned && ok "cloud-init provisioning finished" || bad "provisioning not finished"
lsm=$(cat /sys/kernel/security/lsm); case ",$lsm," in *,bpf,*) ok "bpf LSM active ($lsm)";; *) bad "bpf LSM missing ($lsm)";; esac
command -v bpftrace >/dev/null && ok "$(bpftrace --version)" || bad "bpftrace missing"
bpftool version >/dev/null 2>&1 && ok "bpftool $(bpftool version | head -1 | awk '{print $2}')" || bad "bpftool missing (linux-tools for $(uname -r))"
docker --version >/dev/null 2>&1 && ok "$(docker --version)" || bad "docker missing"
curl -fsS -m 10 -o /dev/null https://api.typesafe.ai/v1/models -w '%{http_code}' 2>/dev/null | grep -qE '^(200|401|403)$' \
  && ok "internet + DNS (api.typesafe.ai reachable)" || bad "no internet / DNS"
gw=$(ip route | awk '/^default/ {print $3; exit}')
for port in 11434 8009 2222; do
  if timeout 3 bash -c "echo > /dev/tcp/$gw/$port" 2>/dev/null; then bad "gateway $gw:$port reachable (host isolation?)"; else ok "host loopback not reachable via gateway $gw:$port"; fi
done
uname -r | sed 's/^/  info  kernel /'
exit $fail
EOF
}

cmd_stop() {
  if running; then
    say "shutting down"
    echo system_powerdown | socat - UNIX-CONNECT:"$STATE/monitor.sock" >/dev/null 2>&1 || true
    for _ in $(seq 60); do running || break; sleep 1; done
    if running; then say "no clean shutdown after 60 s; killing QEMU"; kill "$(cat "$STATE/qemu.pid")"; sleep 1; fi
  else
    say "not running"
  fi
  pid_alive "$STATE/passt.pid" && kill "$(cat "$STATE/passt.pid")" 2>/dev/null || true
  rm -f "$STATE/qemu.pid" "$STATE/passt.pid" "$STATE/passt.sock" "$STATE/monitor.sock"
}

cmd_snapshot() {
  local name=${1:?usage: vm.sh snapshot NAME}
  require_stopped
  qemu-img snapshot -c "$name" "$DISK"
  say "snapshot '$name' saved"
}

cmd_reset() {
  local name=${1:?usage: vm.sh reset NAME}
  require_stopped
  qemu-img snapshot -a "$name" "$DISK"
  say "disk reverted to '$name'"
}

cmd_status() {
  if running; then say "running (pid $(cat "$STATE/qemu.pid")), ssh 127.0.0.1:$SSH_PORT"; else say "stopped"; fi
  if [[ -f $DISK ]]; then
    # -U: read-only look that works while QEMU holds the image lock.
    qemu-img snapshot -l -U "$DISK" | sed 's/^/  /'
  else
    say "not set up"
  fi
}

cmd_destroy() {
  [[ ${1:-} == --yes ]] || die "deletes the VM disk, seed and key in $STATE (the downloaded image is kept). Run: vm.sh destroy --yes"
  cmd_stop
  rm -f "$DISK" "$SEED" "$KEY" "$KEY.pub" "$STATE/known_hosts" "$STATE/serial.log" "$STATE/passt.log"
  say "destroyed; make vm-setup to start over"
}

case ${1:-} in
  fetch) cmd_fetch ;;
  setup) cmd_setup ;;
  start) cmd_start ;;
  wait) cmd_wait ;;
  ssh) shift; guest "$@" ;;
  check) cmd_check ;;
  stop) cmd_stop ;;
  snapshot) cmd_snapshot "${2:-}" ;;
  reset) cmd_reset "${2:-}" ;;
  snapshots|status) cmd_status ;;
  destroy) cmd_destroy "${2:-}" ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
