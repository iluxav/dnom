#!/usr/bin/env bash
# dnom on a remote server: only the collector runs there; everything else stays here.
#
#   remote.sh install HOST   copy the collector, install it as a capped systemd service
#   remote.sh status HOST    service state, memory, CPU, event files, last log lines
#   remote.sh pull HOST      copy the event files here and classify them (no model by default)
#   remote.sh classify HOST  classify the copies that are already here (no connection)
#   remote.sh remove HOST    stop and delete everything on the server
#
# HOST is an ssh alias for root, or for a user with passwordless sudo. The server needs
# x86_64 Linux and systemd; nothing else is installed.
#
# On the server:
#   /opt/dnom/dnom                  the collector (observe-only eBPF, root)
#   /var/lib/dnom/events-<day>.jsonl  raw events, one file per UTC day, root-only.
#                                   Command lines are stored as typed (masking happens at
#                                   classification), so treat these files as sensitive.
#   dnom-collect.service            capped: MemoryMax=128M, CPUQuota=25%, Nice=10
#   dnom-housekeep.timer            hourly: new file each day, gzip old ones, delete after
#                                   7 days, stop collecting if the folder passes 2 GB
#
# Here: ~/.local/state/dnom/remote/HOST/
#   events/      the pulled files
#   dnom.yaml    this server's config, created from the repo's on the first pull: no ignore
#                rules, no decoys. Edit it (e.g. decoys.addresses); the server never sees it.
#   state/       baseline and audit trail, rebuilt from all events on every pull, so a
#                changed rule applies to the whole history
#
# Env for pull and classify: BACKEND (default none), LEARN seconds of event time before
# anything counts as new (default 3600), ONLY (limit a remote model backend to matching
# commands), JSON=1 (write every assessed episode as a JSON line to classify.jsonl instead
# of the text summary in classify.txt).
# Env for all: DNOM_SSH_CONFIG, an ssh config file to use instead of ~/.ssh/config.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
CMD=${1:-}
HOST=${2:-}
[[ -n $CMD && -n $HOST ]] || { sed -n '2,9p' "$0"; exit 2; }
BIN=$REPO/target/release/dnom
LOCAL=$HOME/.local/state/dnom/remote/$HOST
SSH=(ssh ${DNOM_SSH_CONFIG:+-F "$DNOM_SSH_CONFIG"} -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

say() { printf 'remote: %s\n' "$*" >&2; }
# Runs a script on the server as root (stdin), with sudo if the ssh user isn't root.
as_root() { "${SSH[@]}" 'if [ "$(id -u)" = 0 ]; then sh -s; else sudo -n sh -s; fi'; }

install() {
  [[ -x $BIN ]] || { say "build first: make build"; exit 1; }
  [[ $("${SSH[@]}" uname -m) == x86_64 ]] || { say "the collector supports x86_64 only"; exit 1; }
  say "copying the collector"
  "${SSH[@]}" 'cat > /tmp/dnom.new' < "$BIN"
  as_root <<'EOF'
set -eu
install -d -m 700 /opt/dnom /var/lib/dnom
install -m 700 /tmp/dnom.new /opt/dnom/dnom && rm -f /tmp/dnom.new

cat > /opt/dnom/housekeep.sh <<'SH'
#!/bin/sh
# dnom housekeeping (hourly): a new events file each UTC day, old ones compressed and deleted
# after KEEP_DAYS; collecting stops if the data folder passes MAX_MB.
set -eu
D=/var/lib/dnom; MAX_MB=2048; KEEP_DAYS=7
today=events-$(date -u +%Y%m%d).jsonl
if systemctl is-active --quiet dnom-collect && [ ! -e "$D/$today" ]; then systemctl restart dnom-collect; fi
for f in "$D"/events-*.jsonl; do
  [ -e "$f" ] || continue
  [ "$(basename "$f")" = "$today" ] || nice gzip -q "$f"
done
find "$D" -name 'events-*.jsonl.gz' -mtime +"$KEEP_DAYS" -delete
used=$(du -sm "$D" | cut -f1)
if [ "$used" -gt "$MAX_MB" ] && systemctl is-active --quiet dnom-collect; then
  systemctl stop dnom-collect
  echo "$(date -u +%FT%TZ) housekeeping: $used MB in $D is over $MAX_MB MB; collector stopped" >> "$D/collector.log"
fi
SH
chmod 700 /opt/dnom/housekeep.sh

cat > /etc/systemd/system/dnom-collect.service <<'UNIT'
[Unit]
Description=dnom collector (observe-only eBPF sensor)
Documentation=https://github.com/iluxav/dnom
StartLimitIntervalSec=900
StartLimitBurst=3

[Service]
ExecStart=/bin/sh -c 'exec /opt/dnom/dnom collect >> /var/lib/dnom/events-$$(date -u +%%Y%%m%%d).jsonl'
StandardError=append:/var/lib/dnom/collector.log
KillSignal=SIGINT
TimeoutStopSec=15
Restart=on-failure
RestartSec=60
MemoryMax=128M
CPUQuota=25%
Nice=10
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/dnom-housekeep.service <<'UNIT'
[Unit]
Description=dnom housekeeping (rotate, compress, size limit)

[Service]
Type=oneshot
ExecStart=/opt/dnom/housekeep.sh
UNIT

cat > /etc/systemd/system/dnom-housekeep.timer <<'UNIT'
[Unit]
Description=dnom housekeeping, hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --quiet dnom-collect.service dnom-housekeep.timer
systemctl restart dnom-collect.service
systemctl start dnom-housekeep.timer
EOF
  for _ in $(seq 10); do
    as_root <<<'grep -q "sensors attached" /var/lib/dnom/collector.log 2>/dev/null' && break
    sleep 1
  done
  status
}

status() {
  as_root <<'EOF'
echo "collector: $(systemctl is-active dnom-collect 2>/dev/null) (enabled: $(systemctl is-enabled dnom-collect 2>/dev/null)), housekeeping timer: $(systemctl is-active dnom-housekeep.timer 2>/dev/null)"
m=$(systemctl show dnom-collect -p MemoryCurrent --value); p=$(systemctl show dnom-collect -p MemoryPeak --value); c=$(systemctl show dnom-collect -p CPUUsageNSec --value)
case $m in ""|*[!0-9]*) m=0;; esac; case $p in ""|*[!0-9]*) p=0;; esac; case $c in ""|*[!0-9]*) c=0;; esac
echo "memory: $((m / 1048576)) MB now, $((p / 1048576)) MB peak (limit 128 MB); CPU used: $((c / 1000000000)) s since $(systemctl show dnom-collect -p ActiveEnterTimestamp --value)"
# The total includes the file cache of the events file, which grows up to the limit and is
# given back by the kernel on demand; the collector's own share is what should stay flat.
stat=/sys/fs/cgroup$(systemctl show dnom-collect -p ControlGroup --value)/memory.stat
[ -r "$stat" ] && awk '$1=="anon"{a=$2} $1=="kernel"{k=$2} $1=="file"{f=$2}
  END {printf "  of that: %d MB the collector itself, %d MB file cache (freed on demand)\n", (a+k)/1048576, f/1048576}' "$stat"
echo "server: $(free -m | awk 'NR==2{print $7}') MB available, load $(cut -d' ' -f1-3 /proc/loadavg)"
echo "data: $(du -sh /var/lib/dnom 2>/dev/null | cut -f1) in /var/lib/dnom"
ls -l /var/lib/dnom 2>/dev/null | awk 'NR>1 {printf "  %10s  %s\n", $5, $9}'
echo "log (last 5 lines):"; tail -5 /var/lib/dnom/collector.log 2>/dev/null | sed 's/^/  /'
EOF
}

fetch() {
  mkdir -p "$LOCAL/events" && chmod 700 "$LOCAL" "$LOCAL/events"
  say "copying event files to $LOCAL/events"
  # The current day's file is still being written: take what is there now.
  as_root <<<'cd /var/lib/dnom && tar -czf - --ignore-failed-read --warning=no-file-changed events-* collector.log 2>/dev/null || true' \
    | tar -C "$LOCAL/events" -xzf -
  # A day arrives first as .jsonl and later as .jsonl.gz: keep the complete one.
  for gz in "$LOCAL"/events/events-*.jsonl.gz; do [[ -e $gz ]] && rm -f "${gz%.gz}"; done
}

classify() {
  [[ -x $BIN ]] || { say "build first: make build"; exit 1; }
  mkdir -p "$LOCAL/events" && chmod 700 "$LOCAL" "$LOCAL/events"
  if [[ ! -e $LOCAL/dnom.yaml ]]; then
    # This server's config: the repo's, without its desktop-specific ignore rules and decoys.
    awk '
      /^ignore:/ { print "ignore: []"; skip = 1; next }
      skip && /^( |$)/ { next }
      { skip = 0 }
      /^  paths: \[/ { print "  paths: []"; next }
      /^  addresses: \[/ { print "  addresses: []"; next }
      { print }' "$REPO/dnom.yaml" > "$LOCAL/dnom.yaml"
    say "created $LOCAL/dnom.yaml (edit it to add decoy addresses or rules)"
  fi

  local all=$LOCAL/all-events.jsonl
  : > "$all"
  for f in $(ls "$LOCAL"/events/events-* 2>/dev/null | sort); do
    case $f in *.gz) gzip -dc "$f" >> "$all" ;; *) cat "$f" >> "$all" ;; esac
  done
  chmod 600 "$all"
  say "$(wc -l < "$all") events in $(ls "$LOCAL"/events/events-* 2>/dev/null | wc -l) file(s)"

  local backend=${BACKEND:-none} flags=() out=$LOCAL/classify.txt
  [[ -n ${ONLY:-} ]] && flags+=(--only "$ONLY")
  [[ $backend != none && -z ${ONLY:-} ]] && flags+=(--allow-all-remote)
  [[ -n ${JSON:-} ]] && { flags+=(--json); out=$LOCAL/classify.jsonl; }
  rm -rf "$LOCAL/state"
  "$BIN" classify --remote-source --home /root --config "$LOCAL/dnom.yaml" --backend "$backend" "${flags[@]}" \
    --input "$all" --learn "${LEARN:-3600}" --state-dir "$LOCAL/state" > "$out" 2> "$LOCAL/classify.log" || {
    tail -5 "$LOCAL/classify.log" >&2; exit 1; }
  rm -f "$all"
  grep -E 'left out as routine|stopped\.' "$LOCAL/classify.log" >&2
  "$BIN" audit --threats --last 50 --state-dir "$LOCAL/state"
  say "all assessed episodes: $BIN audit --state-dir $LOCAL/state"
}

pull() { [[ -x $BIN ]] || { say "build first: make build"; exit 1; }; fetch; classify; }

remove() {
  as_root <<'EOF'
systemctl disable --now dnom-collect.service dnom-housekeep.timer 2>/dev/null || true
rm -f /etc/systemd/system/dnom-collect.service /etc/systemd/system/dnom-housekeep.service /etc/systemd/system/dnom-housekeep.timer
systemctl daemon-reload
rm -rf /opt/dnom /var/lib/dnom
echo "removed: services, /opt/dnom, /var/lib/dnom"
EOF
  say "local copies stay in $LOCAL (delete them yourself when done)"
}

case $CMD in
  install) install ;;
  status) status ;;
  pull) pull ;;
  classify) classify ;;
  remove) remove ;;
  *) sed -n '2,9p' "$0"; exit 2 ;;
esac
