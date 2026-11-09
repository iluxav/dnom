"""Synthetic event stream: SSH login to another host plus a port-22 sweep of the LAN.

Shaped like `dnom collect` output for `./scripts/fake-lateral.sh` run from a foot terminal.
No such script is run; this only exercises the classifier. Usage:
    python3 lab/replay/make_fake_lateral.py > lab/replay/fake-lateral.jsonl
"""
import json
import time

t = int(time.time() * 1000) - 60_000
H = "/home/iluxa"
out = []


def ev(dt, pid, comm, kind, **kw):
    out.append(dict(ts_ms=t + dt, pid=pid, tid=pid, uid=1000, comm=comm, cgroup=1, kind=kind, **kw))


FOOT, BASH, SCRIPT = 4200001, 4200002, 4200003
ev(0, FOOT, "foot", "exec", exe="/usr/bin/foot", argv=["foot"])
ev(1, FOOT, "foot", "fork", child=BASH)
ev(2, BASH, "bash", "exec", exe="/usr/bin/bash", argv=["/usr/bin/bash"])

ev(1000, BASH, "bash", "fork", child=SCRIPT)
ev(1001, SCRIPT, "fake-lateral.sh", "exec", exe="./scripts/fake-lateral.sh",
   argv=["./scripts/fake-lateral.sh"])
ev(1002, SCRIPT, "bash", "exec", exe="/usr/bin/bash", argv=["bash", "./scripts/fake-lateral.sh"])

# Sweep 10.0.0.1-20 on port 22 with bash /dev/tcp (connects come from the script's bash).
for i in range(1, 21):
    ev(1100 + i * 20, SCRIPT, "bash", "net", op="connect", dest=f"10.0.0.{i}:22")

# Log into one host and run commands there.
SSH = 4200004
ev(1600, SCRIPT, "bash", "fork", child=SSH)
ev(1601, SSH, "ssh", "exec", exe="/usr/bin/ssh",
   argv=["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "deploy@10.0.0.12",
         "uname -a; id; cat /etc/passwd"])
ev(1602, SSH, "ssh", "open", path=H + "/.ssh/config", flags=0, write=False)
ev(1603, SSH, "ssh", "open", path=H + "/.ssh/id_ed25519", flags=0, write=False)
ev(1604, SSH, "ssh", "open", path=H + "/.ssh/known_hosts", flags=0, write=False)
ev(1605, SSH, "ssh", "net", op="connect", dest="10.0.0.12:22")

# Trailing event so replay time passes the settle window.
ev(20000, FOOT, "foot", "open", path=H + "/.config/foot/foot.ini", flags=0, write=False)

out.sort(key=lambda e: e["ts_ms"])
for e in out:
    print(json.dumps(e))
