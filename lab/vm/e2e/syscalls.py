"""Workload for the VM end-to-end test: the less common syscalls dnom's sensor covers.

open(), creat() and openat2() called directly (glibc routes its wrappers through openat),
execveat() via fexecve(), a UDP sendto() with a destination, and a TCP connect over IPv6.
Everything stays local: files in RUN_DIR, network to loopback only.

Usage: python3 -I syscalls.py RUN_DIR   (writes RUN_DIR/syscalls-result.json)
"""
import ctypes
import json
import os
import socket
import sys
from pathlib import Path

root = Path(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
NR_OPEN, NR_CREAT, NR_OPENAT2 = 2, 85, 437
AT_FDCWD = -100


def syscall_fd(*args):
    fd = libc.syscall(*args)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    os.close(fd)


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


files = {name: str(root / f"sys-{name}.txt") for name in ("open", "creat", "openat2")}
write_flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
syscall_fd(ctypes.c_long(NR_OPEN), ctypes.c_char_p(files["open"].encode()), ctypes.c_long(write_flags), ctypes.c_long(0o644))
syscall_fd(ctypes.c_long(NR_CREAT), ctypes.c_char_p(files["creat"].encode()), ctypes.c_long(0o644))
how = OpenHow(write_flags, 0o644, 0)
syscall_fd(ctypes.c_long(NR_OPENAT2), ctypes.c_long(AT_FDCWD), ctypes.c_char_p(files["openat2"].encode()),
           ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))

# execveat: glibc's fexecve() runs execveat(fd, "", argv, envp, AT_EMPTY_PATH).
exe_fd = os.open("/usr/bin/true", os.O_RDONLY)
child = os.fork()
if child == 0:
    os.execve(exe_fd, ["true", "dnom-execveat"], {})
_, status = os.waitpid(child, 0)
assert os.waitstatus_to_exitcode(status) == 0
os.close(exe_fd)

# UDP sendto() naming its destination.
udp_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_rx.bind(("127.0.0.1", 0))
udp_port = udp_rx.getsockname()[1]
udp_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_tx.sendto(b"dnom", ("127.0.0.1", udp_port))
assert udp_rx.recv(16) == b"dnom"
udp_tx.close()
udp_rx.close()

# TCP connect over IPv6 loopback.
v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
v6.bind(("::1", 0))
v6.listen(1)
v6_port = v6.getsockname()[1]
client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.connect(("::1", v6_port))
peer, _ = v6.accept()
peer.close()
client.close()
v6.close()

(root / "syscalls-result.json").write_text(
    json.dumps({"pid": os.getpid(), "files": files, "udp_port": udp_port, "v6_port": v6_port})
)
