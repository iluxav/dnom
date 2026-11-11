#!/usr/bin/env bash
# Probing workload for the decoy-address checks (lab/vm/e2e/run.sh). Connection attempts
# only: to this machine, and to TEST-NET-2 (198.51.100.0/24), which is reserved for
# documentation and never routed. Nothing is sent.
#   127.0.0.1:6379   a decoy port on this machine (nothing listens: refused at once)
#   127.0.0.1:6380   not a decoy: must be recorded, must not match
#   198.51.100.77    a decoy address, tried on port 22
#   198.51.100.78    a decoy address, tried with ping
try() { timeout 1 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null || true; }
try 127.0.0.1 6379
try 127.0.0.1 6380
try 198.51.100.77 22
ping -c 1 -W 1 198.51.100.78 >/dev/null 2>&1 || true
