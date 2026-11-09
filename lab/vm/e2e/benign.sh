#!/usr/bin/env bash
# Benign control workload for the VM end-to-end test (lab/vm/e2e/run.sh): 200 short
# commands, an ordinary file write/read, a failed open, a relative-path open and a
# loopback connection. None of it should match a policy rule.
set -euo pipefail
run_dir=$(dirname "$0")
for i in $(seq 1 200); do
  /usr/bin/true "dnom-burst-$i"
done
printf 'ordinary application data\n' > "$run_dir/ordinary.txt"
cat "$run_dir/ordinary.txt" > /dev/null
if cat "$run_dir/does-not-exist.txt" >/dev/null 2>&1; then
  echo 'expected missing file' >&2
  exit 1
fi
python3 - "$run_dir" <<'PY'
import json, os, pathlib, socket, sys
root = pathlib.Path(sys.argv[1])
os.chdir(root)
with open('ordinary.txt') as f:
    assert f.read() == 'ordinary application data\n'
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(1)
port = listener.getsockname()[1]
with socket.create_connection(('127.0.0.1', port)) as client:
    peer, _ = listener.accept()
    client.sendall(b'dnom dummy health check')
    with peer:
        assert peer.recv(128) == b'dnom dummy health check'
listener.close()
(root / 'benign-result.json').write_text(json.dumps({'pid': os.getpid(), 'loopback_port': port}))
PY
