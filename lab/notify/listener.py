"""Tiny webhook receiver for trying dnom's alerts (`notify:` in dnom.yaml).

Listens on 127.0.0.1 only. Prints one line per alert; with --out FILE also appends the JSON.

Usage: listener.py [--port 8787] [--token TOKEN] [--out FILE] [--fail N] [--port-file FILE]
  --token TOKEN   answer 401 unless the request has "Authorization: Bearer TOKEN"
  --fail N        answer the first N requests with 503, to exercise dnom's retry
  --port 0        pick a free port; --port-file FILE gets the number
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8787)
parser.add_argument("--token")
parser.add_argument("--out")
parser.add_argument("--fail", type=int, default=0)
parser.add_argument("--port-file")
args = parser.parse_args()
failures_left = args.fail


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global failures_left
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if failures_left > 0:
            failures_left -= 1
            return self.reply(503, "try again")
        if args.token and self.headers.get("Authorization") != f"Bearer {args.token}":
            return self.reply(401, "bad token")
        try:
            alert = json.loads(body)
        except ValueError:
            return self.reply(400, "not JSON")
        print(f"{self.path}  {alert.get('event')}  {alert.get('host')}  {alert.get('summary')}", flush=True)
        if args.out:
            with open(args.out, "a") as f:
                f.write(json.dumps({"path": self.path, "alert": alert}) + "\n")
        self.reply(200, "ok")

    def reply(self, status, text):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(text.encode())

    def log_message(self, *_):
        pass


server = HTTPServer(("127.0.0.1", args.port), Handler)
if args.port_file:
    with open(args.port_file, "w") as f:
        f.write(str(server.server_port))
print(f"listening on http://127.0.0.1:{server.server_port} (Ctrl-C to stop)", flush=True)
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
