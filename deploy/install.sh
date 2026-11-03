#!/usr/bin/env bash
# Install the CAM720 two-way talk service (this go2rtc fork) under systemd.
# Standalone: no dependency on any other project. Run as root.
#
# linux/arm64 pulls the release binary. Any other architecture: build from
# source first (see ../CAM720.md, "Building for your architecture") and place
# it at /usr/local/bin/go2rtc-cam720, then re-run.
set -Eeuo pipefail

readonly REPO="OJ-Labs-Ltd/go2rtc-cam720"
readonly RELEASE="v1.9.15-cam720.1"
readonly BIN="/usr/local/bin/go2rtc-cam720"
readonly CONF="/etc/go2rtc-cam720.yaml"
readonly ENVFILE="/etc/go2rtc-cam720.env"
here="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

if [ ! -x "$BIN" ]; then
  case "$(uname -m)" in
    aarch64|arm64)
      curl -fSL -o "$BIN" \
        "https://github.com/${REPO}/releases/download/${RELEASE}/go2rtc-cam720-linux-arm64"
      chmod 0755 "$BIN" ;;
    *) echo "No prebuilt binary for $(uname -m); build from source and place it at $BIN (see CAM720.md)"; exit 1 ;;
  esac
fi

install -m 0644 "$here/go2rtc-cam720.yaml" "$CONF"
if [ ! -f "$ENVFILE" ]; then
  install -m 0600 "$here/go2rtc-cam720.env.example" "$ENVFILE"
  echo "Edit $ENVFILE with your camera's IP, UID and token, then: systemctl restart go2rtc-cam720"
fi
install -m 0644 "$here/go2rtc-cam720.service" /etc/systemd/system/go2rtc-cam720.service
systemctl daemon-reload
systemctl enable --now go2rtc-cam720.service || true
echo "Installed. API on 127.0.0.1:1985, stream 'cam720'."
