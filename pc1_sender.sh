#!/usr/bin/env bash
# PC1 (Sender) multicast stream launcher for Ubuntu
# Usage: ./pc1_sender.sh /path/to/video.ts [iface_ip] [group] [port]
set -euo pipefail

FILE_PATH="${1:-}"
IFACE_IP="${2:-10.10.1.10}"
GROUP="${3:-239.1.1.1}"
PORT="${4:-5004}"
TTL=4
RATE=50
CHUNK=1316

if [[ -z "$FILE_PATH" ]]; then
  echo "Usage: $0 /path/to/video.ts [iface_ip] [group] [port]" >&2
  exit 1
fi

python3 src/sender.py \
  --file "$FILE_PATH" \
  --content-type video \
  --group "$GROUP" \
  --port "$PORT" \
  --iface "$IFACE_IP" \
  --ttl "$TTL" \
  --chunk-size "$CHUNK" \
  --rate "$RATE" \
  --loop
