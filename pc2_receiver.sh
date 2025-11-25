#!/usr/bin/env bash
# PC2 (Receiver) multicast listener for Ubuntu; pipes to ffplay
# Usage: ./pc2_receiver.sh [iface_ip] [group] [port]
set -euo pipefail

IFACE_IP="${1:-10.10.2.10}"
GROUP="${2:-239.1.1.1}"
PORT="${3:-5004}"

python3 src/reciver.py \
  --pipe-stdout \
  --log-level WARNING \
  --group "$GROUP" \
  --port "$PORT" \
  --iface "$IFACE_IP" \
| ffplay -i - -fflags nobuffer -flags low_delay
