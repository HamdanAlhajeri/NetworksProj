#!/usr/bin/env python3
"""Multicast sender for UDP-based multimedia experiments."""
from __future__ import annotations

import argparse
import json
import logging
import secrets
import signal
import socket
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Tuple

MAGIC = b"MM"
VERSION = 1
HEADER = struct.Struct("!2sBBIIH")  # magic, version, payload_type, seq, ts_ms, payload_len
MAX_PAYLOAD = 1400
PAYLOAD_TYPES = {
    "text": 0x01,
    "binary": 0x02,
    "audio": 0x03,
    "video": 0x04,
    "control": 0x7F,
}
CONTENT_TYPE_CHOICES = tuple(k for k in PAYLOAD_TYPES if k != "control")
SEQ_MOD = 1 << 32


class StopToken:
    def __init__(self) -> None:
        self.stop = False

    def install(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._handle)  # type: ignore[arg-type]
            except ValueError:
                pass  # signal not available on this platform

    def _handle(self, signum, _frame) -> None:
        logging.info("Received signal %s, shutting down …", signum)
        self.stop = True


class RateLimiter:
    def __init__(self, rate_hz: float) -> None:
        self.period = None if rate_hz <= 0 else 1.0 / rate_hz
        self.next_tick = time.perf_counter()

    def wait(self) -> None:
        if not self.period:
            return
        self.next_tick += self.period
        delay = self.next_tick - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        else:
            self.next_tick = time.perf_counter()


class ThroughputStats:
    def __init__(self, interval: float) -> None:
        self.interval = max(interval, 0.0)
        self.bytes = 0
        self.packets = 0
        self.last_report = time.perf_counter()

    def update(self, size: int) -> None:
        self.bytes += size
        self.packets += 1
        if not self.interval:
            return
        now = time.perf_counter()
        if now - self.last_report >= self.interval:
            duration = now - self.last_report
            bitrate_kbps = (self.bytes * 8 / duration) / 1000
            logging.info(
                "Sent %d packets (%.1f kbps)", self.packets, bitrate_kbps
            )
            self.bytes = 0
            self.packets = 0
            self.last_report = now


def build_packet(seq: int, payload_type: int, payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"Payload too large ({len(payload)} > {MAX_PAYLOAD})")
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFF
    header = HEADER.pack(MAGIC, VERSION, payload_type, seq, ts_ms, len(payload))
    return header + payload


def payload_source(args: argparse.Namespace, data_payload_type: int) -> Iterator[Tuple[int, bytes]]:
    if args.file:
        path = Path(args.file)
        if not path.exists():
            raise FileNotFoundError(path)
        chunk_size = max(1, min(args.chunk_size, MAX_PAYLOAD - 4))
        meta_interval = max(args.meta_interval, 0.0)

        def file_chunks() -> Iterator[bytes]:
            with path.open("rb") as fh:
                while chunk := fh.read(chunk_size):
                    yield chunk

        while True:
            session_id = secrets.randbits(32)
            metadata = {
                "session_id": session_id,
                "file_name": path.name,
                "file_size": path.stat().st_size,
                "chunk_size": chunk_size,
                "content_type": args.content_type,
                "rate_hz": args.rate,
            }
            yield PAYLOAD_TYPES["control"], json.dumps(metadata).encode("utf-8")
            last_meta = time.time()
            yielded = False
            for chunk in file_chunks():
                yielded = True
                payload = struct.pack("!I", session_id) + chunk
                yield data_payload_type, payload
                now = time.time()
                if meta_interval and (now - last_meta) >= meta_interval:
                    yield PAYLOAD_TYPES["control"], json.dumps(metadata).encode("utf-8")
                    last_meta = now
            if not args.loop or not yielded:
                break
    else:
        payload = args.message.encode(args.encoding)
        while True:
            yield data_payload_type, payload
            if not args.loop:
                break


def create_socket(group: str, ttl: int, iface: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    if iface:
        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface)
        )
    return sock


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="UDP multicast sender for multimedia packets."
    )
    parser.add_argument("--group", default="239.1.1.1", help="Multicast group IPv4.")
    parser.add_argument("--port", type=int, default=5004, help="Destination port.")
    parser.add_argument("--ttl", type=int, default=1, help="Multicast TTL.")
    parser.add_argument("--iface", help="Local interface IPv4 for multicast traffic.")
    parser.add_argument("--rate", type=float, default=10.0, help="Packets per second.")
    parser.add_argument(
        "--payload-type",
        type=lambda v: int(v, 0),
        help="Raw payload type byte (accepts 0x..). Overrides --content-type.",
    )
    parser.add_argument(
        "--content-type",
        choices=CONTENT_TYPE_CHOICES,
        default="text",
        help="High level type hint stored in the payload header.",
    )
    parser.add_argument("--message", default="Hello multicast client!")
    parser.add_argument("--file", help="Path to a binary payload to stream.")
    parser.add_argument("--loop", action="store_true", help="Loop file/message forever.")
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=MAX_PAYLOAD,
        help="Chunk size when streaming a file (bytes).",
    )
    parser.add_argument(
        "--append-timestamp",
        action="store_true",
        help="Append an ISO timestamp to each payload.",
    )
    parser.add_argument(
        "--meta-interval",
        type=float,
        default=5.0,
        help="Seconds between repeating metadata packets when streaming a file (0 = only once).",
    )
    parser.add_argument(
        "--encoding", default="utf-8", help="Encoding for --message payload."
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=5.0,
        help="Seconds between throughput logs (0 disables).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.meta_interval = 5.0  # enforce periodic metadata resend for late joiners
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    socket.setdefaulttimeout(2)
    sock = create_socket(args.group, args.ttl, args.iface)
    stop = StopToken()
    stop.install()

    data_payload_type = (
        args.payload_type
        if args.payload_type is not None
        else PAYLOAD_TYPES[args.content_type]
    )
    payloads = payload_source(args, data_payload_type)
    limiter = RateLimiter(args.rate)
    stats = ThroughputStats(args.stats_interval)
    seq = 0

    logging.info(
        "Streaming to %s:%d (ttl=%d rate=%.2fpps payload=%s type=%s/0x%02x)",
        args.group,
        args.port,
        args.ttl,
        args.rate,
        args.file or args.message,
        args.content_type,
        data_payload_type,
    )

    try:
        while not stop.stop:
            try:
                payload_type, payload = next(payloads)
            except StopIteration:
                break
            if args.append_timestamp and not args.file:
                payload += f"|{datetime.now(timezone.utc).isoformat()}".encode(
                    args.encoding
                )
            packet = build_packet(seq, payload_type, payload)
            sock.sendto(packet, (args.group, args.port))
            stats.update(len(packet))
            seq = (seq + 1) % SEQ_MOD
            limiter.wait()
    except OSError as exc:
        logging.error("Socket error: %s", exc)
        return 1
    finally:
        sock.close()
        stats.update(0)  # flush stats if interval hit
    logging.info("Sender stopped after seq=%d", seq)
    return 0


if __name__ == "__main__":
    sys.exit(main())
