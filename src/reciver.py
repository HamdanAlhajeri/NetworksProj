#!/usr/bin/env python3
"""UDP multicast receiver with jitter-buffer and statistics."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, Optional

MAGIC = b"MM"
HEADER = struct.Struct("!2sBBIIH")
SEQ_MOD = 1 << 32
PAYLOAD_TYPES = {
    0x01: "text",
    0x02: "binary",
    0x03: "audio",
    0x04: "video",
    0x7F: "control",
}


@dataclass(slots=True)
class Packet:
    seq: int
    ts_ms: int
    payload_type: int
    payload: bytes
    arrival: float
    source: tuple[str, int]


@dataclass(slots=True)
class FileSession:
    session_id: int
    path: Path
    fh: BinaryIO
    expected_size: int
    written: int = 0


class StopToken:
    def __init__(self) -> None:
        self.stop = False

    def install(self) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._handle)  # type: ignore[arg-type]
            except ValueError:
                pass

    def _handle(self, signum, _frame) -> None:
        logging.info("Received signal %s, stopping …", signum)
        self.stop = True


class JitterBuffer:
    def __init__(self, buffer_ms: float, missing_timeout_ms: float) -> None:
        self.delay = buffer_ms / 1000.0
        self.missing_timeout = max(missing_timeout_ms / 1000.0, self.delay)
        self.buffer: dict[int, Packet] = {}
        self.expected: Optional[int] = None
        self.last_release = time.monotonic()

    def push(self, packet: Packet) -> None:
        buffer_was_empty = not self.buffer
        self.buffer[packet.seq] = packet
        if self.expected is None or buffer_was_empty:
            self.expected = packet.seq

    def pop_ready(self, now: float) -> tuple[list[Packet], int]:
        ready: list[Packet] = []
        losses = 0
        while self.expected is not None:
            pkt = self.buffer.get(self.expected)
            if pkt:
                if now - pkt.arrival >= self.delay:
                    ready.append(pkt)
                    del self.buffer[self.expected]
                    self.expected = (self.expected + 1) % SEQ_MOD
                    self.last_release = now
                    continue
                break
            if now - self.last_release >= self.missing_timeout:
                losses += 1
                self.expected = (self.expected + 1) % SEQ_MOD
                self.last_release = now
                continue
            break
        return ready, losses

    def __len__(self) -> int:
        return len(self.buffer)


class StreamStats:
    def __init__(self, interval: float) -> None:
        self.interval = max(interval, 0.0)
        self.received = 0
        self.lost = 0
        self.started = time.perf_counter()
        self.last_report = self.started

    def on_packet(self) -> None:
        self.received += 1

    def on_loss(self, count: int) -> None:
        self.lost += count

    def maybe_report(self, buffer_depth: int) -> None:
        if not self.interval:
            return
        now = time.perf_counter()
        if now - self.last_report < self.interval:
            return
        total = self.received + self.lost
        loss_pct = (self.lost / total * 100.0) if total else 0.0
        logging.info(
            "stats: recv=%d lost=%d loss=%.2f%% buffer=%d",
            self.received,
            self.lost,
            loss_pct,
            buffer_depth,
        )
        self.last_report = now


class FileAssembler:
    def __init__(self, output_dir: Path, live_sink: Optional[BinaryIO] = None) -> None:
        self.output_dir = output_dir
        self.live_sink = live_sink
        self.sessions: Dict[int, FileSession] = {}
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def handle_packet(self, packet: Packet) -> None:
        if packet.payload_type == 0x7F:
            self._handle_metadata(packet.payload)
        else:
            self._handle_chunk(packet.payload)

    def close_all(self) -> None:
        for session in list(self.sessions.values()):
            session.fh.close()
        self.sessions.clear()

    def _handle_metadata(self, payload: bytes) -> None:
        try:
            meta = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            logging.warning("Invalid metadata payload: %s", exc)
            return
        session_id = meta.get("session_id")
        if session_id is None:
            logging.warning("Metadata missing session_id field.")
            return
        try:
            session_id = int(session_id)
        except (TypeError, ValueError):
            logging.warning("Invalid session_id value: %r", session_id)
            return
        file_name = Path(meta.get("file_name", "payload.bin")).name or "payload.bin"
        expected_size = int(meta.get("file_size", 0) or 0)
        chunk_size = int(meta.get("chunk_size", 0) or 0)
        content_type = meta.get("content_type", "unknown")
        target_path = self._derive_path(session_id, file_name)
        self._close_session(session_id)
        fh = target_path.open("wb")
        self.sessions[session_id] = FileSession(
            session_id=session_id,
            path=target_path,
            fh=fh,
            expected_size=expected_size,
        )
        logging.info(
            "Recording session %08x -> %s (type=%s size=%d chunk=%d)",
            session_id,
            target_path,
            content_type,
            expected_size,
            chunk_size,
        )

    def _handle_chunk(self, payload: bytes) -> None:
        if len(payload) < 4:
            logging.warning("Data payload too small to contain session_id header.")
            return
        session_id = struct.unpack_from("!I", payload)[0]
        chunk = payload[4:]
        session = self.sessions.get(session_id)
        if not session:
            logging.debug(
                "No active session for chunk session=%08x (%d bytes dropped)",
                session_id,
                len(chunk),
            )
            return
        if not chunk:
            return
        if self.live_sink:
            try:
                self.live_sink.write(chunk)
                self.live_sink.flush()
            except Exception as exc:
                logging.warning("Live sink write failed: %s", exc)
                self.live_sink = None
        remaining = session.expected_size - session.written if session.expected_size else None
        to_write = (
            chunk
            if remaining is None or remaining <= 0
            else chunk[:remaining]
        )
        if not to_write:
            return
        session.fh.write(to_write)
        session.written += len(to_write)
        if session.expected_size and session.written >= session.expected_size:
            session.fh.flush()
            session.fh.close()
            logging.info(
                "Completed session %08x (%s, %d bytes)",
                session.session_id,
                session.path,
                session.written,
            )
            del self.sessions[session_id]

    def _close_session(self, session_id: int) -> None:
        existing = self.sessions.pop(session_id, None)
        if existing:
            existing.fh.close()

    def _derive_path(self, session_id: int, file_name: str) -> Path:
        base = self.output_dir / f"{session_id:08x}_{file_name}"
        if not base.exists():
            return base
        suffix = 1
        while True:
            candidate = self.output_dir / f"{session_id:08x}_{suffix}_{file_name}"
            if not candidate.exists():
                return candidate
            suffix += 1


def parse_packet(data: bytes, source: tuple[str, int]) -> Packet:
    if len(data) < HEADER.size:
        raise ValueError("packet too short")
    magic, version, payload_type, seq, ts_ms, payload_len = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError("bad magic")
    if version != 1:
        raise ValueError(f"unsupported version {version}")
    if payload_len > len(data) - HEADER.size:
        raise ValueError("declared payload length exceeds datagram")
    payload = data[HEADER.size : HEADER.size + payload_len]
    return Packet(seq=seq, ts_ms=ts_ms, payload_type=payload_type, payload=payload, arrival=time.monotonic(), source=source)


def create_socket(group: str, port: int, iface: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    iface_ip = socket.inet_aton(iface or "0.0.0.0")
    mreq = socket.inet_aton(group) + iface_ip
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setblocking(False)
    return sock


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="UDP multicast receiver with jitter buffering."
    )
    parser.add_argument("--group", default="239.1.1.1", help="Multicast group to join.")
    parser.add_argument("--port", type=int, default=5004, help="UDP port to bind.")
    parser.add_argument("--iface", help="Local interface IPv4 for IGMP join.")
    parser.add_argument(
        "--buffer-ms",
        type=float,
        default=200.0,
        help="Jitter buffer depth in milliseconds.",
    )
    parser.add_argument(
        "--missing-timeout",
        type=float,
        default=200.0,
        help="Milliseconds to wait before declaring a packet lost.",
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=5.0,
        help="Seconds between statistics logs (0 disables).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    parser.add_argument(
        "--preview-bytes",
        type=int,
        default=64,
        help="Number of payload bytes to print for inspection.",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to store reconstructed payloads (blank disables writing).",
    )
    parser.add_argument(
        "--pipe-stdout",
        action="store_true",
        help="Also stream reconstructed data to stdout for live playback (e.g., pipe into ffplay).",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=0.0,
        help="Seconds of inactivity before shutting down (0 = never).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    sock = create_socket(args.group, args.port, args.iface)
    buffer = JitterBuffer(args.buffer_ms, args.missing_timeout)
    stats = StreamStats(args.stats_interval)
    stop = StopToken()
    stop.install()
    last_packet_time = time.monotonic()
    assembler: Optional[FileAssembler] = None
    live_sink = sys.stdout.buffer if args.pipe_stdout else None
    if args.output_dir:
        try:
            assembler = FileAssembler(Path(args.output_dir), live_sink=live_sink)
        except OSError as exc:
            logging.error("Unable to prepare output directory %s: %s", args.output_dir, exc)
            return 1

    logging.info(
        "Listening on %s:%d (iface=%s buffer=%.1fms)",
        args.group,
        args.port,
        args.iface or "0.0.0.0",
        args.buffer_ms,
    )

    try:
        while not stop.stop:
            try:
                data, addr = sock.recvfrom(65535)
            except BlockingIOError:
                pass
            else:
                try:
                    packet = parse_packet(data, addr)
                except ValueError as exc:
                    logging.warning("Dropped packet from %s: %s", addr, exc)
                else:
                    buffer.push(packet)
                    last_packet_time = time.monotonic()

            ready, losses = buffer.pop_ready(time.monotonic())
            if losses:
                stats.on_loss(losses)
            for packet in ready:
                stats.on_packet()
                payload_preview = packet.payload[: args.preview_bytes]
                content_type = PAYLOAD_TYPES.get(packet.payload_type, "unknown")
                logging.info(
                    "seq=%d ts=%d type=%s(0x%02x) bytes=%d src=%s preview=%r",
                    packet.seq,
                    packet.ts_ms,
                    content_type,
                    packet.payload_type,
                    len(packet.payload),
                    packet.source,
                    payload_preview,
                )
                if assembler:
                    assembler.handle_packet(packet)
            stats.maybe_report(len(buffer))
            if args.idle_timeout > 0:
                inactive = time.monotonic() - last_packet_time
                no_buffer = len(buffer) == 0
                no_sessions = not assembler or not assembler.sessions
                if inactive >= args.idle_timeout and no_buffer and no_sessions:
                    logging.info("Idle for %.1fs, stopping receiver.", inactive)
                    break
            time.sleep(0.005)
    except OSError as exc:
        logging.error("Socket error: %s", exc)
        return 1
    finally:
        sock.close()
        if assembler:
            assembler.close_all()
    logging.info("Receiver stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
