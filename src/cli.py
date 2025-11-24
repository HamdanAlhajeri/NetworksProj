#!/usr/bin/env python3
"""Unified CLI to launch sender or receiver. Receiver auto-pipes to ffplay."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SENDER = ROOT / "sender.py"
RECEIVER = ROOT / "reciver.py"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Multicast sender/receiver launcher")
    parser.add_argument(
        "mode", choices=["sender", "receiver"], help="Choose which role to run."
    )
    parser.add_argument(
        "--ffplay",
        help="Path to ffplay (optional). If omitted, tries to find ffplay on PATH.",
    )
    parser.add_argument(
        "rest",
        nargs=argparse.REMAINDER,
        help="Additional args passed through to sender/receiver scripts.",
    )
    return parser.parse_args(argv)


def run_sender(extra_args: list[str]) -> int:
    from sender import main as sender_main

    return sender_main(extra_args)


def run_receiver(ffplay_path: str | None, extra_args: list[str]) -> int:
    ffplay = ffplay_path or shutil.which("ffplay")
    if not ffplay:
        print("ffplay not found on PATH. Install ffmpeg/ffplay or pass --ffplay.", file=sys.stderr)
        return 1

    # Ensure receiver pipes data to stdout for ffplay.
    recv_cmd = [sys.executable, str(RECEIVER), "--pipe-stdout"]
    recv_cmd.extend(extra_args)

    ffplay_cmd = [ffplay, "-i", "-", "-fflags", "nobuffer", "-flags", "low_delay"]

    with subprocess.Popen(
        recv_cmd, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=0
    ) as recv_proc:
        with subprocess.Popen(ffplay_cmd, stdin=recv_proc.stdout) as ffplay_proc:
            recv_proc.stdout.close()  # allow receiver to get SIGPIPE if ffplay exits
            ffplay_proc.wait()
            recv_proc.terminate()
            recv_proc.wait()
            return ffplay_proc.returncode


def main(argv: list[str] | None = None) -> int:
    if not argv:
        return interactive_menu()

    args = parse_args(argv)
    extra = args.rest
    if extra and extra[0] == "--":
        extra = extra[1:]

    if args.mode == "sender":
        return run_sender(extra)
    return run_receiver(args.ffplay, extra)


def interactive_menu() -> int:
    print("Select mode:")
    print("1) Sender")
    print("2) Receiver")
    choice = input("Enter choice (1/2): ").strip()
    if choice == "1":
        file_path = input("Path to file/video to send: ").strip('"').strip()
        if not file_path:
            print("No file provided; aborting.")
            return 1
        path_obj = Path(file_path)
        if not path_obj.exists():
            print(f"File not found: {path_obj}")
            return 1
        group = input("Multicast group [239.1.1.1]: ").strip() or "239.1.1.1"
        port = input("Port [5004]: ").strip() or "5004"
        rate = input("Packets per second [50]: ").strip() or "50"
        chunk = input("Chunk size bytes [1316]: ").strip() or "1316"
        iface = input("Interface IP (optional, blank for default): ").strip()
        args = [
            "--file",
            str(path_obj),
            "--content-type",
            "video",
            "--group",
            group,
            "--port",
            port,
            "--rate",
            rate,
            "--chunk-size",
            chunk,
        ]
        if iface:
            args += ["--iface", iface]
        return run_sender(args)
    elif choice == "2":
        group = input("Multicast group to join [239.1.1.1]: ").strip() or "239.1.1.1"
        port = input("Port [5004]: ").strip() or "5004"
        iface = input("Interface IP (optional, blank for default): ").strip()
        idle = input("Idle timeout seconds (0=never) [0]: ").strip() or "0"
        args = ["--group", group, "--port", port, "--pipe-stdout", "--idle-timeout", idle]
        if iface:
            args += ["--iface", iface]
        return run_receiver(None, args)
    else:
        print("Invalid choice.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
