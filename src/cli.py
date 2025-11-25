#!/usr/bin/env python3
"""Unified CLI to launch sender or receiver. Receiver auto-pipes into a player."""
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
        "--vlc",
        help="Path to VLC (optional). If omitted, tries to find vlc on PATH.",
    )
    parser.add_argument(
        "--player",
        choices=["ffplay", "vlc"],
        default="vlc",
        help="Choose playback tool for receiver; defaults to VLC (falls back to ffplay).",
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


def _locate_binary(preferred: str | None, fallback: str, label: str) -> str | None:
    if preferred:
        return preferred
    found = shutil.which(fallback)
    if not found:
        print(f"{label} not found on PATH. Install it or pass an explicit path.", file=sys.stderr)
    return found


def run_receiver(
    player: str | None, ffplay_path: str | None, vlc_path: str | None, extra_args: list[str]
) -> int:
    chosen_player = player or "vlc"
    if chosen_player == "vlc" and not vlc_path:
        # auto-switch to ffplay if VLC isn't available and user didn't force it via --vlc
        if not shutil.which("vlc"):
            chosen_player = "ffplay"
    if not vlc_path and chosen_player == "vlc":
        vlc_path = shutil.which("vlc")

    match chosen_player:
        case "vlc":
            vlc = _locate_binary(vlc_path, "vlc", "vlc")
            if not vlc:
                return 1
            player_cmd = [
                vlc,
                "--intf",
                "dummy",
                "--quiet",
                "--demux",
                "ts",
                "-",
            ]
        case _:
            ffplay = _locate_binary(ffplay_path, "ffplay", "ffplay")
            if not ffplay:
                return 1
            player_cmd = [ffplay, "-i", "-", "-fflags", "nobuffer", "-flags", "low_delay"]

    # Ensure receiver pipes data to stdout so the chosen player can read it.
    recv_cmd = [sys.executable, str(RECEIVER), "--pipe-stdout"]
    recv_cmd.extend(extra_args)

    with subprocess.Popen(
        recv_cmd, stdout=subprocess.PIPE, stderr=sys.stderr, bufsize=0
    ) as recv_proc:
        with subprocess.Popen(player_cmd, stdin=recv_proc.stdout) as player_proc:
            recv_proc.stdout.close()  # allow receiver to get SIGPIPE if ffplay exits
            player_proc.wait()
            recv_proc.terminate()
            recv_proc.wait()
            return player_proc.returncode


def main(argv: list[str] | None = None) -> int:
    if not argv:
        return interactive_menu()

    args = parse_args(argv)
    extra = args.rest
    if extra and extra[0] == "--":
        extra = extra[1:]

    if args.mode == "sender":
        return run_sender(extra)
    return run_receiver(args.player, args.ffplay, args.vlc, extra)


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
        player_choice = input("Playback tool [vlc/ffplay] (blank for vlc): ").strip().lower()
        if player_choice not in {"ffplay", "vlc", ""}:
            print("Invalid player choice; defaulting to vlc.")
            player_choice = ""
        player_choice = player_choice or "vlc"
        player_path = input(f"Path to {player_choice} (optional): ").strip()
        args = ["--group", group, "--port", port, "--pipe-stdout", "--idle-timeout", idle]
        if iface:
            args += ["--iface", iface]
        ffplay_path = player_path if player_choice == "ffplay" and player_path else None
        vlc_path = player_path if player_choice == "vlc" and player_path else None
        return run_receiver(player_choice, ffplay_path, vlc_path, args)
    else:
        print("Invalid choice.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
