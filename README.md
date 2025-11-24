# UDP Multicast Sender/Receiver (Python)

This project sends arbitrary payloads (including video) over UDP multicast and optionally reconstructs/plays the stream on the receiver.

## Dependencies
- Python 3.9+ (tested on Windows)
- ffmpeg/ffplay (for live playback). On Windows you can install via Chocolatey: `choco install ffmpeg` or download a static build and add `bin` to `PATH`.
- No extra Python packages beyond the standard library.

## Files
- `src/sender.py` — multicast sender with chunked file streaming.
- `src/reciver.py` — multicast receiver with jitter buffer, file reconstruction, and optional live piping to a player.

## Typical workflow (Windows / PowerShell)
Open two PowerShell windows in the project root.

### 1) Receiver
Streams incoming payloads to stdout (for live playback) and saves reconstructed files into `output/`:
```powershell
python .\src\reciver.py --pipe-stdout --log-level WARNING
```
- Add `--idle-timeout 5` to auto-exit after 5 seconds of inactivity once buffers are empty.
- Add `--iface <your_ip>` if you must bind to a specific NIC.

To pipe directly into ffplay (after ffmpeg install):
```powershell
python reciver.py --pipe-stdout --log-level WARNING | ffplay -i - -fflags nobuffer -flags low_delay
```
or

```powershell
python3 reciver.py --pipe-stdout --log-level WARNING | ffplay -i - -fflags nobuffer -flags low_delay
```

### 2) Sender
Send a transport-stream file (recommended for live playback):
```powershell
python sender.py --file video.ts --content-type video --chunk-size 1316 --rate 50 --meta-interval 5
```
or
```powershell
python3 sender.py --file video.ts --content-type video --chunk-size 1316 --rate 50 --meta-interval 5
```
- Use `--iface <your_ip>` to select the outbound interface.
- Drop `--loop` to send once; add `--loop` to repeat.

If your source is MP4, transmux once to TS for smooth streaming:
```powershell
ffmpeg -i "C:\path\to\video.mp4" -c copy -f mpegts "C:\path\to\video.ts"
```

## Key options
- `--group` / `--port` — multicast destination (defaults: 239.1.1.1:5004).
- `--rate` — packets per second.
- `--chunk-size` — bytes per payload; 1316 (7×188) aligns to MPEG-TS packets.
- `--content-type` — high-level type hint (text, binary, audio, video).
- `--pipe-stdout` (receiver) — stream chunks to stdout for live playback.
- `--output-dir` (receiver) — where reconstructed files are written (default: `output/`).
- `--idle-timeout` (receiver) — auto-stop after N seconds of inactivity (0 = never).
- `--meta-interval` (sender) resends the stream metadata every N seconds so late-joining receivers can discover the current session  
                    and start reconstructing immediately
## Troubleshooting
- `ffplay` not found: install ffmpeg and reopen PowerShell; verify with `where ffplay`.
- Corrupted video / “Invalid NAL unit”: use MPEG-TS input (`.ts`) and TS-aligned `--chunk-size 1316`; lower `--rate` if you suspect loss.
- No packets received: ensure sender/receiver use the same group/port; check firewall rules and interface selection.


## TODO:

- Make it so that a user can join mid broadcast


python reciver.py --pipe-stdout --log-level WARNING | ffplay -i - -fflags nobuffer -flags low_delay
python sender.py --file video2.ts --content-type video --chunk-size 1300 --rate 100
