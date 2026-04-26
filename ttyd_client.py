"""
ttyd_client.py - Interactive terminal client for ttyd over WebSocket.

Outbound framing (client -> server):
  "0" + raw keystrokes   -> terminal input
  "1" + JSON             -> resize: {"columns": N, "rows": N}

Inbound framing (server -> client):
  "0" + bytes            -> terminal output  (write to stdout)
  "1" + bytes            -> title change     (update terminal title via OSC)
  "2" + JSON             -> options          (ignore)
"""

import asyncio
import json
import os
import shutil
import signal
import sys
import termios
import tty

import websockets # pyright: ignore[reportMissingImports]


TARGET_DEFAULT = "ws://192.168.1.1:7689/ws"
AUTH_PAYLOAD   = json.dumps({"AuthToken": ""})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def terminal_size() -> tuple[int, int]:
    """Return (columns, rows) of the local terminal."""
    size = shutil.get_terminal_size(fallback=(80, 24))
    return size.columns, size.lines


def resize_payload(cols: int, rows: int) -> bytes:
    """Build the ttyd resize frame."""
    msg = json.dumps({"columns": cols, "rows": rows})
    return ("1" + msg).encode()


def input_payload(data: bytes) -> bytes:
    """Wrap raw bytes as a ttyd input frame."""
    return b"0" + data


# ---------------------------------------------------------------------------
# Main coroutine
# ---------------------------------------------------------------------------

async def run(url: str) -> None:
    print(f"Connecting to {url} ...", file=sys.stderr)

    async with websockets.connect(
        url,
        subprotocols=["tty"],
        open_timeout=8,
    ) as ws:
        print("Connected. Press Ctrl-C (then q) to exit cleanly.", file=sys.stderr)

        # Send auth immediately.
        await ws.send(AUTH_PAYLOAD)

        # Tell the server our terminal dimensions.
        cols, rows = terminal_size()
        await ws.send(resize_payload(cols, rows))

        # Put the local terminal into raw mode so every keystroke goes
        # straight to the remote shell without local echo or line editing.
        old_attrs = termios.tcgetattr(sys.stdin.fileno())
        tty.setraw(sys.stdin.fileno())

        loop = asyncio.get_running_loop()

        # Queue that keyboard reader fills, websocket writer drains.
        input_queue: asyncio.Queue[bytes] = asyncio.Queue()

        def _read_stdin() -> None:
            """Called by the event loop when stdin is readable."""
            data = os.read(sys.stdin.fileno(), 256)
            if data:
                input_queue.put_nowait(data)

        loop.add_reader(sys.stdin.fileno(), _read_stdin)

        def _on_resize(*_) -> None:
            """SIGWINCH handler - forward new terminal size to server."""
            c, r = terminal_size()
            input_queue.put_nowait(resize_payload(c, r)[0:0])  # sentinel
            # We can't easily send from a signal handler, so enqueue a special
            # resize frame directly.
            asyncio.ensure_future(_send_resize(ws, c, r))

        signal.signal(signal.SIGWINCH, _on_resize)

        async def _send_resize(sock, c: int, r: int) -> None:
            try:
                await sock.send(resize_payload(c, r))
            except Exception:
                pass

        try:
            async def sender() -> None:
                """Drain the input queue and forward to the WebSocket."""
                while True:
                    data = await input_queue.get()
                    await ws.send(input_payload(data))

            async def receiver() -> None:
                """Receive frames from the server and write to stdout."""
                async for raw in ws:
                    if isinstance(raw, str):
                        raw = raw.encode()
                    kind = chr(raw[0])
                    payload = raw[1:]

                    if kind == "0":
                        # Terminal output - write directly to stdout.
                        sys.stdout.buffer.write(payload)
                        sys.stdout.buffer.flush()
                    elif kind == "1":
                        # Title change - emit an xterm OSC sequence.
                        title = payload.decode(errors="replace")
                        sys.stdout.buffer.write(
                            f"\x1b]0;{title}\x07".encode()
                        )
                        sys.stdout.buffer.flush()
                    # kind == "2" (options) - nothing useful to do with it.

            # Run both coroutines concurrently; stop when either finishes.
            done, pending = await asyncio.wait(
                [
                    asyncio.ensure_future(sender()),
                    asyncio.ensure_future(receiver()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()

        finally:
            # Always restore the terminal, even on exception.
            loop.remove_reader(sys.stdin.fileno())
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)
            termios.tcsetattr(
                sys.stdin.fileno(), termios.TCSADRAIN, old_attrs
            )
            print("\r\nDisconnected.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET_DEFAULT
    try:
        asyncio.run(run(url))
    except KeyboardInterrupt:
        pass
    except websockets.exceptions.ConnectionClosedError as exc:
        print(f"\r\nServer closed connection: code={exc.code}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Could not connect: {exc}", file=sys.stderr)
        sys.exit(1)
