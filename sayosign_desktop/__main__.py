"""Starts SayoSign Desktop: a local server plus a window (pywebview if installed, else the browser)."""
import argparse
import asyncio
import secrets
import socket
import threading
import webbrowser

from aiohttp import web

from .server import App


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser(prog="sayosign-desktop")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--no-window", action="store_true", help="do not open a window or browser")
    args = ap.parse_args()

    token = secrets.token_urlsafe(24)
    port = args.port or free_port()
    url = f"http://127.0.0.1:{port}/#token={token}"
    app = App(token).build()

    try:
        import webview  # optional native window
    except ImportError:
        webview = None

    if webview and not args.no_window:
        def serve():
            asyncio.run(_serve(app, port))
        threading.Thread(target=serve, daemon=True).start()
        webview.create_window("SayoSign", url, width=1180, height=820, min_size=(420, 600))
        webview.start()
        return

    print(f"SayoSign Desktop is running at {url}")
    if not args.no_window:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    web.run_app(app, host="127.0.0.1", port=port, print=None)


async def _serve(app, port):
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    main()
