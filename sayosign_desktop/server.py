"""Local web server behind the SayoSign Desktop window.

Binds to 127.0.0.1 only and requires a per-launch token on every API call, so other
websites open in the browser cannot talk to it.
"""
import asyncio
import json
import os
import re
import secrets
import shutil
import sys
import urllib.parse
import uuid
from pathlib import Path

from aiohttp import web

from . import device
from .certs import CertError, CertStore

HERE = Path(__file__).parent
WEB = HERE / "web"


def _data_dirs():
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
        return base / "SayoSign", Path(os.environ.get("LOCALAPPDATA", base)) / "SayoSign" / "cache"
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "SayoSign"
        return base, Path.home() / "Library" / "Caches" / "SayoSign"
    return (Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "sayosign",
            Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "sayosign")


CONFIG, CACHE = _data_dirs()
FILES = CACHE / "files"


def find_cli() -> str | None:
    exe = "sayosign.exe" if sys.platform == "win32" else "sayosign"
    for c in [os.environ.get("SAYOSIGN_CLI"), HERE / "bin" / exe, HERE.parent.parent / "build" / exe, shutil.which(exe)]:
        if c and Path(c).is_file():
            return str(c)
    return None


class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex[:12]
        self.events: list[dict] = []
        self.done = False
        self.output: Path | None = None
        self.cond = asyncio.Condition()

    async def emit(self, **ev):
        self.events.append(ev)
        async with self.cond:
            self.cond.notify_all()


class App:
    def __init__(self, token: str):
        self.token = token
        self.certs = CertStore(CONFIG / "certs")
        self.jobs: dict[str, Job] = {}
        FILES.mkdir(parents=True, exist_ok=True)

    # ---------- middleware ----------
    @web.middleware
    async def auth(self, request, handler):
        if request.path.startswith("/api/"):
            tok = request.headers.get("X-Token") or request.query.get("token")
            if not secrets.compare_digest(tok or "", self.token):
                return web.json_response({"error": "unauthorized"}, status=401)
        try:
            return await handler(request)
        except CertError as e:
            return web.json_response({"error": str(e)}, status=400)
        except web.HTTPException:
            raise
        except Exception as e:
            return web.json_response({"error": str(e) or type(e).__name__}, status=500)

    # ---------- files ----------
    def _file(self, fid: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", fid or ""):
            raise CertError("bad file id")
        d = FILES / fid
        files = list(d.iterdir()) if d.is_dir() else []
        if not files:
            raise CertError("file not found")
        return files[0]

    async def upload(self, request):
        name = Path(urllib.parse.unquote(request.headers.get("X-Filename", "file.bin"))).name or "file.bin"
        fid = uuid.uuid4().hex
        d = FILES / fid
        d.mkdir(parents=True)
        path = d / name
        with open(path, "wb") as f:
            async for chunk in request.content.iter_chunked(1 << 20):
                f.write(chunk)
        return web.json_response({"id": fid, "name": name, "size": path.stat().st_size})

    # ---------- certs ----------
    async def certs_list(self, request):
        return web.json_response(await asyncio.to_thread(self.certs.list))

    async def certs_add(self, request):
        b = await request.json()
        p12 = self._file(b["p12"]).read_bytes()
        prof = self._file(b["profile"]).read_bytes()
        pw = b.get("password")
        info = await asyncio.to_thread(self.certs.add, p12, prof, pw if pw else None, b.get("nickname", ""))
        return web.json_response(info)

    async def certs_check(self, request):
        return web.json_response(await asyncio.to_thread(self.certs.info, request.match_info["id"], True))

    async def certs_delete(self, request):
        self.certs.remove(request.match_info["id"])
        return web.json_response({"ok": True})

    # ---------- devices ----------
    async def devices(self, request):
        try:
            return web.json_response(await device.list_devices())
        except Exception as e:
            return web.json_response({"devices": [], "error": str(e) or type(e).__name__}, status=503)

    async def apps(self, request):
        return web.json_response(await device.list_apps(request.match_info["udid"]))

    async def uninstall(self, request):
        await device.uninstall(request.match_info["udid"], request.match_info["bundle"])
        return web.json_response({"ok": True})

    # ---------- signing ----------
    async def job_start(self, request):
        b = await request.json()
        job = Job()
        self.jobs[job.id] = job
        asyncio.create_task(self._run(job, b))
        return web.json_response({"id": job.id})

    async def _run(self, job: Job, b: dict):
        try:
            ipa = self._file(b["ipa"])
            out = ipa.parent / (ipa.stem + "-signed.ipa")
            if b.get("cert"):
                cli = find_cli()
                if not cli:
                    raise CertError("sayosign CLI not found. Build it with `make` or set SAYOSIGN_CLI.")
                p12, prof, pw = self.certs.paths(b["cert"])
                o = b.get("options", {})
                args = [cli, "sign", "-k", str(p12), "-p", pw, "-m", str(prof), "-i", str(ipa), "-o", str(out)]
                for flag, key in (("-n", "name"), ("-b", "bundleId"), ("-v", "build"), ("-s", "version"), ("-c", "icon")):
                    if o.get(key):
                        args += [flag, str(self._file(o[key])) if key == "icon" else str(o[key])]
                for t in o.get("tweaks", []):
                    args += ["-l", str(self._file(t))]
                if o.get("removePlugins"):
                    args.append("-x")
                if o.get("removeWatch"):
                    args.append("-w")
                if o.get("fileSharing"):
                    args.append("-f")
                if o.get("compression") is not None:
                    args += ["-z", str(o["compression"])]
                await job.emit(stage="sign", percent=0)
                proc = await asyncio.create_subprocess_exec(
                    *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                buf, last = b"", ""
                while True:
                    chunk = await proc.stdout.read(256)
                    if not chunk:
                        break
                    buf += chunk
                    for m in re.finditer(rb"\[\s*(\d+)%\]\s*(\w+)", buf):
                        pct, step = int(m.group(1)), m.group(2).decode()
                        if f"{pct}{step}" != last:
                            last = f"{pct}{step}"
                            await job.emit(stage="sign", percent=pct, step=step)
                    buf = buf[-200:]
                tail = buf.decode(errors="replace").strip()
                if await proc.wait() != 0 or not out.exists():
                    raise CertError(tail.splitlines()[-1] if tail else "signing failed")
                await job.emit(stage="sign", percent=100, step="done")
            else:
                out = ipa
            job.output = out
            await job.emit(stage="signed", size=out.stat().st_size, download=f"/api/jobs/{job.id}/download")

            if b.get("udid"):
                await job.emit(stage="install", percent=0)
                loop = asyncio.get_running_loop()
                last = [-1]

                def prog(p):
                    if p != last[0]:
                        last[0] = p
                        loop.create_task(job.emit(stage="install", percent=p))

                await device.install(b["udid"], out, prog)
                await job.emit(stage="installed")
            await job.emit(stage="done")
        except Exception as e:
            await job.emit(stage="error", error=str(e) or type(e).__name__)
        finally:
            job.done = True
            async with job.cond:
                job.cond.notify_all()

    async def job_events(self, request):
        job = self.jobs.get(request.match_info["id"])
        if not job:
            raise web.HTTPNotFound()
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
        await resp.prepare(request)
        i = 0
        while True:
            while i < len(job.events):
                await resp.write(f"data: {json.dumps(job.events[i])}\n\n".encode())
                i += 1
            if job.done and i >= len(job.events):
                break
            async with job.cond:
                try:
                    await asyncio.wait_for(job.cond.wait(), timeout=15)
                except asyncio.TimeoutError:
                    await resp.write(b": ping\n\n")
        return resp

    async def job_download(self, request):
        job = self.jobs.get(request.match_info["id"])
        if not job or not job.output:
            raise web.HTTPNotFound()
        return web.FileResponse(job.output, headers={"Content-Disposition": f'attachment; filename="{job.output.name}"'})

    async def status(self, request):
        return web.json_response({"cli": bool(find_cli()), "version": "0.1.0"})

    async def index(self, request):
        return web.FileResponse(WEB / "index.html", headers={"Cache-Control": "no-store"})

    def build(self) -> web.Application:
        app = web.Application(middlewares=[self.auth], client_max_size=8 * 1024 ** 3)
        r = app.router
        r.add_get("/", self.index)
        r.add_get("/api/status", self.status)
        r.add_post("/api/files", self.upload)
        r.add_get("/api/certs", self.certs_list)
        r.add_post("/api/certs", self.certs_add)
        r.add_post("/api/certs/{id}/check", self.certs_check)
        r.add_delete("/api/certs/{id}", self.certs_delete)
        r.add_get("/api/devices", self.devices)
        r.add_get("/api/devices/{udid}/apps", self.apps)
        r.add_delete("/api/devices/{udid}/apps/{bundle}", self.uninstall)
        r.add_post("/api/jobs", self.job_start)
        r.add_get("/api/jobs/{id}/events", self.job_events)
        r.add_get("/api/jobs/{id}/download", self.job_download)
        r.add_static("/static/", WEB)
        return app
