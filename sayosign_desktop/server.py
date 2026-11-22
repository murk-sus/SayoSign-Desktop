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
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

from . import device
import plistlib
import zipfile

from cryptography.hazmat.primitives import serialization

from . import appleid as aid
from .anisette import PUBLIC_SERVERS, AnisetteError
from .certs import CertError, CertStore
from .relay import AnisetteConfig, Relay, pick_best

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


def ipa_bundle_id(ipa_path):
    with zipfile.ZipFile(ipa_path) as z:
        plists = sorted((n for n in z.namelist() if n.startswith("Payload/") and n.endswith(".app/Info.plist")
                         and n.count("/") == 2), key=len)
        if not plists:
            raise CertError("no Info.plist in IPA")
        info = plistlib.loads(z.read(plists[0]))
        return info.get("CFBundleIdentifier"), info.get("CFBundleDisplayName") or info.get("CFBundleName") or "App"


class AppleIDStore:
    """Stores signed-in Apple Developer accounts (session token + certificate + key)."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def _dir(self, aid_id):
        d = (self.root / aid_id).resolve()
        if d.parent != self.root.resolve():
            raise CertError("bad id")
        return d

    def save(self, email, team, session, anisette, key, cert, device_id):
        import uuid as _uuid
        acc = "aid_" + _uuid.uuid4().hex[:10]
        d = self._dir(acc)
        d.mkdir()
        (d / "session.json").write_text(json.dumps(session))
        (d / "meta.json").write_text(json.dumps({"email": email, "team": team["teamId"],
                                                 "teamName": team.get("name", ""), "anisette": anisette,
                                                 "device_id": device_id}))
        (d / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                      serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
        (d / "cert.der").write_bytes(cert.public_bytes(serialization.Encoding.DER))
        return self.info(acc)

    def info(self, acc):
        d = self._dir(acc)
        meta = json.loads((d / "meta.json").read_text())
        from cryptography import x509
        cert = x509.load_der_x509_certificate((d / "cert.der").read_bytes())
        return {"id": acc, "kind": "appleid", "email": meta["email"], "team": meta["teamName"],
                "teamId": meta["team"], "expires": cert.not_valid_after_utc.isoformat()}

    def load(self, acc):
        d = self._dir(acc)
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        meta = json.loads((d / "meta.json").read_text())
        session = json.loads((d / "session.json").read_text())
        key = load_pem_private_key((d / "key.pem").read_bytes(), None)
        cert = x509.load_der_x509_certificate((d / "cert.der").read_bytes())
        return meta, session, key, cert

    def list(self):
        out = []
        for d in sorted(self.root.iterdir()) if self.root.exists() else []:
            if (d / "meta.json").exists():
                try:
                    out.append(self.info(d.name))
                except Exception:
                    pass
        return out

    def remove(self, acc):
        import shutil
        shutil.rmtree(self._dir(acc))


class App:
    def __init__(self, token: str):
        self.token = token
        self.certs = CertStore(CONFIG / "certs")
        self.accounts = AppleIDStore(CONFIG / "appleid")
        self.pending = {}  # in-memory half-finished logins
        self.ani = AnisetteConfig(CONFIG / "anisette.json", CONFIG / "anisette-state")
        self.relay = Relay(self.ani)
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

    # ---------- anisette ----------
    async def anisette_get(self, request):
        return web.json_response({"server": self.ani.server, "presets": [{"name": n, "url": u} for n, u in PUBLIC_SERVERS],
                                  "relay": self.relay.info()})

    async def anisette_set(self, request):
        b = await request.json()
        url = (b.get("server") or "").strip().rstrip("/")
        if not url:
            return web.json_response({"error": "Enter a server address"}, status=400)
        if "://" not in url:
            url = "https://" + url
        self.ani.data["server"] = url
        self.ani.save()
        return await self.anisette_get(request)

    async def anisette_check(self, request):
        b = await request.json() if request.can_read_body else {}
        url = (b.get("server") or self.ani.server).strip()
        return web.json_response(await asyncio.to_thread(self.ani.anisette(url).status))

    async def anisette_auto(self, request):
        best, results = await pick_best(self.ani.state_dir)
        if best:
            self.ani.data["server"] = best["server"]
            self.ani.save()
        return web.json_response({"best": best, "results": results, "server": self.ani.server})

    async def anisette_reset(self, request):
        await asyncio.to_thread(self.ani.anisette().reset)
        return web.json_response({"ok": True})

    async def anisette_relay(self, request):
        b = await request.json()
        if b.get("port"):
            self.ani.data["port"] = int(b["port"])
        try:
            if b.get("on"):
                await self.relay.stop()
                await self.relay.start()
            else:
                await self.relay.stop()
        except AnisetteError as e:
            return web.json_response({"error": str(e)}, status=400)
        self.ani.data["relay"] = bool(b.get("on"))
        self.ani.save()
        return web.json_response(self.relay.info())

    async def on_startup(self, app):
        if self.ani.data.get("relay"):
            try:
                await self.relay.start()
            except AnisetteError:
                pass

    async def on_cleanup(self, app):
        await self.relay.stop()

    # ---------- Apple ID ----------
    async def appleid_list(self, request):
        return web.json_response(await asyncio.to_thread(self.accounts.list))

    async def appleid_delete(self, request):
        self.accounts.remove(request.match_info["id"])
        return web.json_response({"ok": True})

    async def _first_udid(self):
        try:
            devs = await device.list_devices()
            d = next((x for x in devs if x.get("paired")), None)
            return d["udid"] if d else None
        except Exception:
            return None

    async def appleid_login(self, request):
        b = await request.json()
        server = self.ani.server

        def do_login():
            sess = aid.Session(self.ani.anisette(server))
            gs = aid.GSAuth(sess, b["email"].strip(), b["password"])
            try:
                factor = gs.login()
            except aid.AppleIDError as e:
                if any(c in str(e) for c in ("-45061", "-80045", "-80046")):
                    sess.an.reset()  # stale or rejected identity: start fresh once
                    factor = gs.login()
                else:
                    raise
            return sess, gs, factor

        try:
            sess, gs, factor = await asyncio.to_thread(do_login)
        except (aid.AppleIDError, AnisetteError) as e:
            return web.json_response({"error": str(e)}, status=400)
        if factor:
            pid = uuid.uuid4().hex[:12]
            self.pending[pid] = {"sess": sess, "gs": gs, "server": server}
            try:
                await asyncio.to_thread(gs.request_code)
            except Exception as e:
                return web.json_response({"error": f"Could not send the code: {e}"}, status=400)
            return web.json_response({"id": pid, "needs2FA": True, "factor": factor})
        try:
            acc = await self._finish_login(sess, gs, server)
        except (aid.AppleIDError, AnisetteError) as e:
            return web.json_response({"error": str(e)}, status=400)
        return web.json_response(acc)

    async def appleid_2fa(self, request):
        b = await request.json()
        p = self.pending.get(b["id"])
        if not p:
            return web.json_response({"error": "Session expired, sign in again"}, status=400)
        try:
            await asyncio.to_thread(p["gs"].submit_code, b["code"].strip())
            acc = await self._finish_login(p["sess"], p["gs"], p["server"])
        except (aid.AppleIDError, AnisetteError) as e:
            return web.json_response({"error": str(e)}, status=400)
        self.pending.pop(b["id"], None)
        return web.json_response(acc)

    async def _finish_login(self, sess, gs, server):
        def work():
            token = gs.xcode_token()
            api = aid.DeveloperAPI(token, sess)
            teams = api.teams()
            if not teams:
                raise aid.AppleIDError("This Apple ID has no developer team")
            team = teams[0]
            key, cert = api.create_certificate(team["teamId"])
            return token, team, key, cert

        token, team, key, cert = await asyncio.to_thread(work)
        udid = await self._first_udid()
        if udid:
            try:
                await asyncio.to_thread(lambda: aid.DeveloperAPI(token, sess).ensure_device(team["teamId"], udid))
            except aid.AppleIDError:
                pass
        return await asyncio.to_thread(self.accounts.save, token["email"], team, token, server, key, cert,
                                       sess.an.device_id)

    async def _apple_identity(self, acc_id, ipa):
        """Fetches a fresh provisioning profile for this IPA from the Apple account and
        bundles a temporary .p12 the CLI can use. Returns (p12, profile, password, tmpdir)."""
        bundle_id, name = await asyncio.to_thread(ipa_bundle_id, ipa)
        if not bundle_id:
            raise CertError("could not read the app's bundle ID")

        def work():
            meta, session, key, cert = self.accounts.load(acc_id)
            if datetime.fromisoformat(session["expiry"]) < datetime.now(timezone.utc):
                raise aid.AppleIDError("Apple ID session expired, sign in again")
            sess = aid.Session(self.ani.anisette(meta.get("anisette") or self.ani.server))
            api = aid.DeveloperAPI(session, sess)
            prof = api.profile(meta["team"], bundle_id, name)
            tmp = FILES / ("aid_" + uuid.uuid4().hex)
            tmp.mkdir()
            (tmp / "id.p12").write_bytes(aid.bundle_p12(key, cert, ""))
            (tmp / "id.mobileprovision").write_bytes(prof)
            return tmp

        tmp = await asyncio.to_thread(work)
        return tmp / "id.p12", tmp / "id.mobileprovision", "", tmp

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
        apple_tmp = None
        try:
            ipa = self._file(b["ipa"])
            out = ipa.parent / (ipa.stem + "-signed.ipa")
            if b.get("cert"):
                cli = find_cli()
                if not cli:
                    raise CertError("sayosign CLI not found. Build it with `make` or set SAYOSIGN_CLI.")
                if str(b["cert"]).startswith("aid_"):
                    await job.emit(stage="sign", percent=0, step="apple")
                    p12, prof, pw, apple_tmp = await self._apple_identity(b["cert"], ipa)
                else:
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
            if apple_tmp:
                shutil.rmtree(apple_tmp, ignore_errors=True)
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
        r.add_get("/api/anisette", self.anisette_get)
        r.add_post("/api/anisette", self.anisette_set)
        r.add_post("/api/anisette/check", self.anisette_check)
        r.add_post("/api/anisette/auto", self.anisette_auto)
        r.add_post("/api/anisette/reset", self.anisette_reset)
        r.add_post("/api/anisette/relay", self.anisette_relay)
        r.add_get("/api/appleid", self.appleid_list)
        r.add_post("/api/appleid/login", self.appleid_login)
        r.add_post("/api/appleid/2fa", self.appleid_2fa)
        r.add_delete("/api/appleid/{id}", self.appleid_delete)
        r.add_get("/api/devices", self.devices)
        r.add_get("/api/devices/{udid}/apps", self.apps)
        r.add_delete("/api/devices/{udid}/apps/{bundle}", self.uninstall)
        r.add_post("/api/jobs", self.job_start)
        r.add_get("/api/jobs/{id}/events", self.job_events)
        r.add_get("/api/jobs/{id}/download", self.job_download)
        r.add_static("/static/", WEB)
        app.on_startup.append(self.on_startup)
        app.on_cleanup.append(self.on_cleanup)
        return app
