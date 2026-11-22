"""Anisette client: the v3 protocol (provisioning over WebSocket + /v3/get_headers),
with a v1 fallback (GET / returning JSON). Mirrors iloader/isideload and SideStore.

Since October 2026 Apple rejects anisette that does not match the client info it was
made for, so every Apple request must use the client info and user agent the anisette
server itself reports at /v3/client_info.
"""
import asyncio
import base64
import hashlib
import json
import os
import plistlib
import ssl
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

HERE = Path(__file__).parent
APPLE_ROOT = HERE / "apple_root.pem"
URL_BAG = "https://gsa.apple.com/grandslam/GsService2/lookup"
XCODE_VERSION = "27.0 (27A5218g)"

# Mac-based servers (Apple accepts these). Android-ADI servers get -80045 since Oct 2026.
PUBLIC_SERVERS = [
    ("iloader", "https://ani.iloader.app"),
    ("jkcoxson (Mac)", "https://mac-ani.jkcoxson.com"),
    ("SideStore (new)", "https://new.ani.sidestore.io"),
]


class AnisetteError(Exception):
    pass


def apple_ssl():
    """TLS context that also trusts Apple Root CA (gsa.apple.com chains to it)."""
    ctx = ssl.create_default_context()
    if APPLE_ROOT.exists():
        ctx.load_verify_locations(str(APPLE_ROOT))
    return ctx


def system_proxy(url):
    """The system HTTPS/HTTP proxy for url, or None. aiohttp only looks up WSS_PROXY for
    wss:// URLs, so the WebSocket would bypass the HTTPS_PROXY that urllib uses."""
    host = urllib.parse.urlsplit(url).hostname or ""
    if urllib.request.proxy_bypass(host):
        return None
    proxies = urllib.request.getproxies()
    scheme = urllib.parse.urlsplit(url).scheme
    return proxies.get(scheme) or proxies.get("https" if scheme in ("https", "wss") else "http")


def _http_json(url, data=None, timeout=20):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "akd/1.0",
                                                          **({"Content-Type": "application/json"} if data else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


class Anisette:
    """One anisette server plus our persistent virtual-device identity for it."""

    def __init__(self, server, state_dir: Path):
        self.server = server.rstrip("/")
        self.state_dir = state_dir
        state_dir.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(self.server.encode()).hexdigest()[:16]
        self.state_path = state_dir / f"anisette-{key}.json"
        self.version = None
        self.client_info = None
        self.user_agent = None
        self._load()

    # ---------- state ----------
    def _load(self):
        try:
            s = json.loads(self.state_path.read_text())
            self.identifier = base64.b64decode(s["identifier"])
            self.adi_pb = base64.b64decode(s["adi_pb"]) if s.get("adi_pb") else None
        except Exception:
            self.identifier = os.urandom(16)
            self.adi_pb = None

    def _save(self):
        self.state_path.write_text(json.dumps({
            "identifier": base64.b64encode(self.identifier).decode(),
            "adi_pb": base64.b64encode(self.adi_pb).decode() if self.adi_pb else None,
        }))
        os.chmod(self.state_path, 0o600)

    def reset(self):
        self.identifier = os.urandom(16)
        self.adi_pb = None
        self._save()

    @property
    def device_id(self):
        return str(uuid.UUID(bytes=self.identifier))

    @property
    def md_lu(self):
        return hashlib.sha256(self.identifier).hexdigest()

    # ---------- discovery ----------
    def detect(self):
        """Figures out the protocol and the client info Apple must see."""
        try:
            info = _http_json(self.server + "/v3/client_info", timeout=12)
            self.version = "v3"
            self.client_info = info["client_info"]
            self.user_agent = info["user_agent"]
            return self
        except Exception:
            pass
        try:
            d = _http_json(self.server + "/", timeout=20)
        except Exception as e:
            raise AnisetteError(f"Anisette server is unreachable: {e}")
        if not d.get("X-Apple-I-MD") or not d.get("X-Apple-I-MD-M"):
            raise AnisetteError("Not an anisette server (no v3 endpoints and no v1 JSON).")
        self.version = "v1"
        self.client_info = d.get("X-MMe-Client-Info") or "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
        self.user_agent = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0"
        self._v1 = d
        return self

    def base_headers(self, json_body=False):
        ct = "application/json" if json_body else "text/x-xml-plist"
        return {"Content-Type": ct, "Accept": ct, "X-Mme-Client-Info": self.client_info,
                "User-Agent": self.user_agent, "X-Xcode-Version": XCODE_VERSION,
                "X-Apple-App-Info": "com.apple.gs.xcode.auth"}

    def url_bag(self):
        req = urllib.request.Request(URL_BAG, headers=self.base_headers())
        with urllib.request.urlopen(req, context=apple_ssl(), timeout=20) as r:
            return plistlib.loads(r.read())["urls"]

    def _apple_plist(self, url, request):
        h = {**self.base_headers(), "X-Apple-I-MD-LU": self.md_lu, "X-Mme-Device-Id": self.device_id,
             "X-Apple-I-Client-Time": _now(), "X-Apple-I-TimeZone": "UTC", "X-Apple-Locale": "en_US"}
        body = plistlib.dumps({"Header": {}, "Request": request})
        req = urllib.request.Request(url, data=body, headers=h, method="POST")
        with urllib.request.urlopen(req, context=apple_ssl(), timeout=30) as r:
            return plistlib.loads(r.read())["Response"]

    # ---------- v3 provisioning ----------
    async def _provision_async(self):
        bag = await asyncio.to_thread(self.url_bag)
        start, finish = bag["midStartProvisioning"], bag["midFinishProvisioning"]
        ws_url = self.server.replace("https://", "wss://").replace("http://", "ws://") + "/v3/provisioning_session"
        async with aiohttp.ClientSession(trust_env=True) as s:
            async with s.ws_connect(ws_url, timeout=aiohttp.ClientWSTimeout(ws_close=10), heartbeat=20,
                                    proxy=system_proxy(self.server)) as ws:
                async for msg in ws:
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        break
                    m = json.loads(msg.data)
                    r = m.get("result")
                    if r == "GiveIdentifier":
                        await ws.send_str(json.dumps({"identifier": base64.b64encode(self.identifier).decode()}))
                    elif r == "GiveStartProvisioningData":
                        resp = await asyncio.to_thread(self._apple_plist, start, {})
                        await ws.send_str(json.dumps({"spim": resp["spim"]}))
                    elif r == "GiveEndProvisioningData":
                        resp = await asyncio.to_thread(self._apple_plist, finish, {"cpim": m["cpim"]})
                        await ws.send_str(json.dumps({"ptm": resp["ptm"], "tk": resp["tk"]}))
                    elif r == "ProvisioningSuccess":
                        self.adi_pb = base64.b64decode(m["adi_pb"])
                        self._save()
                        return
                    else:
                        raise AnisetteError(f"Provisioning failed: {r} {m.get('message', '')}".strip())
        raise AnisetteError("Provisioning socket closed before finishing")

    def provision(self):
        asyncio.run(self._provision_async())

    # ---------- headers ----------
    def headers(self):
        """Fresh anisette headers for one Apple request."""
        if self.version is None:
            self.detect()
        if self.version == "v1":
            d = _http_json(self.server + "/", timeout=20)
            return {"X-Apple-I-MD": d["X-Apple-I-MD"], "X-Apple-I-MD-M": d["X-Apple-I-MD-M"],
                    "X-Apple-I-MD-RINFO": str(d.get("X-Apple-I-MD-RINFO", "17106176")),
                    "X-Apple-I-MD-LU": d.get("X-Apple-I-MD-LU", self.md_lu),
                    "X-Mme-Device-Id": d.get("X-Mme-Device-Id", self.device_id),
                    "X-Apple-I-SRL-NO": "0", "X-Apple-I-Client-Time": _now(),
                    "X-Apple-I-TimeZone": "UTC", "X-Apple-Locale": "en_US"}
        for attempt in range(2):
            if not self.adi_pb:
                self.provision()
            body = json.dumps({"identifier": base64.b64encode(self.identifier).decode(),
                               "adi_pb": base64.b64encode(self.adi_pb).decode()}).encode()
            d = _http_json(self.server + "/v3/get_headers", data=body)
            if d.get("result") == "Headers":
                return {"X-Apple-I-MD": d["X-Apple-I-MD"], "X-Apple-I-MD-M": d["X-Apple-I-MD-M"],
                        "X-Apple-I-MD-RINFO": str(d.get("X-Apple-I-MD-RINFO", "17106176")),
                        "X-Apple-I-MD-LU": self.md_lu, "X-Mme-Device-Id": self.device_id,
                        "X-Apple-I-SRL-NO": "0", "X-Apple-I-Client-Time": _now(),
                        "X-Apple-I-TimeZone": "UTC", "X-Apple-Locale": "en_US"}
            msg = d.get("message", "")
            if attempt == 0:  # -45061 "not provisioned" or stale adi.pb: start over once
                self.reset()
                continue
            raise AnisetteError(f"Anisette server error: {msg}")

    def status(self):
        """Health report for the UI: protocol, client info, and a real header fetch."""
        out = {"server": self.server, "ok": False}
        try:
            self.detect()
            out.update(version=self.version, clientInfo=self.client_info, userAgent=self.user_agent)
            h = self.headers()
            out.update(ok=True, provisioned=bool(self.adi_pb) or self.version == "v1",
                       deviceId=self.device_id, machineId=h["X-Apple-I-MD-M"][:16] + "…")
            out["mac"] = "Mac OS X" in self.client_info or "macOS" in self.client_info
            out["legacy"] = "3594.4.19" in self.client_info
        except Exception as e:
            out["error"] = str(e)
        return out


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
