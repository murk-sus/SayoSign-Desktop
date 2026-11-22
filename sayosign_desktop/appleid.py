"""Sign in to a free or paid Apple Developer account from the desktop.

Faithful port of SayoSign's iOS GrandSlam flow. The SRP-6a here is byte-for-byte
verified against the C engine's tested implementation. It needs an anisette server
(host your own with https://github.com/Dadoum/anisette-v3-server or use a public one).
"""
import hashlib
import json
import plistlib
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

GSA = "https://gsa.apple.com/grandslam/GsService2"
DEV = "https://developerservices2.apple.com/services/QH65B2"
CLIENT_ID = "XABBG36SBA"
APP = "com.apple.gs.xcode.auth"

# RFC 5054 2048-bit group, g = 2
_N = int(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED"
    "8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3"
    "661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA7"
    "1D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE5329"
    "9CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F5475"
    "9B65E372FCD68EF20FA7111F9E4AFF73", 16)
_G = 2


class AppleIDError(Exception):
    pass


def _h(*parts):
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def _i2b(x, n):
    return x.to_bytes(n, "big")


class _SRP:
    """GrandSlam SRP-6a client (SHA-256, no identity in x), matching the C engine."""

    def __init__(self, a_bytes):
        self.a = int.from_bytes(a_bytes, "big")
        self.A = pow(_G, self.a, _N)
        self.Ab = _i2b(self.A, 256)

    def process(self, username, pass_key, salt, B):
        Bn = (int.from_bytes(B, "big")) % _N
        if Bn == 0:
            raise AppleIDError("bad SRP B")
        k = int.from_bytes(_h(_i2b(_N, 256), _i2b(_G, 256)), "big")
        u = int.from_bytes(_h(self.Ab, _i2b(Bn, 256)), "big")
        x = int.from_bytes(_h(salt, _h(b":", pass_key)), "big")
        v = pow(_G, x, _N)
        base = (Bn - k * v) % _N
        S = pow(base, self.a + u * x, _N)
        self.K = _h(_i2b(S, 256).lstrip(b"\x00"))
        hn = int.from_bytes(_h(_i2b(_N, 256)), "big") ^ int.from_bytes(_h(bytes([_G])), "big")
        self.M1 = _h(_i2b(hn, 32), _h(username.encode()), salt, self.Ab, _i2b(Bn, 256), self.K)
        self.M2 = _h(self.Ab, self.M1, self.K)


class Anisette:
    def __init__(self, headers, device_id):
        self.headers = headers
        self.device_id = device_id

    @staticmethod
    def fetch(server, device_id):
        req = urllib.request.Request(server, headers={"User-Agent": "akd/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                raw = r.read()
                hdr = {k: v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            raise AppleIDError(f"The anisette server returned HTTP {e.code}. It may be down or blocked — "
                               f"try a different one, or self-host anisette-v3-server.")
        except urllib.error.URLError as e:
            raise AppleIDError(f"Cannot reach the anisette server ({server}). Check the URL or your connection.")
        md = hdr.get("X-Apple-I-MD")
        if not md:
            try:
                j = json.loads(raw)
                hdr.update({k: v for k, v in j.items() if k.startswith("X-Apple")})
            except Exception:
                pass
        if not hdr.get("X-Apple-I-MD") or not hdr.get("X-Apple-I-MD-M"):
            raise AppleIDError("Anisette server is missing machine data. Use a v1/v3 server.")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        hdr.setdefault("X-Apple-I-Client-Time", now)
        hdr.setdefault("X-Apple-Locale", "en_US")
        hdr.setdefault("X-Apple-I-TimeZone", "UTC")
        hdr.setdefault("X-Apple-I-MD-LU", hashlib.sha256(device_id.encode()).hexdigest())
        hdr.setdefault("X-Apple-I-MD-RINFO", "17106176")
        hdr.setdefault("X-Apple-I-SRL-NO", "0")
        hdr.setdefault("X-Mme-Device-Id", device_id)
        return Anisette(hdr, device_id)

    _KEYS = ["X-Apple-I-Client-Time", "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU",
             "X-Apple-I-MD-RINFO", "X-Apple-I-SRL-NO", "X-Apple-I-TimeZone", "X-Apple-Locale", "X-Mme-Device-Id"]

    @property
    def cpd(self):
        d = {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud",
             "X-Apple-I-Client-Time": self.headers["X-Apple-I-Client-Time"],
             "loc": self.headers.get("X-Apple-Locale", "en_US")}
        for k in self._KEYS:
            if k in self.headers:
                d[k] = self.headers[k]
        return d

    def apply(self, req):
        for k in self._KEYS:
            if k in self.headers:
                req.add_header(k, self.headers[k])
        req.add_header("Loc", self.headers.get("X-Apple-Locale", "en_US"))

    @property
    def client_info(self):
        # Apple began rejecting Mac/Xcode and Android client-info in Oct 2026 (-80045);
        # Windows identity is currently accepted. Prefer the anisette server's own value.
        return self.headers.get("X-MMe-Client-Info",
                                "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/7.21)>")


# Apple error codes seen since the Oct 2026 GrandSlam tightening.
_EC_HELP = {
    -20209: "Apple temporarily locked this Apple ID after repeated sign-in attempts. "
            "Wait a few hours and use a spare Apple ID, not your main account.",
    -80045: "Apple rejected the anisette data (it must come from a macOS/Windows source "
            "with matching client info). Try a different anisette server.",
    -22406: "Wrong Apple ID or password.",
    -22421: "The two-factor code is wrong or expired.",
}


def _gsa_error(ec, em=None):
    msg = _EC_HELP.get(ec, em or f"Apple error {ec}")
    return AppleIDError(msg)


def _post_gsa(anisette, body):
    payload = {"Header": {"Version": "1.0.1"},
               "Request": {**body, "cpd": body.get("cpd", anisette.cpd)}}
    data = plistlib.dumps(payload)
    req = urllib.request.Request(GSA, data=data, method="POST")
    req.add_header("Content-Type", "text/x-xml-plist")
    req.add_header("Accept", "*/*")
    req.add_header("User-Agent", "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0")
    req.add_header("X-MMe-Client-Info", anisette.client_info)
    req.add_header("Connection", "close")  # Apple edge drops pooled/keep-alive connections
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            resp = plistlib.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 503:
            raise AppleIDError("Apple's GrandSlam server returned 503. The anisette server is "
                               "likely rejected — switch to a Mac-backed or self-hosted anisette server.")
        raise AppleIDError(f"Apple sign-in failed (HTTP {e.code}).")
    out = resp.get("Response", resp)
    status = out.get("Status", {})
    ec = status.get("ec", 0)
    if ec not in (0, None):
        raise _gsa_error(ec, status.get("em"))
    return out


class GSAuth:
    def __init__(self, anisette, email, password):
        self.an = anisette
        self.email = email
        self.password = password

    def login(self):
        import os
        srp = _SRP(os.urandom(32))
        init = _post_gsa(self.an, {"A2k": srp.Ab, "cpd": self.an.cpd, "o": "init",
                                   "ps": ["s2k", "s2k_fo"], "u": self.email})
        sp, it, salt, B, c = init.get("sp"), init.get("i"), init.get("s"), init.get("B"), init.get("c")
        if not all([sp, it, salt, B, c]):
            raise AppleIDError("Apple did not accept the login request")
        hashed = hashlib.sha256(self.password.encode()).digest()
        pw_input = hashed.hex().encode() if sp == "s2k_fo" else hashed
        pass_key = hashlib.pbkdf2_hmac("sha256", pw_input, salt, it, 32)
        srp.process(self.email, pass_key, salt, B)
        comp = _post_gsa(self.an, {"M1": srp.M1, "c": c, "cpd": self.an.cpd, "o": "complete", "u": self.email})
        if comp.get("M2") and comp["M2"] != srp.M2:
            raise AppleIDError("Apple server proof mismatch")
        spd = comp.get("spd")
        if not spd:
            raise AppleIDError("Wrong Apple ID or password")
        key = _hmac(srp.K, b"extra data key:")
        iv = _hmac(srp.K, b"extra data iv:")[:16]
        dec = _cbc_decrypt(key, iv, spd)
        sd = plistlib.loads(dec)
        self.session = {"adsid": sd["adsid"], "idms": sd["GsIdmsToken"], "sk": sd["sk"], "c": sd["c"]}
        au = comp.get("Status", {}).get("au")
        self.second = {"trustedDeviceSecondaryAuth": "trusted", "secondaryAuth": "sms"}.get(au)
        return self.second

    def _auth_req(self, url, method, json_body=False):
        import base64
        req = urllib.request.Request(url, method=method)
        ident = base64.b64encode(f"{self.session['adsid']}:{self.session['idms']}".encode()).decode()
        req.add_header("X-Apple-Identity-Token", ident)
        req.add_header("X-Apple-App-Info", APP)
        req.add_header("X-Xcode-Version", "11.2 (11B41)")
        ct = "application/json" if json_body else "text/x-xml-plist"
        req.add_header("Content-Type", ct)
        req.add_header("Accept", ct)
        req.add_header("User-Agent", "Xcode")
        req.add_header("Connection", "close")
        self.an.apply(req)
        return req

    def request_code(self):
        if self.second == "trusted":
            urllib.request.urlopen(self._auth_req("https://gsa.apple.com/auth/verify/trusteddevice", "GET"), timeout=30)
        else:
            urllib.request.urlopen(self._auth_req("https://gsa.apple.com/auth", "GET", True), timeout=30)
            req = self._auth_req("https://gsa.apple.com/auth/verify/phone", "PUT", True)
            req.data = json.dumps({"phoneNumber": {"id": 1}, "mode": "sms"}).encode()
            urllib.request.urlopen(req, timeout=30)

    def submit_code(self, code):
        if self.second == "trusted":
            req = self._auth_req("https://gsa.apple.com/grandslam/GsService2/validate", "GET")
            req.add_header("security-code", code)
            with urllib.request.urlopen(req, timeout=30) as r:
                p = plistlib.loads(r.read())
            if p.get("ec", 0):
                raise AppleIDError(p.get("em") or "Wrong code")
        else:
            req = self._auth_req("https://gsa.apple.com/auth/verify/phone/securitycode", "POST", True)
            req.data = json.dumps({"phoneNumber": {"id": 1}, "securityCode": {"code": code}, "mode": "sms"}).encode()
            urllib.request.urlopen(req, timeout=30)
        # Re-login to fold the trust token into a fresh session.
        self.login()

    def xcode_token(self):
        s = self.session
        checksum = _hmac(s["sk"], b"apptokens" + s["adsid"].encode() + APP.encode())
        resp = _post_gsa(self.an, {"app": [APP], "c": s["c"], "checksum": checksum, "cpd": self.an.cpd,
                                   "o": "apptokens", "t": s["idms"], "u": s["adsid"]})
        et = resp.get("et")
        if not et:
            raise AppleIDError("Apple did not return an app token")
        dec = _gcm_decrypt(s["sk"], et)
        p = plistlib.loads(dec)
        x = p["t"][APP]
        exp = datetime.fromtimestamp(x["expiry"] / 1000, timezone.utc) if x.get("expiry") else datetime.now(timezone.utc) + timedelta(days=7)
        return {"adsid": s["adsid"], "idms": s["idms"], "token": x["token"], "expiry": exp.isoformat(), "email": self.email}


def _hmac(key, msg):
    import hmac
    return hmac.new(key, msg, hashlib.sha256).digest()


def _cbc_decrypt(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = c.update(data) + c.finalize()
    return out[:-out[-1]] if out and out[-1] <= 16 else out


def _gcm_decrypt(key, blob):
    # blob = b"XYZ" + version(1) + iv(16) + ciphertext + tag(16)
    iv, ct, tag = blob[3:3 + 16], blob[3 + 16:-16], blob[-16:]
    c = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return c.update(ct) + c.finalize()


class DeveloperAPI:
    def __init__(self, session, anisette):
        self.s = session
        self.an = anisette

    def call(self, action, ios=True, **params):
        path = f"ios/{action}.action" if ios else f"{action}.action"
        body = {**params, "clientId": CLIENT_ID, "protocolVersion": "QH65B2",
                "requestId": str(uuid.uuid4()).upper()}
        req = urllib.request.Request(f"{DEV}/{path}?clientId={CLIENT_ID}", data=plistlib.dumps(body), method="POST")
        for k, v in {"Content-Type": "text/x-xml-plist", "Accept": "text/x-xml-plist",
                     "Accept-Language": "en-us", "User-Agent": "Xcode", "X-Apple-App-Info": APP,
                     "X-Xcode-Version": "11.2 (11B41)", "X-Apple-I-Identity-Id": self.s["adsid"],
                     "X-Apple-GS-Token": self.s["token"], "Connection": "close"}.items():
            req.add_header(k, v)
        self.an.apply(req)
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                p = plistlib.loads(r.read())
        except urllib.error.HTTPError as e:
            raise AppleIDError(f"Apple developer services returned HTTP {e.code}.")
        if p.get("resultCode", 0):
            raise AppleIDError(p.get("userString") or p.get("resultString") or f"error {p['resultCode']}")
        return p

    def teams(self):
        return self.call("listTeams", ios=False).get("teams", [])

    def ensure_device(self, team, udid, name="iPhone"):
        devs = self.call("listDevices", teamId=team).get("devices", [])
        if any((d.get("deviceNumber") or "").upper() == udid.upper() for d in devs):
            return
        self.call("addDevice", teamId=team, deviceNumber=udid, name=name)

    def create_certificate(self, team):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SayoSign")])).sign(key, hashes.SHA256())
        pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        existing = self.call("listAllDevelopmentCerts", teamId=team).get("certificates", [])
        for c in existing:
            if c.get("machineName") == "SayoSign" and c.get("serialNumber"):
                try:
                    self.call("revokeDevelopmentCert", teamId=team, serialNumber=c["serialNumber"])
                except AppleIDError:
                    pass
        try:
            submit = self.call("submitDevelopmentCSR", teamId=team, csrContent=pem,
                               machineId=self.an.device_id, machineName="SayoSign")
        except AppleIDError:
            if existing and existing[0].get("serialNumber"):
                self.call("revokeDevelopmentCert", teamId=team, serialNumber=existing[0]["serialNumber"])
                return self.create_certificate(team)
            raise
        req = submit.get("certRequest", {})
        content = req.get("certContent")
        if not content:
            serial = req.get("serialNumber")
            for c in self.call("listAllDevelopmentCerts", teamId=team).get("certificates", []):
                if c.get("serialNumber") == serial and c.get("certContent"):
                    content = c["certContent"]
                    break
        if not content:
            raise AppleIDError("Apple did not return the certificate")
        cert = x509.load_der_x509_certificate(content)
        return key, cert

    def profile(self, team, bundle_id, name="SayoSign App"):
        ids = self.call("listAppIds", teamId=team).get("appIds", [])
        app_id = next((a.get("appIdId") for a in ids if a.get("identifier") == bundle_id), None)
        if not app_id:
            safe = "".join(ch for ch in name if ch.isalnum() or ch == " ").strip() or "SayoSign App"
            resp = self.call("addAppId", teamId=team, identifier=bundle_id, name=safe)
            app_id = resp.get("appId", {}).get("appIdId")
        if not app_id:
            raise AppleIDError("Cannot register the App ID")
        resp = self.call("downloadTeamProvisioningProfile", teamId=team, appIdId=app_id)
        enc = resp.get("provisioningProfile", {}).get("encodedProfile")
        if not enc:
            raise AppleIDError("Apple did not return a provisioning profile")
        return enc


def bundle_p12(key, cert, password=""):
    return pkcs12.serialize_key_and_certificates(
        b"SayoSign", key, cert, None,
        serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption())
