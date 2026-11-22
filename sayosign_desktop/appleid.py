"""Sign in to a free or paid Apple Developer account from the desktop.

GrandSlam (SRP-6a, byte-for-byte verified against the C engine) on top of the anisette
v3 client in anisette.py. Endpoints come from Apple's URL bag; every request carries the
client info of the anisette server, which Apple requires since October 2026.
"""
import hashlib
import json
import plistlib
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from .anisette import Anisette, AnisetteError, apple_ssl

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


# Human-readable messages for common GrandSlam error codes.
GSA_ERRORS = {
    -20101: "Wrong Apple ID or password",
    -22406: "Wrong Apple ID or password",
    -20209: "This Apple ID is locked. Unlock it at iforgot.apple.com",
    -20751: "This Apple ID is locked. Unlock it at iforgot.apple.com",
    -80045: "Apple rejected the anisette data. Use a Mac-based anisette server (e.g. ani.iloader.app)",
    -80046: "Apple rejected the anisette data. Reset anisette and try a Mac-based server",
    -45061: "Anisette is not provisioned for this server. Reset anisette and try again",
    -22410: "Too many attempts. Wait a few minutes and try again",
    -22411: "Apple is limiting sign-ins right now. Try again later",
}


def _gsa_error(status):
    ec = status.get("ec", 0)
    if not ec:
        return None
    msg = GSA_ERRORS.get(ec) or status.get("em") or "Apple error"
    return AppleIDError(f"{msg} ({ec})")


class Session:
    """Anisette + Apple's URL bag, shared by every request in one sign-in."""

    def __init__(self, anisette: Anisette):
        self.an = anisette.detect()
        self.bag = self.an.url_bag()

    def url(self, key):
        u = self.bag.get(key)
        if not u:
            raise AppleIDError(f"Apple's URL bag has no '{key}'")
        return u

    def cpd(self, h):
        d = {"bootstrap": True, "icscrec": True, "loc": "en_US", "pbe": False, "prkgen": True, "svct": "iCloud"}
        d.update({k: v for k, v in h.items() if k in ("X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id",
                                                        "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Apple-I-SRL-NO",
                                                        "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale")})
        return d

    def gsa(self, request):
        h = self.an.headers()
        request = {**request, "cpd": self.cpd(h)}
        body = plistlib.dumps({"Header": {"Version": "1.0.1"}, "Request": request})
        req = urllib.request.Request(self.url("gsService"), data=body, method="POST",
                                     headers={**self.an.base_headers(), "Connection": "close"})
        try:
            with urllib.request.urlopen(req, context=apple_ssl(), timeout=30) as r:
                resp = plistlib.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (500, 503):
                raise AppleIDError(f"Apple answered {e.code}. This usually means the anisette data was rejected; "
                                   "switch to a Mac-based anisette server and reset anisette.")
            raise
        out = resp.get("Response", resp)
        err = _gsa_error(out.get("Status", {}))
        if err:
            raise err
        return out

    def request(self, url, method, extra, json_body=False, data=None):
        h = {**self.an.base_headers(json_body), **self.an.headers(), **extra}
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        return urllib.request.urlopen(req, context=apple_ssl(), timeout=30)


class GSAuth:
    def __init__(self, session: Session, email, password):
        self.s = session
        self.email = email
        self.password = password
        self.second = None

    def login(self):
        import os
        srp = _SRP(os.urandom(32))
        init = self.s.gsa({"A2k": srp.Ab, "o": "init", "ps": ["s2k", "s2k_fo"], "u": self.email})
        sp, it, salt, B, c = init.get("sp"), init.get("i"), init.get("s"), init.get("B"), init.get("c")
        if sp not in ("s2k", "s2k_fo") or not all([it, salt, B, c]):
            raise AppleIDError("Apple did not accept the login request")
        hashed = hashlib.sha256(self.password.encode()).digest()
        pw_input = hashed.hex().encode() if sp == "s2k_fo" else hashed
        pass_key = hashlib.pbkdf2_hmac("sha256", pw_input, salt, it, 32)
        srp.process(self.email, pass_key, salt, B)
        comp = self.s.gsa({"M1": srp.M1, "c": c, "o": "complete", "u": self.email})
        if comp.get("M2") and comp["M2"] != srp.M2:
            raise AppleIDError("Apple server proof mismatch")
        spd = comp.get("spd")
        if not spd:
            raise AppleIDError("Wrong Apple ID or password")
        key = _hmac(srp.K, b"extra data key:")
        iv = _hmac(srp.K, b"extra data iv:")[:16]
        sd = plistlib.loads(_cbc_decrypt(key, iv, spd))
        self.session = {"adsid": sd["adsid"], "idms": sd["GsIdmsToken"], "sk": sd["sk"], "c": sd["c"]}
        status = comp.get("Status", {})
        au = status.get("au")
        if au == "trustedDeviceSecondaryAuth":
            self.second = "trusted"
        elif au == "secondaryAuth":
            self.second = "sms"
        elif au and au != "repair":
            raise AppleIDError(f"Apple asks for an extra step: {au}. Finish it on apple.com and try again.")
        else:
            self.second = None
        return self.second

    def _identity(self):
        import base64
        return {"X-Apple-Identity-Token": base64.b64encode(f"{self.session['adsid']}:{self.session['idms']}".encode()).decode()}

    def request_code(self):
        if self.second == "trusted":
            self.s.request(self.s.url("trustedDeviceSecondaryAuth"), "GET", self._identity()).close()
        else:
            self.s.request("https://gsa.apple.com/auth", "GET", self._identity(), json_body=True).close()
            self.s.request("https://gsa.apple.com/auth/verify/phone", "PUT", self._identity(), json_body=True,
                           data=json.dumps({"phoneNumber": {"id": 1}, "mode": "sms"}).encode()).close()

    def submit_code(self, code):
        if self.second == "trusted":
            r = self.s.request(self.s.url("validateCode"), "GET", {**self._identity(), "security-code": code})
            p = plistlib.loads(r.read())
            err = _gsa_error(p.get("Status", p))
            if err:
                raise AppleIDError("Wrong code" if p.get("Status", p).get("ec") in (-21669,) else str(err))
        else:
            try:
                self.s.request("https://gsa.apple.com/auth/verify/phone/securitycode", "POST", self._identity(),
                               json_body=True, data=json.dumps({"phoneNumber": {"id": 1},
                                                                "securityCode": {"code": code}, "mode": "sms"}).encode()).close()
            except urllib.error.HTTPError:
                raise AppleIDError("Wrong code")
        # The trusted session only exists after logging in again.
        self.login()
        if self.second:
            raise AppleIDError("Apple still asks for a code. Try signing in again.")

    def xcode_token(self):
        s = self.session
        checksum = _hmac(s["sk"], b"apptokens" + s["adsid"].encode() + APP.encode())
        resp = self.s.gsa({"app": [APP], "c": s["c"], "checksum": checksum, "o": "apptokens",
                           "t": s["idms"], "u": s["adsid"]})
        et = resp.get("et")
        if not et:
            raise AppleIDError("Apple did not return an app token")
        p = plistlib.loads(_gcm_decrypt(s["sk"], et))
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
    def __init__(self, session, gs: Session):
        self.s = session
        self.gs = gs

    def call(self, action, ios=True, **params):
        path = f"ios/{action}.action" if ios else f"{action}.action"
        body = {"clientId": CLIENT_ID, "protocolVersion": "QH65B2", "requestId": str(uuid.uuid4()).upper(),
                "userLocale": ["en_US"], **params}
        h = {**self.gs.an.base_headers(), **self.gs.an.headers(), "Accept-Language": "en-us",
             "X-Apple-I-Identity-Id": self.s["adsid"], "X-Apple-GS-Token": self.s["token"]}
        req = urllib.request.Request(f"{DEV}/{path}?clientId={CLIENT_ID}", data=plistlib.dumps(body), method="POST", headers=h)
        with urllib.request.urlopen(req, context=apple_ssl(), timeout=40) as r:
            p = plistlib.loads(r.read())
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
                               machineId=self.gs.an.device_id, machineName="SayoSign")
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
