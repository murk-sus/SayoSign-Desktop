"""Certificate library: stores .p12 + .mobileprovision pairs and checks them with Apple OCSP."""
import json
import os
import plistlib
import shutil
import stat
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

COMMON_PASSWORDS = ["", "1", "123", "1234", "12345", "123456", "0000"]
_issuers: dict[str, x509.Certificate] = {}


class CertError(Exception):
    pass


class WrongPassword(CertError):
    pass


def _http(url, data=None, ctype=None):
    req = urllib.request.Request(url, data=data, headers={"Content-Type": ctype} if ctype else {})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read()


def _attr(name, oid):
    v = name.get_attributes_for_oid(oid)
    return v[0].value if v else ""


def load_p12(data: bytes, password: str | None):
    """Returns (cert, extra_certs, password_used). Tries common passwords when none is given."""
    for pw in [password] if password is not None else COMMON_PASSWORDS:
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(data, pw.encode())
        except ValueError:
            continue
        if cert is None or key is None:
            raise CertError("The .p12 has no certificate or private key")
        return cert, extra or [], pw
    raise WrongPassword("Wrong certificate password")


def _issuer(cert, extra):
    for c in extra:
        if c.subject == cert.issuer:
            return c
    aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    for d in aia:
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            url = d.access_location.value
            if url not in _issuers:
                raw = _http(url)
                try:
                    _issuers[url] = x509.load_der_x509_certificate(raw)
                except ValueError:
                    _issuers[url] = x509.load_pem_x509_certificate(raw)
            return _issuers[url]
    return None


def ocsp_status(cert, extra=()):
    """'GOOD' | 'REVOKED' | 'UNKNOWN', plus revocation time."""
    try:
        issuer = _issuer(cert, list(extra))
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        url = next(d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP)
        req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
        resp = ocsp.load_der_ocsp_response(
            _http(url, req.public_bytes(serialization.Encoding.DER), "application/ocsp-request"))
        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return {"status": "UNKNOWN"}
        st = resp.certificate_status
        if st == ocsp.OCSPCertStatus.REVOKED:
            return {"status": "REVOKED", "revokedAt": resp.revocation_time_utc.isoformat()}
        return {"status": "GOOD" if st == ocsp.OCSPCertStatus.GOOD else "UNKNOWN"}
    except Exception as e:  # offline or Apple hiccup
        return {"status": "UNKNOWN", "error": str(e)}


def parse_profile(data: bytes) -> dict:
    a, b = data.find(b"<?xml"), data.find(b"</plist>")
    if a < 0 or b < 0:
        raise CertError("Invalid provisioning profile")
    p = plistlib.loads(data[a:b + 8])
    ent = p.get("Entitlements", {})
    if p.get("ProvisionsAllDevices"):
        kind = "enterprise"
    elif p.get("ProvisionedDevices") is not None:
        kind = "development" if ent.get("get-task-allow") else "ad-hoc"
    else:
        kind = "app-store"
    app_id = ent.get("application-identifier", "")
    prefix = (p.get("ApplicationIdentifierPrefix") or [""])[0]
    exp = p.get("ExpirationDate")
    return {
        "name": p.get("Name"),
        "type": kind,
        "expires": exp.replace(tzinfo=timezone.utc).isoformat() if exp else None,
        "devices": p.get("ProvisionedDevices") or [],
        "allDevices": bool(p.get("ProvisionsAllDevices")),
        "appId": app_id[len(prefix) + 1:] if prefix and app_id.startswith(prefix + ".") else app_id,
        "certs": p.get("DeveloperCertificates") or [],
    }


class CertStore:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, stat.S_IRWXU)

    def _dir(self, cid: str) -> Path:
        d = (self.root / cid).resolve()
        if d.parent != self.root.resolve():
            raise CertError("bad id")
        return d

    def add(self, p12: bytes, profile: bytes, password: str | None, nickname: str = "") -> dict:
        cert, extra, pw = load_p12(p12, password)
        prof = parse_profile(profile)
        der = cert.public_bytes(serialization.Encoding.DER)
        if der not in prof["certs"]:
            raise CertError("This profile was not made for this certificate")
        cid = uuid.uuid4().hex[:12]
        d = self._dir(cid)
        d.mkdir()
        (d / "cert.p12").write_bytes(p12)
        (d / "profile.mobileprovision").write_bytes(profile)
        meta = {"password": pw, "nickname": nickname, "added": datetime.now(timezone.utc).isoformat()}
        (d / "meta.json").write_text(json.dumps(meta))
        for f in d.iterdir():
            os.chmod(f, stat.S_IRUSR | stat.S_IWUSR)
        return self.info(cid, check=True)

    def info(self, cid: str, check: bool = False) -> dict:
        d = self._dir(cid)
        meta = json.loads((d / "meta.json").read_text())
        cert, extra, _ = load_p12((d / "cert.p12").read_bytes(), meta["password"])
        prof = parse_profile((d / "profile.mobileprovision").read_bytes())
        prof.pop("certs")
        out = {
            "id": cid,
            "nickname": meta.get("nickname", ""),
            "name": _attr(cert.subject, NameOID.COMMON_NAME),
            "team": _attr(cert.subject, NameOID.ORGANIZATION_NAME),
            "teamId": _attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
            "serial": format(cert.serial_number, "X"),
            "expires": cert.not_valid_after_utc.isoformat(),
            "profile": prof,
            "ocsp": meta.get("ocsp"),
        }
        if check:
            out["ocsp"] = ocsp_status(cert, extra)
            out["ocsp"]["checked"] = datetime.now(timezone.utc).isoformat()
            meta["ocsp"] = out["ocsp"]
            (d / "meta.json").write_text(json.dumps(meta))
        return out

    def list(self) -> list[dict]:
        out = []
        for d in sorted(self.root.iterdir(), key=lambda p: p.stat().st_mtime):
            if (d / "meta.json").exists():
                try:
                    out.append(self.info(d.name))
                except Exception as e:
                    out.append({"id": d.name, "error": str(e)})
        return out

    def paths(self, cid: str):
        d = self._dir(cid)
        meta = json.loads((d / "meta.json").read_text())
        return d / "cert.p12", d / "profile.mobileprovision", meta["password"]

    def remove(self, cid: str):
        shutil.rmtree(self._dir(cid))
