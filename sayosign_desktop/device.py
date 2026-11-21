"""iPhone access over USB/Wi-Fi through usbmuxd (pymobiledevice3)."""
from pathlib import Path

from pymobiledevice3 import usbmux
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService


async def _lockdown(udid: str):
    return await create_using_usbmux(serial=udid, autopair=True)


async def list_devices() -> list[dict]:
    seen = {}
    for d in await usbmux.list_devices():
        if d.serial in seen and seen[d.serial]["connection"] == "USB":
            continue
        info = {"udid": d.serial, "connection": "USB" if d.is_usb else "Wi-Fi"}
        try:
            ld = await _lockdown(d.serial)
            v = ld.all_values
            info.update(
                name=v.get("DeviceName"),
                model=v.get("ProductType"),
                ios=v.get("ProductVersion"),
                build=v.get("BuildVersion"),
                paired=True,
            )
            await ld.close()
        except Exception as e:
            info.update(paired=False, error=str(e) or type(e).__name__)
        seen[d.serial] = info
    return list(seen.values())


async def list_apps(udid: str) -> list[dict]:
    ld = await _lockdown(udid)
    try:
        svc = InstallationProxyService(lockdown=ld)
        apps = await svc.get_apps(application_type="User")
        out = []
        for bid, a in apps.items():
            out.append({
                "bundleId": bid,
                "name": a.get("CFBundleDisplayName") or a.get("CFBundleName") or bid,
                "version": a.get("CFBundleShortVersionString"),
                "signer": a.get("SignerIdentity"),
                "profileValidated": a.get("ProfileValidated"),
            })
        return sorted(out, key=lambda x: (x["name"] or "").lower())
    finally:
        await ld.close()


async def install(udid: str, ipa: Path, progress) -> None:
    ld = await _lockdown(udid)
    try:
        svc = InstallationProxyService(lockdown=ld)
        await svc.install_from_local(ipa, handler=lambda pct, *a: progress(pct))
    finally:
        await ld.close()


async def uninstall(udid: str, bundle_id: str) -> None:
    ld = await _lockdown(udid)
    try:
        await InstallationProxyService(lockdown=ld).uninstall(bundle_id)
    finally:
        await ld.close()
