# SayoSign Desktop

Sign and install IPA files on your iPhone from **Linux**, Windows or macOS. An open alternative to Sideloadly, built on the SayoSign signing engine.

- Drop an IPA: name, icon, version, minimum iOS, **decrypted or not**, injected tweaks, shown before you sign (IPALens inside).
- Certificate library: `.p12` + `.mobileprovision` pairs, **live revocation check with Apple (OCSP)**, expiry, "is my iPhone in this profile?". Common passwords are tried automatically.
- Options: name, bundle ID, version, inject `.deb` / `.dylib` tweaks, remove extensions and Watch apps, Files sharing, compression.
- **Sign & install** over USB (or Wi-Fi sync) with live progress, or sign only and download.
- Installed apps on your iPhone, with uninstall.
- English, Русский, 中文. Light and dark.

## Install

**Linux**

```sh
git clone https://github.com/murk-sus/SayoSign && cd SayoSign
./desktop/install-linux.sh
sayosign-desktop
```

Needs `usbmuxd` (Arch: `pacman -S usbmuxd`, Debian/Ubuntu: `apt install usbmuxd`), Python 3.10+, OpenSSL headers, zlib and liblzma to build the engine.

**Windows / macOS**: grab the build from [Releases](https://github.com/murk-sus/SayoSign/releases). On Windows, install iTunes (or Apple Devices) so the iPhone driver is present.

**From source, any OS**

```sh
make                                  # builds build/sayosign
pip install ./desktop                 # or: pip install './desktop[window]' for a native window
sayosign-desktop
```

## How it works

A small local server (`127.0.0.1` only, random token per launch) runs the `sayosign` engine for signing and [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) for installs. The interface opens in a native window when `pywebview` is installed, otherwise in your browser. Certificates are stored in your user config folder with owner-only permissions.

Your certificates and IPAs never leave your computer.
