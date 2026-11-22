#!/bin/sh
# Installs SayoSign Desktop for the current user: builds the signing engine (the engine/
# submodule, which is the SayoSign repository), installs the app with pipx or pip --user,
# and adds a menu entry.
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [ ! -f engine/Makefile ]; then
  git submodule update --init --depth 1 engine
fi
make -C engine -j"$(nproc 2>/dev/null || echo 4)"
mkdir -p sayosign_desktop/bin
cp engine/build/sayosign sayosign_desktop/bin/
if command -v pipx >/dev/null; then
  pipx install --force .
else
  python3 -m pip install --user --break-system-packages . 2>/dev/null || python3 -m pip install --user .
fi
ICON_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"
mkdir -p "$ICON_DIR" "$HOME/.local/share/applications"
cp sayosign_desktop/web/icon.png "$ICON_DIR/sayosign.png"
cat > "$HOME/.local/share/applications/sayosign.desktop" <<DESK
[Desktop Entry]
Name=SayoSign
Comment=Sign and install IPA files on your iPhone
Exec=sayosign-desktop
Icon=sayosign
Terminal=false
Type=Application
Categories=Utility;Development;
DESK
echo "Done. Start SayoSign from the app menu or run: sayosign-desktop"
echo "iPhone not found? Install usbmuxd (Arch: pacman -S usbmuxd, Debian/Ubuntu: apt install usbmuxd)."
