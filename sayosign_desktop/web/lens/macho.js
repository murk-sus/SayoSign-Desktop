// Reads Mach-O headers: architectures, encryption, linked dylibs, minimum OS.
// Only the first few hundred KB of a binary are needed, so callers pass a prefix.

const td = new TextDecoder();
const CPU = { 7: "x86", 12: "armv7", 0x01000007: "x86_64", 0x0100000c: "arm64", 0x0200000c: "arm64_32" };
const PLATFORM = { 1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "Mac Catalyst", 7: "iOS Simulator", 11: "visionOS" };

const ver = (v) => `${v >>> 16}.${(v >> 8) & 255}` + ((v & 255) ? `.${v & 255}` : "");

// Returns { slices: [{offset, size, arch}] } describing a thin or fat binary.
export function slices(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const magic = dv.getUint32(0, false);
  if (magic === 0xcafebabe || magic === 0xcafebabf) {
    const n = dv.getUint32(4, false), wide = magic === 0xcafebabf;
    const out = [];
    for (let i = 0; i < n; i++) {
      const o = 8 + i * (wide ? 32 : 20);
      const cpu = dv.getUint32(o, false), sub = dv.getUint32(o + 4, false) & 0xff;
      const offset = wide ? Number(dv.getBigUint64(o + 8, false)) : dv.getUint32(o + 8, false);
      const size = wide ? Number(dv.getBigUint64(o + 16, false)) : dv.getUint32(o + 12, false);
      out.push({ offset, size, arch: archName(cpu, sub) });
    }
    return out;
  }
  return [{ offset: 0, size: buf.length, arch: null }];
}

function archName(cpu, sub) {
  if (cpu === 0x0100000c && sub === 2) return "arm64e";
  return CPU[cpu] || `cpu ${cpu}`;
}

// Parses one thin Mach-O starting at `off` in `buf`.
export function parseMachO(buf, off = 0) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const magic = dv.getUint32(off, true);
  const is64 = magic === 0xfeedfacf;
  if (!is64 && magic !== 0xfeedface) throw new Error("Not a Mach-O binary");
  const cpu = dv.getUint32(off + 4, true), sub = dv.getUint32(off + 8, true) & 0xff;
  const filetype = dv.getUint32(off + 12, true);
  const ncmds = dv.getUint32(off + 16, true);
  const info = {
    arch: archName(cpu, sub), filetype, encrypted: false, cryptid: null,
    dylibs: [], weak: [], rpaths: [], minOS: null, sdk: null, platform: null, signed: false,
  };
  const cstr = (o) => { let e = o; while (e < buf.length && buf[e]) e++; return td.decode(buf.subarray(o, e)); };
  let p = off + (is64 ? 32 : 28);
  for (let i = 0; i < ncmds && p + 8 <= buf.length; i++) {
    const cmd = dv.getUint32(p, true), size = dv.getUint32(p + 4, true);
    if (size < 8) break;
    switch (cmd & 0x7fffffff) {
      case 0x0c: case 0x18: case 0x1f: case 0x23: { // LOAD_DYLIB, LOAD_WEAK, REEXPORT, LOAD_UPWARD
        const name = cstr(p + dv.getUint32(p + 8, true));
        (cmd === 0x80000018 ? info.weak : info.dylibs).push(name);
        break;
      }
      case 0x1c: info.rpaths.push(cstr(p + dv.getUint32(p + 8, true))); break;
      case 0x21: case 0x2c: { // ENCRYPTION_INFO(_64)
        info.cryptid = dv.getUint32(p + 16, true);
        info.encrypted = info.cryptid !== 0;
        break;
      }
      case 0x25: // VERSION_MIN_IPHONEOS
        info.platform = "iOS"; info.minOS = ver(dv.getUint32(p + 8, true)); info.sdk = ver(dv.getUint32(p + 12, true));
        break;
      case 0x32: { // BUILD_VERSION
        const pl = dv.getUint32(p + 8, true);
        info.platform = PLATFORM[pl] || `platform ${pl}`;
        info.minOS = ver(dv.getUint32(p + 12, true));
        info.sdk = ver(dv.getUint32(p + 16, true));
        break;
      }
      case 0x1d: // CODE_SIGNATURE
        info.signed = true;
        info.sigOff = dv.getUint32(p + 8, true);
        info.sigSize = dv.getUint32(p + 12, true);
        break;
    }
    p += size;
  }
  return info;
}

// Bytes needed from the file start to parse every slice's load commands.
export function headerSpan(buf) {
  return Math.max(...slices(buf).map((s) => s.offset + 65536));
}

// Classifies linked libraries that usually mean an app was modified.
export function injectedLibs(dylibs) {
  const hooks = /substrate|substitute|ellekit|libhooker|sayohook|fishhook|tweakinject/i;
  return dylibs.filter((d) => hooks.test(d) || /^@(executable|loader)_path\/.*\.dylib$/.test(d) ||
    (/^@rpath\/.*\.dylib$/.test(d) && !/libswift/i.test(d)));
}

// Reads entitlements from a code signature SuperBlob (big-endian). Returns XML text or null.
export function entitlementsXML(buf, off, size) {
  if (off + 12 > buf.length) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (dv.getUint32(off) !== 0xfade0cc0) return null;
  const count = dv.getUint32(off + 8);
  for (let i = 0; i < count; i++) {
    const blob = off + dv.getUint32(off + 12 + i * 8 + 4);
    if (blob + 8 > buf.length) continue;
    if (dv.getUint32(blob) === 0xfade7171) {
      const len = dv.getUint32(blob + 4);
      return td.decode(buf.subarray(blob + 8, blob + len));
    }
  }
  return null;
}

// Entitlements that stock iOS only grants to Apple, TrollStore or a jailbreak.
export function privilegedEntitlements(ent) {
  return Object.keys(ent || {}).filter((k) =>
    /^com\.apple\.private\./.test(k) || ["platform-application", "com.apple.security.no-container",
      "com.apple.security.no-sandbox", "task_for_pid-allow", "com.apple.system-task-ports",
      "run-unsigned-code", "dynamic-codesigning", "com.apple.springboard.debugapplications",
      "com.apple.rootless.install", "com.apple.security.exception.files.absolute-path.read-write"].includes(k));
}
