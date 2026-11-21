import { openZip } from "./zip.js";
import { parsePlist, parseProvision } from "./plist.js";
import { slices, parseMachO, headerSpan, injectedLibs } from "./macho.js";
import { uncrush } from "./png.js";

const HOOK_FRAMEWORKS = /^(CydiaSubstrate|ellekit|libhooker|substitute|Orion|Cephei|CepheiPrefs|AltList)\.framework$/i;

export function summarizeProvision(p) {
  const ent = p.Entitlements || {};
  const type = p.ProvisionsAllDevices ? "enterprise"
    : p.ProvisionedDevices ? (ent["get-task-allow"] ? "development" : "ad-hoc")
    : "app-store";
  const appId = ent["application-identifier"] || "";
  const prefix = (p.ApplicationIdentifierPrefix || [])[0] || "";
  return {
    name: p.Name,
    appIdName: p.AppIDName,
    team: p.TeamName,
    teamId: (p.TeamIdentifier || [])[0],
    type,
    created: p.CreationDate,
    expires: p.ExpirationDate,
    devices: p.ProvisionedDevices || [],
    allDevices: !!p.ProvisionsAllDevices,
    bundlePattern: prefix && appId.startsWith(prefix + ".") ? appId.slice(prefix.length + 1) : appId,
    wildcard: appId.endsWith("*"),
    entitlements: ent,
    certCount: (p.DeveloperCertificates || []).length,
    certs: p.DeveloperCertificates || [],
    uuid: p.UUID,
  };
}

export async function inspectProvisionFile(buf) {
  return summarizeProvision(parseProvision(buf));
}

async function readBinary(zip, path) {
  const e = zip.entries.get(path);
  if (!e) return null;
  let head = await zip.read(e, 65536);
  const need = Math.min(e.size, headerSpan(head));
  if (need > head.length) head = await zip.read(e, need);
  const out = { size: e.size, slices: [] };
  for (const s of slices(head)) {
    if (s.offset + 32 > head.length) continue;
    try { out.slices.push(parseMachO(head, s.offset)); } catch { /* not Mach-O */ }
  }
  return out;
}

function pickIcon(info, appDir, names) {
  const files = new Set();
  const collect = (icons) => {
    const prim = icons && icons.CFBundlePrimaryIcon;
    for (const f of (prim && prim.CFBundleIconFiles) || []) files.add(f);
    if (prim && prim.CFBundleIconName) files.add(prim.CFBundleIconName);
  };
  collect(info.CFBundleIcons);
  collect(info["CFBundleIcons~ipad"]);
  for (const f of info.CFBundleIconFiles || []) files.add(f);
  if (info.CFBundleIconFile) files.add(info.CFBundleIconFile);

  const pngs = names.filter((n) => n.startsWith(appDir) && !n.slice(appDir.length).includes("/") && n.endsWith(".png"));
  let best = null, bestScore = -1;
  for (const n of pngs) {
    const base = n.slice(appDir.length);
    const hit = [...files].some((f) => base.startsWith(f.replace(/\.png$/, "")));
    if (!hit && !/^AppIcon/i.test(base)) continue;
    const m = base.match(/(\d+)(?:x\d+)?(?:@(\d)x)?/);
    const score = m ? Number(m[1]) * Number(m[2] || 1) : 1;
    if (score > bestScore) { best = n; bestScore = score; }
  }
  return best;
}

export async function inspectIPA(blob) {
  const zip = await openZip(blob);
  const names = zip.names();
  const plistPath = names
    .filter((n) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(n))
    .sort((a, b) => a.length - b.length)[0];
  if (!plistPath) throw new Error("No Payload/*.app/Info.plist — this is not an IPA");
  const appDir = plistPath.slice(0, -"Info.plist".length);
  const info = parsePlist(await zip.read(plistPath));

  const r = {
    kind: "ipa",
    fileSize: blob.size,
    installedSize: [...zip.entries.values()].reduce((n, e) => n + e.size, 0),
    appDir,
    name: info.CFBundleDisplayName || info.CFBundleName || info.CFBundleExecutable,
    bundleId: info.CFBundleIdentifier,
    version: info.CFBundleShortVersionString,
    build: info.CFBundleVersion,
    minOS: info.MinimumOSVersion,
    executable: info.CFBundleExecutable,
    devices: (info.UIDeviceFamily || []).map((d) => ({ 1: "iPhone", 2: "iPad", 3: "TV", 4: "Watch", 6: "Mac", 7: "Vision" })[d] || d),
    urlSchemes: (info.CFBundleURLTypes || []).flatMap((t) => t.CFBundleURLSchemes || []),
    fileSharing: !!(info.UIFileSharingEnabled || info.LSSupportsOpeningDocumentsInPlace),
    privacy: Object.fromEntries(Object.entries(info).filter(([k]) => /^NS.*UsageDescription$/.test(k))),
    info,
  };

  const inApp = (sub) => names.filter((n) => n.startsWith(appDir + sub));
  const topLevel = (list, re) =>
    [...new Set(list.map((n) => n.slice(appDir.length).split("/").slice(0, 2).join("/")).filter((n) => re.test(n)))];
  r.frameworks = topLevel(inApp("Frameworks/"), /^Frameworks\/[^/]+\.(framework|dylib)$/).map((n) => n.split("/")[1]);
  r.plugins = topLevel(inApp("PlugIns/"), /^PlugIns\/[^/]+\.appex$/).map((n) => n.split("/")[1]);
  r.extensionKit = topLevel(inApp("Extensions/"), /^Extensions\/[^/]+\.appex$/).map((n) => n.split("/")[1]);
  r.watch = topLevel(inApp("Watch/"), /^Watch\/[^/]+\.app$/).map((n) => n.split("/")[1]);
  r.looseDylibs = names.filter((n) => n.startsWith(appDir) && n.endsWith(".dylib") && !n.includes("/Frameworks/libswift"))
    .map((n) => n.slice(appDir.length));
  r.hookFrameworks = r.frameworks.filter((f) => HOOK_FRAMEWORKS.test(f));
  r.signed = names.includes(appDir + "_CodeSignature/CodeResources");
  r.hasSCInfo = names.some((n) => n.startsWith(appDir + "SC_Info/"));

  const bin = await readBinary(zip, appDir + r.executable);
  if (bin) {
    r.binarySize = bin.size;
    r.slices = bin.slices;
    r.archs = bin.slices.map((s) => s.arch);
    r.encrypted = bin.slices.some((s) => s.encrypted);
    const libs = [...new Set(bin.slices.flatMap((s) => [...s.dylibs, ...s.weak]))];
    r.linked = libs;
    r.injected = injectedLibs(libs);
  }

  const prov = await zip.read(appDir + "embedded.mobileprovision");
  if (prov) {
    try { r.provision = summarizeProvision(parseProvision(prov)); } catch { /* corrupt */ }
  }

  const iconPath = pickIcon(info, appDir, names);
  if (iconPath) {
    try { r.icon = await uncrush(await zip.read(iconPath)); } catch { /* unreadable */ }
  }
  r.tweaked = !!(r.injected?.length || r.hookFrameworks.length);
  return r;
}

export function sourceEntry(r, { downloadURL = "", developer = "", iconURL = "" } = {}) {
  return {
    name: r.name,
    bundleIdentifier: r.bundleId,
    developerName: developer,
    version: r.version,
    versionDate: new Date().toISOString().slice(0, 10),
    downloadURL,
    localizedDescription: r.name,
    iconURL,
    size: r.fileSize,
    versions: [{
      version: r.version,
      buildVersion: r.build,
      date: new Date().toISOString().slice(0, 10),
      downloadURL,
      size: r.fileSize,
      minOSVersion: r.minOS,
    }],
    appPermissions: {
      entitlements: [],
      privacy: r.privacy,
    },
  };
}
