// Property list parser: binary (bplist00) and XML. Dates become Date, data becomes Uint8Array.

const td = new TextDecoder();

export function parsePlist(buf) {
  if (td.decode(buf.subarray(0, 8)) === "bplist00") return parseBinary(buf);
  return parseXML(td.decode(buf));
}

function parseBinary(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const t = buf.length - 32;
  const offSize = dv.getUint8(t + 6), refSize = dv.getUint8(t + 7);
  const numObjects = Number(dv.getBigUint64(t + 8));
  const top = Number(dv.getBigUint64(t + 16));
  const tableOff = Number(dv.getBigUint64(t + 24));

  const uint = (o, n) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = v * 256 + buf[o + i];
    return v;
  };
  const offsets = [];
  for (let i = 0; i < numObjects; i++) offsets.push(uint(tableOff + i * offSize, offSize));

  const obj = (ref, depth = 0) => {
    if (depth > 64) throw new Error("plist too deep");
    let o = offsets[ref];
    const m = buf[o], type = m >> 4, info = m & 15;
    const len = () => {
      if (info !== 15) return [info, o + 1];
      const n = 1 << (buf[o + 1] & 15);
      return [uint(o + 2, n), o + 2 + n];
    };
    switch (type) {
      case 0: return info === 8 ? false : info === 9 ? true : null;
      case 1: {
        const n = 1 << info;
        return n === 8 ? Number(dv.getBigInt64(o + 1)) : uint(o + 1, n);
      }
      case 2: return info === 2 ? dv.getFloat32(o + 1) : dv.getFloat64(o + 1);
      case 3: return new Date((978307200 + dv.getFloat64(o + 1)) * 1000);
      case 4: { const [n, s] = len(); return buf.slice(s, s + n); }
      case 5: { const [n, s] = len(); return td.decode(buf.subarray(s, s + n)); }
      case 6: {
        const [n, s] = len();
        let r = "";
        for (let i = 0; i < n; i++) r += String.fromCharCode(dv.getUint16(s + i * 2));
        return r;
      }
      case 8: return uint(o + 1, info + 1);
      case 10: {
        const [n, s] = len();
        return Array.from({ length: n }, (_, i) => obj(uint(s + i * refSize, refSize), depth + 1));
      }
      case 13: {
        const [n, s] = len();
        const d = {};
        for (let i = 0; i < n; i++) {
          const k = obj(uint(s + i * refSize, refSize), depth + 1);
          d[k] = obj(uint(s + (n + i) * refSize, refSize), depth + 1);
        }
        return d;
      }
    }
    return null;
  };
  return obj(top);
}

function b64(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const unesc = (s) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
   .replace(/&apos;/g, "'").replace(/&#(x?)([0-9a-f]+);/gi, (_, x, n) => String.fromCodePoint(parseInt(n, x ? 16 : 10)))
   .replace(/&amp;/g, "&");

// Tiny tokenizer-based XML plist reader, so it also runs outside the browser.
function parseXML(xml) {
  const re = /<(\/?)([a-zA-Z]+)(?:\s[^>]*?)?(\/)?>|([^<]+)/g;
  const toks = [];
  let m;
  const body = xml.replace(/<\?[^>]*\?>|<!DOCTYPE[^>]*>|<!--[\s\S]*?-->/g, "");
  while ((m = re.exec(body))) {
    if (m[4] !== undefined) toks.push({ text: m[4] });
    else toks.push({ close: !!m[1], tag: m[2], empty: !!m[3] });
  }
  let i = 0;
  const skipText = () => { while (i < toks.length && toks[i].text !== undefined && !toks[i].text.trim()) i++; };
  const textUntil = (tag) => {
    let s = "";
    while (i < toks.length && !(toks[i].close && toks[i].tag === tag)) { if (toks[i].text) s += toks[i].text; i++; }
    i++;
    return unesc(s);
  };
  const value = () => {
    skipText();
    const t = toks[i++];
    if (!t || t.close) return undefined;
    if (t.empty) {
      return t.tag === "true" ? true : t.tag === "false" ? false
        : t.tag === "dict" ? {} : t.tag === "array" ? [] : t.tag === "data" ? new Uint8Array() : "";
    }
    switch (t.tag) {
      case "plist": { const v = value(); skipText(); i++; return v; }
      case "dict": {
        const d = {};
        for (;;) {
          skipText();
          if (toks[i].close) { i++; return d; }
          i++; // <key>
          const k = textUntil("key");
          d[k] = value();
        }
      }
      case "array": {
        const a = [];
        for (;;) {
          skipText();
          if (toks[i].close) { i++; return a; }
          a.push(value());
        }
      }
      case "string": return textUntil("string");
      case "integer": return Number(textUntil("integer"));
      case "real": return Number(textUntil("real"));
      case "date": return new Date(textUntil("date"));
      case "data": return b64(textUntil("data"));
      case "true": i++; return true;
      case "false": i++; return false;
    }
    return textUntil(t.tag);
  };
  return value();
}

// Extracts the XML plist embedded in a CMS-signed .mobileprovision.
export function parseProvision(buf) {
  const s = td.decode(buf);
  const a = s.indexOf("<?xml"), b = s.indexOf("</plist>");
  if (a < 0 || b < 0) throw new Error("Not a provisioning profile");
  return parseXML(s.slice(a, b + 8));
}
