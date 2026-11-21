// Converts Apple's "crushed" CgBI PNGs (BGRA, raw deflate) into normal PNGs browsers can show.

const CRC = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function pipe(data, stream) {
  return new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(stream)).arrayBuffer());
}

function chunk(type, data) {
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  dv.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)));
  return out;
}

export async function uncrush(png) {
  const dv = new DataView(png.buffer, png.byteOffset, png.byteLength);
  const chunks = [];
  let p = 8, cgbi = false;
  while (p + 8 <= png.length) {
    const len = dv.getUint32(p);
    const type = String.fromCharCode(...png.subarray(p + 4, p + 8));
    chunks.push({ type, data: png.subarray(p + 8, p + 8 + len) });
    if (type === "CgBI") cgbi = true;
    p += 12 + len;
    if (type === "IEND") break;
  }
  if (!cgbi) return png;

  const ihdr = chunks.find((c) => c.type === "IHDR").data;
  const ih = new DataView(ihdr.buffer, ihdr.byteOffset, ihdr.byteLength);
  const width = ih.getUint32(0), depth = ihdr[8], color = ihdr[9];
  const idat = chunks.filter((c) => c.type === "IDAT");
  const joined = new Uint8Array(idat.reduce((n, c) => n + c.data.length, 0));
  let o = 0;
  for (const c of idat) { joined.set(c.data, o); o += c.data.length; }

  const raw = await pipe(joined, new DecompressionStream("deflate-raw"));
  if (depth === 8 && color === 6) {
    // Filters only reference the same channel, so swapping B and R in filtered data is safe.
    const stride = 1 + width * 4;
    for (let row = 0; row + stride <= raw.length; row += stride) {
      for (let x = row + 1; x < row + stride; x += 4) {
        const b = raw[x]; raw[x] = raw[x + 2]; raw[x + 2] = b;
      }
    }
  }
  const z = await pipe(raw, new CompressionStream("deflate"));

  const parts = [png.subarray(0, 8)];
  let wroteIdat = false;
  for (const c of chunks) {
    if (c.type === "CgBI") continue;
    if (c.type === "IDAT") {
      if (!wroteIdat) parts.push(chunk("IDAT", z));
      wroteIdat = true;
      continue;
    }
    parts.push(chunk(c.type, c.data));
  }
  const out = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
  o = 0;
  for (const x of parts) { out.set(x, o); o += x.length; }
  return out;
}
