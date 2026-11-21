// Minimal random-access ZIP reader over a Blob: reads only the central directory
// and the entries you ask for, so multi-gigabyte IPAs open instantly.

const td = new TextDecoder();

async function bytes(blob, start, end) {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

function u64(dv, o) {
  return dv.getUint32(o, true) + dv.getUint32(o + 4, true) * 2 ** 32;
}

export async function openZip(blob) {
  const tailLen = Math.min(blob.size, 65557 + 20);
  const tail = await bytes(blob, blob.size - tailLen, blob.size);
  const tdv = new DataView(tail.buffer);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tdv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("Not a ZIP archive");

  let count = tdv.getUint16(eocd + 10, true);
  let cdSize = tdv.getUint32(eocd + 12, true);
  let cdOff = tdv.getUint32(eocd + 16, true);

  const loc = eocd - 20;
  if (loc >= 0 && tdv.getUint32(loc, true) === 0x07064b50) {
    const z64 = u64(tdv, loc + 8);
    const rec = new DataView((await bytes(blob, z64, z64 + 56)).buffer);
    if (rec.getUint32(0, true) === 0x06064b50) {
      count = u64(rec, 32);
      cdSize = u64(rec, 40);
      cdOff = u64(rec, 48);
    }
  }

  const cd = await bytes(blob, cdOff, cdOff + cdSize);
  const dv = new DataView(cd.buffer);
  const entries = new Map();
  let p = 0;
  for (let n = 0; n < count && p + 46 <= cd.length; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    let csize = dv.getUint32(p + 20, true);
    let size = dv.getUint32(p + 24, true);
    const nlen = dv.getUint16(p + 28, true);
    const xlen = dv.getUint16(p + 30, true);
    const clen = dv.getUint16(p + 32, true);
    let off = dv.getUint32(p + 42, true);
    const name = td.decode(cd.subarray(p + 46, p + 46 + nlen));
    let x = p + 46 + nlen;
    const xend = x + xlen;
    while (x + 4 <= xend) {
      const id = dv.getUint16(x, true), len = dv.getUint16(x + 2, true);
      if (id === 1) {
        let q = x + 4;
        if (size === 0xffffffff) { size = u64(dv, q); q += 8; }
        if (csize === 0xffffffff) { csize = u64(dv, q); q += 8; }
        if (off === 0xffffffff) { off = u64(dv, q); }
      }
      x += 4 + len;
    }
    entries.set(name, { name, method, csize, size, off });
    p = xend + clen;
  }
  return new Zip(blob, entries);
}

class Zip {
  constructor(blob, entries) {
    this.blob = blob;
    this.entries = entries;
  }

  names() { return [...this.entries.keys()]; }

  async #dataStart(e) {
    const h = new DataView((await bytes(this.blob, e.off, e.off + 30)).buffer);
    if (h.getUint32(0, true) !== 0x04034b50) throw new Error("Bad local header: " + e.name);
    return e.off + 30 + h.getUint16(26, true) + h.getUint16(28, true);
  }

  // Returns the entry's bytes. With `limit`, stops after that many output bytes.
  async read(name, limit = Infinity) {
    const e = typeof name === "string" ? this.entries.get(name) : name;
    if (!e) return null;
    const start = await this.#dataStart(e);
    const raw = this.blob.slice(start, start + e.csize);
    if (e.method === 0) {
      return new Uint8Array(await raw.slice(0, Math.min(e.size, limit)).arrayBuffer());
    }
    if (e.method !== 8) throw new Error("Unsupported compression in " + e.name);
    const want = Math.min(e.size, limit);
    const out = new Uint8Array(want);
    let got = 0;
    const reader = raw.stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
    while (got < want) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = Math.min(value.length, want - got);
      out.set(value.subarray(0, take), got);
      got += take;
    }
    reader.cancel().catch(() => {});
    return got === want ? out : out.subarray(0, got);
  }
}
