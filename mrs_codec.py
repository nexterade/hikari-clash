#!/usr/bin/env python3
"""
Hikari /.CLASH — codec rule-set biner Mihomo (.mrs) <-> daftar rule (.yaml / .txt).

Format .mrs (setelah dekompresi zstd):
    "MRS\\x01" | behavior(1B: 0=domain, 1=ipcidr) | count(int64 BE) | extra_len(int64 BE) | extra
    domain : version(1B=1) | leaves[int64 n, n x uint64] | labelBitmap[int64 n, n x uint64] | labels[int64 n, n B]
             (succinct trie atas domain TERBALIK; setiap "+.x" disimpan sebagai dua kunci: "x" dan "+.x")
    ipcidr : version(1B=1) | n(int64) | n x (from[16B] | to[16B])   <- rentang IPv6/4-in-6, sudah di-merge

Status verifikasi:
  * domain : encoder menghasilkan byte IDENTIK dengan blocker.mrs & plus18.mrs asli (lihat tests/).
  * ipcidr : dibangun dari spesifikasi, BELUM diuji dengan file .mrs ipcidr asli. Reader memvalidasi
             panjang data (gagal keras kalau layout tidak cocok); writer menyarankan cek dengan core.

Kompresi zstd (Python stdlib belum punya sebelum 3.14) memakai backend yang tersedia, berurutan:
  compression.zstd (3.14+) -> modul `zstandard` -> libzstd via ctypes -> binary `zstd`.
"""

import ctypes
import ctypes.util
import ipaddress
import os
import re
import shutil
import struct
import subprocess

try:
    import yaml
except ImportError:          # codec tetap bisa dipakai untuk .txt tanpa PyYAML
    yaml = None

MAGIC = b"MRS\x01"
BEHAVIORS = {0: "domain", 1: "ipcidr"}
BEHAVIOR_ID = {v: k for k, v in BEHAVIORS.items()}
ZSTD_LEVEL = 19

_V4_MAPPED = 0xFFFF << 32          # ::ffff:0:0/96  (As16 dari alamat IPv4)
_V4_MAPPED_END = _V4_MAPPED + 0xFFFFFFFF


class MrsError(ValueError):
    pass


class ZstdUnavailable(MrsError):
    pass


INSTALL_HINT = ("Backend zstd tidak ditemukan. Pasang salah satu:\n"
                "  Termux  : pkg install zstd        (atau: pip install zstandard)\n"
                "  Linux/PC: pip install zstandard   (atau paket libzstd / zstd)\n"
                "  OpenWrt : opkg install libzstd zstd\n"
                "  Python 3.14+ sudah bawaan (compression.zstd).")


# =====================================================================
#  Backend zstd
# =====================================================================
class _StdlibBackend:
    name = "compression.zstd (stdlib)"

    def __init__(self):
        from compression import zstd           # Python 3.14+
        self._z = zstd

    def compress(self, data, level=ZSTD_LEVEL):
        return self._z.compress(data, level=level)

    def decompress(self, data):
        return self._z.decompress(data)


class _ZstandardBackend:
    name = "zstandard (pip)"

    def __init__(self):
        import zstandard
        self._z = zstandard

    def compress(self, data, level=ZSTD_LEVEL):
        return self._z.ZstdCompressor(level=level).compress(data)

    def decompress(self, data):
        return self._z.ZstdDecompressor().decompressobj().decompress(data)


class _InBuf(ctypes.Structure):
    _fields_ = [("src", ctypes.c_void_p), ("size", ctypes.c_size_t), ("pos", ctypes.c_size_t)]


class _OutBuf(ctypes.Structure):
    _fields_ = [("dst", ctypes.c_void_p), ("size", ctypes.c_size_t), ("pos", ctypes.c_size_t)]


class _CtypesBackend:
    name = "libzstd (ctypes)"

    def __init__(self):
        lib = None
        for cand in (ctypes.util.find_library("zstd"), "libzstd.so.1", "libzstd.so",
                     "libzstd.dylib", "zstd.dll", "libzstd.dll"):
            if not cand:
                continue
            try:
                lib = ctypes.CDLL(cand)
                break
            except OSError:
                continue
        if lib is None:
            raise OSError("libzstd tidak ditemukan")
        sz, vp, ci = ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int
        lib.ZSTD_compressBound.argtypes = [sz]; lib.ZSTD_compressBound.restype = sz
        lib.ZSTD_compress.argtypes = [vp, sz, vp, sz, ci]; lib.ZSTD_compress.restype = sz
        lib.ZSTD_isError.argtypes = [sz]; lib.ZSTD_isError.restype = ctypes.c_uint
        lib.ZSTD_getErrorName.argtypes = [sz]; lib.ZSTD_getErrorName.restype = ctypes.c_char_p
        lib.ZSTD_createDCtx.restype = vp
        lib.ZSTD_freeDCtx.argtypes = [vp]
        lib.ZSTD_decompressStream.argtypes = [vp, ctypes.POINTER(_OutBuf), ctypes.POINTER(_InBuf)]
        lib.ZSTD_decompressStream.restype = sz
        self._lib = lib

    def _check(self, code):
        if self._lib.ZSTD_isError(code):
            raise MrsError("zstd: " + self._lib.ZSTD_getErrorName(code).decode("ascii", "replace"))
        return code

    def compress(self, data, level=ZSTD_LEVEL):
        lib = self._lib
        src = ctypes.create_string_buffer(data, len(data)) if data else ctypes.create_string_buffer(1)
        cap = lib.ZSTD_compressBound(len(data))
        dst = ctypes.create_string_buffer(cap)
        n = self._check(lib.ZSTD_compress(ctypes.cast(dst, ctypes.c_void_p), cap,
                                          ctypes.cast(src, ctypes.c_void_p), len(data), level))
        return dst.raw[:n]

    def decompress(self, data):
        lib = self._lib
        ctx = lib.ZSTD_createDCtx()
        try:
            src = ctypes.create_string_buffer(data, len(data))
            inb = _InBuf(ctypes.cast(src, ctypes.c_void_p), len(data), 0)
            chunk = 1 << 20
            buf = ctypes.create_string_buffer(chunk)
            out = bytearray()
            while True:
                before = inb.pos
                ob = _OutBuf(ctypes.cast(buf, ctypes.c_void_p), chunk, 0)
                ret = self._check(lib.ZSTD_decompressStream(ctx, ctypes.byref(ob), ctypes.byref(inb)))
                out += buf.raw[:ob.pos]
                if ret == 0:                          # frame selesai
                    break
                if ob.pos == 0 and inb.pos == before:
                    raise MrsError("zstd: data terpotong / tidak lengkap")
            return bytes(out)
        finally:
            lib.ZSTD_freeDCtx(ctx)


class _CliBackend:
    name = "binary zstd (CLI)"

    def __init__(self):
        self._bin = shutil.which("zstd")
        if not self._bin:
            raise OSError("binary zstd tidak ada")

    def _run(self, args, data):
        p = subprocess.run([self._bin] + args, input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        if p.returncode != 0:
            raise MrsError("zstd CLI: " + p.stderr.decode("utf-8", "replace").strip())
        return p.stdout

    def compress(self, data, level=ZSTD_LEVEL):
        return self._run(["-q", "-c", f"-{level}"], data)

    def decompress(self, data):
        return self._run(["-q", "-d", "-c"], data)


_BACKEND = None


def get_backend(refresh=False):
    """Backend zstd pertama yang bisa dipakai, atau raise ZstdUnavailable."""
    global _BACKEND
    if _BACKEND is not None and not refresh:
        return _BACKEND
    for cls in (_StdlibBackend, _ZstandardBackend, _CtypesBackend, _CliBackend):
        try:
            _BACKEND = cls()
            return _BACKEND
        except Exception:
            continue
    raise ZstdUnavailable(INSTALL_HINT)


def backend_name():
    try:
        return get_backend().name
    except ZstdUnavailable:
        return None


# =====================================================================
#  Parsing daftar rule (yaml / txt) -> entri bersih
# =====================================================================
_CLASSICAL = re.compile(r"^([A-Z][A-Z0-9-]*)\s*,\s*([^,]+?)\s*(?:,.*)?$")
_DOMAIN_OK = re.compile(r"^[a-z0-9_*+.\-]+$")


def parse_rule_text(text):
    """Isi file .yaml / .txt -> list string entri. YAML (payload: / list) diprioritaskan; selain itu per baris."""
    items = None
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("payload"), list):
            items = data["payload"]
        elif isinstance(data, list):
            items = data
    if items is None:
        items = [ln for ln in text.splitlines()]
    out = []
    for it in items:
        s = str(it).strip()
        if not s or s.startswith("#"):
            continue
        s = s.split(" #")[0].strip().strip("'\"")
        if s:
            out.append(s)
    return out


def detect_behavior(entries):
    """'ipcidr' bila (hampir) semua entri berupa CIDR/IP, selain itu 'domain'."""
    if not entries:
        return "domain"
    hits = 0
    for e in entries[:200]:
        m = _CLASSICAL.match(e)
        v = m.group(2) if m and m.group(1).startswith("IP-CIDR") else e
        try:
            ipaddress.ip_network(v, strict=False)
            hits += 1
        except ValueError:
            pass
    return "ipcidr" if hits >= max(1, min(len(entries), 200) * 0.8) else "domain"


def normalize_entries(entries, behavior):
    """Bersihkan entri untuk behavior tertentu. Return (entri_unik_berurutan, peringatan[])."""
    warnings, out, seen, dropped = [], [], set(), {}
    for raw in entries:
        e = raw.strip()
        m = _CLASSICAL.match(e)
        if m and m.group(1) in ("DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"):
            typ, val = m.group(1), m.group(2).strip()
            if behavior == "domain" and typ == "DOMAIN":
                e = val
            elif behavior == "domain" and typ == "DOMAIN-SUFFIX":
                e = "+." + val
            elif behavior == "ipcidr" and typ.startswith("IP-CIDR"):
                e = val
            else:
                dropped[typ] = dropped.get(typ, 0) + 1
                continue
        elif m:
            dropped[m.group(1)] = dropped.get(m.group(1), 0) + 1
            continue
        if behavior == "domain":
            e = e.lower()
            if not _DOMAIN_OK.match(e):
                try:
                    e = e.encode("idna").decode("ascii")
                except UnicodeError:
                    warnings.append(f"dilewati (domain tidak valid): {raw[:40]}")
                    continue
                if not _DOMAIN_OK.match(e):
                    warnings.append(f"dilewati (domain tidak valid): {raw[:40]}")
                    continue
        else:
            try:
                ipaddress.ip_network(e, strict=False)
            except ValueError:
                warnings.append(f"dilewati (bukan IP/CIDR): {raw[:40]}")
                continue
        if e not in seen:
            seen.add(e)
            out.append(e)
    for typ, n in sorted(dropped.items()):
        warnings.append(f"{n} entri {typ} dilewati (.mrs hanya mendukung behavior domain / ipcidr)")
    return out, warnings


# =====================================================================
#  Domain: succinct trie
# =====================================================================
def _setbit(words, i, v):
    while (i >> 6) >= len(words):
        words.append(0)
    if v:
        words[i >> 6] |= 1 << (i & 63)


def _getbit(words, i):
    return (words[i >> 6] >> (i & 63)) & 1


def domain_entries_to_keys(entries):
    """Entri domain-behavior -> kunci trie (maju, belum dibalik).
       'x' -> {x} | '+.x' -> {x, +.x} | '.x' -> {+.x} (hanya subdomain) | '*.x' -> {*.x}"""
    keys = set()
    for e in entries:
        if e.startswith("+."):
            keys.add(e[2:]); keys.add(e)
        elif e.startswith(".") and len(e) > 1:
            keys.add("+" + e)
        else:
            keys.add(e)
    keys.discard("")
    return keys


def encode_domain_body(entries):
    """Entri domain -> bytes isi domain-set (tanpa header MRS)."""
    rev = sorted(k[::-1].encode("ascii") for k in domain_entries_to_keys(entries))
    leaves, bitmap, labels = [], [], bytearray()
    if rev:
        queue = [(0, len(rev), 0)]
        lidx = i = 0
        while i < len(queue):
            s, e, col = queue[i]
            if col == len(rev[s]):
                s += 1
                _setbit(leaves, i, 1)
            j = s
            while j < e:
                frm = j
                while j < e and rev[j][col] == rev[frm][col]:
                    j += 1
                queue.append((frm, j, col + 1))
                labels.append(rev[frm][col])
                _setbit(bitmap, lidx, 0)
                lidx += 1
            _setbit(bitmap, lidx, 1)
            lidx += 1
            i += 1
    body = bytearray(b"\x01")
    for words in (leaves, bitmap):
        body += struct.pack(">q", len(words))
        body += struct.pack(f">{len(words)}Q", *words) if words else b""
    body += struct.pack(">q", len(labels)) + bytes(labels)
    return bytes(body)


def decode_domain_body(buf, pos):
    """bytes (mulai di `pos`) -> list kunci maju. Raise MrsError kalau layout tidak cocok."""
    try:
        if buf[pos] != 1:
            raise MrsError(f"versi domain-set {buf[pos]} tidak dikenal")
        pos += 1
        sets = []
        for _ in range(2):
            n, = struct.unpack_from(">q", buf, pos); pos += 8
            if n < 0 or pos + 8 * n > len(buf):
                raise MrsError("domain-set rusak (panjang bitmap)")
            sets.append(list(struct.unpack_from(f">{n}Q", buf, pos))); pos += 8 * n
        n, = struct.unpack_from(">q", buf, pos); pos += 8
        if n < 0 or pos + n > len(buf):
            raise MrsError("domain-set rusak (panjang label)")
        labels = buf[pos:pos + n]; pos += n
    except struct.error:
        raise MrsError("domain-set terpotong")
    leaves, bitmap = sets
    nodes, keys = [b""], []
    bit = li = i = 0
    nbits = len(bitmap) * 64
    while i < len(nodes):
        if (i >> 6) < len(leaves) and _getbit(leaves, i):
            keys.append(nodes[i][::-1].decode("ascii", "replace"))
        while True:
            if bit >= nbits:
                raise MrsError("domain-set rusak (bitmap habis)")
            if _getbit(bitmap, bit):
                break
            if li >= len(labels):
                raise MrsError("domain-set rusak (label habis)")
            nodes.append(nodes[i] + bytes([labels[li]]))
            li += 1; bit += 1
        bit += 1; i += 1
    return keys, pos


def domain_keys_to_entries(keys):
    """Kebalikan domain_entries_to_keys (pasangan 'x' + '+.x' dilipat jadi '+.x')."""
    kset = set(keys)
    out = []
    for k in kset:
        if k.startswith("+."):
            out.append(k if k[2:] in kset else "." + k[2:])
        elif "+." + k in kset:
            continue
        else:
            out.append(k)
    out.sort(key=lambda x: x.lstrip("+*.")[::-1])
    return out


# =====================================================================
#  IP-CIDR: rentang
# =====================================================================
def _net_to_range(net):
    a, b = int(net.network_address), int(net.broadcast_address)
    if net.version == 4:
        a += _V4_MAPPED; b += _V4_MAPPED
    return a, b


def cidr_entries_to_ranges(entries):
    rng = sorted(_net_to_range(ipaddress.ip_network(e, strict=False)) for e in entries)
    merged = []
    for a, b in rng:
        if merged and a <= merged[-1][1] + 1:
            if b > merged[-1][1]:
                merged[-1][1] = b
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]


def ranges_to_cidrs(ranges):
    out = []
    for a, b in ranges:
        while a <= b:
            if _V4_MAPPED <= a <= _V4_MAPPED_END:
                end = min(b, _V4_MAPPED_END)
                lo, hi = ipaddress.IPv4Address(a - _V4_MAPPED), ipaddress.IPv4Address(end - _V4_MAPPED)
            else:
                end = b if a > _V4_MAPPED_END else min(b, _V4_MAPPED - 1)
                lo, hi = ipaddress.IPv6Address(a), ipaddress.IPv6Address(end)
            out.extend(str(n) for n in ipaddress.summarize_address_range(lo, hi))
            a = end + 1
    return out


def encode_ipcidr_body(entries):
    ranges = cidr_entries_to_ranges(entries)
    body = bytearray(b"\x01") + struct.pack(">q", len(ranges))
    for a, b in ranges:
        body += a.to_bytes(16, "big") + b.to_bytes(16, "big")
    return bytes(body)


def decode_ipcidr_body(buf, pos):
    try:
        if buf[pos] != 1:
            raise MrsError(f"versi ipcidr-set {buf[pos]} tidak dikenal")
        n, = struct.unpack_from(">q", buf, pos + 1)
    except (struct.error, IndexError):
        raise MrsError("ipcidr-set terpotong")
    pos += 9
    if n < 0 or pos + 32 * n != len(buf):
        raise MrsError("layout ipcidr tidak cocok dengan spesifikasi (file .mrs ipcidr dari versi core lain?)")
    ranges = []
    for _ in range(n):
        ranges.append((int.from_bytes(buf[pos:pos + 16], "big"), int.from_bytes(buf[pos + 16:pos + 32], "big")))
        pos += 32
    return ranges_to_cidrs(ranges), pos


# =====================================================================
#  API publik
# =====================================================================
def write_mrs_bytes(behavior, entries, level=ZSTD_LEVEL):
    """Return (bytes_mrs_terkompres, peringatan[]). `entries` sudah dinormalisasi (lihat normalize_entries)."""
    if behavior not in BEHAVIOR_ID:
        raise MrsError(f"behavior harus domain/ipcidr, bukan '{behavior}'")
    if not entries:
        raise MrsError("tidak ada entri valid untuk ditulis")
    warns = []
    body = encode_domain_body(entries) if behavior == "domain" else encode_ipcidr_body(entries)
    if behavior == "ipcidr":
        warns.append("ipcidr: layout dibangun dari spesifikasi dan belum diuji dengan file .mrs ipcidr asli — "
                     "cek dengan `mihomo -t` sebelum dipakai (atau convert pakai core: mihomo convert-ruleset)")
    raw = MAGIC + bytes([BEHAVIOR_ID[behavior]]) + struct.pack(">q", len(entries)) + struct.pack(">q", 0) + body
    return get_backend().compress(raw, level), warns


def read_mrs_bytes(data):
    """Return dict(behavior, count, entries[])."""
    raw = get_backend().decompress(data)
    if raw[:4] != MAGIC:
        raise MrsError("bukan file .mrs Mihomo (magic 'MRS\\x01' tidak ada)")
    try:
        beh = BEHAVIORS[raw[4]]
        count, = struct.unpack_from(">q", raw, 5)
        extra, = struct.unpack_from(">q", raw, 13)
    except (KeyError, struct.error, IndexError):
        raise MrsError("header .mrs rusak")
    pos = 21 + max(extra, 0)
    if beh == "domain":
        keys, _ = decode_domain_body(raw, pos)
        entries = domain_keys_to_entries(keys)
    else:
        entries, _ = decode_ipcidr_body(raw, pos)
    return {"behavior": beh, "count": count, "entries": entries}


def mrs_info(path):
    d = read_mrs_bytes(open(path, "rb").read())
    return {"behavior": d["behavior"], "count": d["count"], "entries": len(d["entries"]),
            "size": os.path.getsize(path)}


def entries_to_text(entries, fmt="yaml", header=""):
    if fmt == "text":
        return "\n".join(entries) + "\n"
    lines = [f"# {ln}" for ln in header.splitlines() if ln] if header else []
    lines.append("payload:")
    lines += ["  - '" + e.replace("'", "''") + "'" for e in entries]
    return "\n".join(lines) + "\n"


def convert_file(src, dst, behavior=None, text_out=False):
    """Konversi satu file. .mrs -> .yaml/.txt, atau .yaml/.txt -> .mrs (arah dari ekstensi `src`).
    Return dict(direction, behavior, entries, warnings, dst)."""
    warns = []
    if src.lower().endswith(".mrs"):
        d = read_mrs_bytes(open(src, "rb").read())
        header = (f"Dikonversi dari {os.path.basename(src)} oleh Hikari /.CLASH\n"
                  f"behavior: {d['behavior']} | entri: {len(d['entries'])}")
        with open(dst, "w", encoding="utf-8") as f:
            f.write(entries_to_text(d["entries"], "text" if text_out else "yaml", header))
        return {"direction": "mrs->text", "behavior": d["behavior"], "entries": len(d["entries"]),
                "warnings": warns, "dst": dst}
    with open(src, "r", encoding="utf-8") as f:
        raw = parse_rule_text(f.read())
    behavior = behavior or detect_behavior(raw)
    entries, warns = normalize_entries(raw, behavior)
    blob, w2 = write_mrs_bytes(behavior, entries)
    with open(dst, "wb") as f:
        f.write(blob)
    return {"direction": "text->mrs", "behavior": behavior, "entries": len(entries),
            "warnings": warns + w2, "dst": dst}


def find_mihomo(extra=None):
    """Cari binary core Mihomo: env HIKARI_MIHOMO, PATH, lalu lokasi umum Box/Nikki/OpenClash."""
    cands = [extra, os.environ.get("HIKARI_MIHOMO")]
    for n in ("mihomo", "clash-meta", "clash_meta", "mihomo-linux-amd64", "mihomo-android-arm64"):
        cands.append(shutil.which(n))
    cands += ["/data/adb/box/bin/mihomo", "/data/adb/box/bin/clash", "/usr/bin/mihomo",
              "/usr/local/bin/mihomo", "/etc/openclash/core/clash_meta"]
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None
