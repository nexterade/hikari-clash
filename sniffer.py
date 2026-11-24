#!/usr/bin/env python3
"""
Hikari /.CLASH — inspector sniffer (tanpa UI; dipakai menu Miscellaneous > Sniffer Only).

Membaca `GET /connections` dari external-controller Mihomo, lalu menyusun detail per koneksi:
alamat tujuan, IP, host hasil sniff (SNI/Host) vs host dari DNS, subdomain & domain dasar, GeoIP, ASN,
CDN (Cloudflare / CloudFront), rule + chain, aplikasi, dan trafik.

Batasan (disengaja):
  - GeoIP & ASN hanya muncul kalau core mengisinya (config sniffer_only.yaml memakai rule probe untuk itu).
  - CDN dikenali berurutan: label rule/chain  >  daftar CIDR (Cloudflare bawaan, CloudFront dari cache resmi AWS)
    >  tebakan dari nama host. Kolom `cdn_basis` mencatat dasar yang dipakai; tebakan nama host bukan bukti.
  - Pemecahan subdomain memakai heuristik (daftar akhiran multi-label kecil), bukan Public Suffix List penuh.
"""

import csv
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

CLOUDFLARE_V4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)
CLOUDFLARE_V6 = (
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)
CLOUDFLARE_URLS = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

CLOUDFLARE_FILE = "cloudflare-cidr.txt"
CLOUDFRONT_FILE = "cloudfront-cidr.txt"

# akhiran 2-label yang membuat domain dasar = 3 label (heuristik; bukan Public Suffix List penuh)
MULTI_SUFFIX = {
    "co.id", "or.id", "go.id", "ac.id", "sch.id", "web.id", "my.id", "biz.id", "net.id", "mil.id",
    "desa.id", "ponpes.id", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "co.in", "com.sg", "com.my", "com.br", "com.cn", "com.hk", "com.tw",
    "co.nz", "co.za", "com.ph", "co.th", "in.th", "com.vn", "co.kr", "com.tr", "com.mx", "com.ar",
}

# tebakan dari nama host (dasar terlemah)
CLOUDFLARE_HOST_HINTS = (".cloudflare.com", ".cloudflare-dns.com", ".workers.dev", ".pages.dev", ".trycloudflare.com")
CLOUDFRONT_HOST_HINTS = (".cloudfront.net",)

CSV_FIELDS = ["no", "first_seen", "network", "inbound", "source", "dst_ip", "dst_port", "host", "sniff_host",
              "host_source", "subdomain", "base_domain", "geoip", "asn", "cdn", "cdn_basis", "rule",
              "rule_payload", "chains", "process", "uid", "upload", "download"]


class SnifferError(Exception):
    """Pesan ramah untuk ditampilkan langsung ke pengguna."""


# ---------- host ----------
def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def split_host(host):
    """'cdn.img.shopee.co.id' -> ('cdn.img', 'shopee.co.id'); IP / host kosong -> ('', host)."""
    h = (host or "").strip().strip(".").lower()
    if not h or _is_ip(h):
        return "", h
    labels = h.split(".")
    if len(labels) <= 2:
        return "", h
    keep = 3 if ".".join(labels[-2:]) in MULTI_SUFFIX else 2
    if len(labels) <= keep:
        return "", h
    return ".".join(labels[:-keep]), ".".join(labels[-keep:])


# ---------- CIDR CDN ----------
def _parse_nets(lines):
    nets = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(ln, strict=False))
        except ValueError:
            continue
    return nets


def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except OSError:
        return []


class CdnRanges:
    """Daftar CIDR Cloudflare & CloudFront. Cloudflare selalu ada (bawaan); CloudFront hanya dari cache."""

    def __init__(self, cache_dir=None):
        cf = _read_lines(os.path.join(cache_dir, CLOUDFLARE_FILE)) if cache_dir else []
        fr = _read_lines(os.path.join(cache_dir, CLOUDFRONT_FILE)) if cache_dir else []
        self.cloudflare = _parse_nets(cf) or _parse_nets(CLOUDFLARE_V4 + CLOUDFLARE_V6)
        self.cloudfront = _parse_nets(fr)
        self.cloudflare_from_cache = bool(cf)

    def lookup(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for label, nets in (("Cloudflare", self.cloudflare), ("CloudFront", self.cloudfront)):
            if any(addr.version == n.version and addr in n for n in nets):
                return label
        return None


def detect_cdn(chains, ip, name, ranges):
    """Return (label, dasar). dasar: 'rule' | 'ip' | 'host' | ''. Urutan = kekuatan bukti."""
    for c in chains or []:
        low = str(c).lower()
        if "cloudflare" in low:
            return "Cloudflare", "rule"
        if "cloudfront" in low:
            return "CloudFront", "rule"
    if ip and ranges:
        hit = ranges.lookup(ip)
        if hit:
            return hit, "ip"
    low = "." + (name or "").lower().strip(".")
    if low.endswith(CLOUDFRONT_HOST_HINTS):
        return "CloudFront", "host"
    if low.endswith(CLOUDFLARE_HOST_HINTS):
        return "Cloudflare", "host"
    return "-", ""


# ---------- koneksi -> baris ----------
def _split_addr(addr):
    """'1.2.3.4:443' / '[::1]:443' -> ('1.2.3.4', '443')"""
    a = str(addr or "")
    if a.startswith("[") and "]" in a:
        ip, _, rest = a[1:].partition("]")
        return ip, rest.lstrip(":")
    if a.count(":") == 1:
        ip, _, port = a.partition(":")
        return ip, port
    return a, ""


def build_row(conn, ranges=None, no=0):
    m = conn.get("metadata") or {}
    host, sniff = m.get("host") or "", m.get("sniffHost") or ""
    name = sniff or host
    ip, port = m.get("destinationIP") or "", str(m.get("destinationPort") or "")
    if not ip and m.get("remoteDestination"):
        ip, rport = _split_addr(m["remoteDestination"])
        port = port or rport
    sub, base = split_host(name)
    geo = m.get("destinationGeoIP") or []
    geo = [geo] if isinstance(geo, str) else list(geo)
    chains = [str(c) for c in conn.get("chains") or []]
    cdn, basis = detect_cdn(chains, ip, name, ranges)
    src = f"{m.get('sourceIP', '')}:{m.get('sourcePort', '')}" if m.get("sourceIP") else ""
    return {
        "no": no, "id": conn.get("id", ""), "first_seen": time.strftime("%H:%M:%S"),
        "network": str(m.get("network") or "").upper(), "inbound": m.get("type") or "",
        "source": src, "dst_ip": ip, "dst_port": port,
        "host": host, "sniff_host": sniff,
        "host_source": "sniff (SNI/Host)" if sniff else ("DNS/domain" if host else "tanpa host (IP murni)"),
        "subdomain": sub, "base_domain": base,
        "geoip": ",".join(geo), "asn": m.get("destinationIPASN") or "",
        "cdn": cdn, "cdn_basis": basis,
        "rule": conn.get("rule") or "", "rule_payload": conn.get("rulePayload") or "",
        "chains": " > ".join(reversed(chains)),
        "process": m.get("process") or m.get("processPath") or "", "uid": m.get("uid") or "",
        "upload": conn.get("upload") or 0, "download": conn.get("download") or 0,
    }


class Tracker:
    """Koneksi hilang dari /connections begitu ditutup, jadi disimpan di sini selama sesi."""

    def __init__(self, ranges=None):
        self.ranges = ranges
        self.rows = {}           # id -> row, urut kemunculan pertama

    def update(self, conns):
        new = []
        for c in conns or []:
            cid = c.get("id")
            if cid in self.rows:
                self.rows[cid]["upload"] = c.get("upload") or 0
                self.rows[cid]["download"] = c.get("download") or 0
                continue
            row = build_row(c, self.ranges, no=len(self.rows) + 1)
            self.rows[cid] = row
            new.append(row)
        return new

    def all(self):
        return list(self.rows.values())


# ---------- tampilan ----------
def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_compact(row):
    name = row["sniff_host"] or row["host"] or row["dst_ip"] or "?"
    port = f":{row['dst_port']}" if row["dst_port"] else ""
    cdn = row["cdn"] if row["cdn"] != "-" else ""
    geo = row["geoip"] or "--"
    return f"#{row['no']:<3} {row['first_seen']} {row['network']:<3} {name}{port}  {row['dst_ip']}  [{geo}] {cdn}".rstrip()


def fmt_detail(row):
    name = row["sniff_host"] or row["host"]
    cdn = "-" if row["cdn"] == "-" else f"{row['cdn']}  (dasar: {row['cdn_basis']})"
    pairs = [
        ("Alamat", f"{row['dst_ip'] or '-'}:{row['dst_port']}" if row["dst_port"] else (row["dst_ip"] or "-")),
        ("Host", f"{name or '-'}  ← {row['host_source']}"),
        ("Host DNS", row["host"] or "-"),
        ("Host sniff", row["sniff_host"] or "-"),
        ("Subdomain", row["subdomain"] or "-"),
        ("Domain dasar", row["base_domain"] or "-"),
        ("GeoIP", row["geoip"] or "-"),
        ("ASN", row["asn"] or "-"),
        ("CDN", cdn),
        ("Rule", f"{row['rule']} {row['rule_payload']}".strip() or "-"),
        ("Chain", row["chains"] or "-"),
        ("Sumber", f"{row['source'] or '-'}  ({row['network']}/{row['inbound'] or '-'})"),
        ("Aplikasi", str(row["process"] or row["uid"] or "-")),
        ("Trafik", f"↑ {human_bytes(row['upload'])}   ↓ {human_bytes(row['download'])}"),
    ]
    out = [f"#{row['no']}  {row['first_seen']}  {row['network']}"]
    out += [f"  {k:<13}: {v}" for k, v in pairs]
    return out


def summarize(rows):
    rows = list(rows)
    return {
        "total": len(rows),
        "no_host": sum(1 for r in rows if not (r["sniff_host"] or r["host"])),
        "sniffed": sum(1 for r in rows if r["sniff_host"]),
        "cdn": Counter(r["cdn"] for r in rows if r["cdn"] != "-"),
        "geo": Counter(g for r in rows for g in (r["geoip"].split(",") if r["geoip"] else [])),
        "base": Counter(r["base_domain"] for r in rows if r["base_domain"]),
    }


def summary_lines(rows, top=10):
    s = summarize(rows)
    out = [f"Total koneksi   : {s['total']}",
           f"Host dari sniff : {s['sniffed']}   ·   tanpa host (IP murni): {s['no_host']}"]
    if s["cdn"]:
        out.append("CDN             : " + ", ".join(f"{k} {v}" for k, v in s["cdn"].most_common()))
    if s["geo"]:
        out.append("GeoIP           : " + ", ".join(f"{k} {v}" for k, v in s["geo"].most_common(top)))
    if s["base"]:
        out.append("Domain teratas  : " + ", ".join(f"{k} ({v})" for k, v in s["base"].most_common(top)))
    return out


# ---------- ekspor ----------
def export_csv(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return path


def export_json(rows, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(rows), f, ensure_ascii=False, indent=2)
        f.write("\n")
    return path


# ---------- laporan markdown (hanya koneksi yang MENERIMA data) ----------
def _md(text):
    return str(text if text not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def _app_of(row):
    return str(row.get("process") or row.get("uid") or "(tidak diketahui)")


def aggregate_ok(rows, min_download=1):
    """Gabungkan koneksi serupa (aplikasi + protokol + port + host + chain) yang MENERIMA data.
    Koneksi dengan download < min_download dibuang (handshake tanpa balasan, diblokir, dsb).
    Return (groups, total, dibuang); groups terurut dari trafik terbesar."""
    groups, total, dropped = {}, 0, 0
    for r in rows:
        total += 1
        if int(r.get("download") or 0) < min_download:
            dropped += 1
            continue
        sniff, host, ip = r.get("sniff_host") or "", r.get("host") or "", r.get("dst_ip") or ""
        if sniff:
            name, kind = sniff, "SNI"
        elif host:
            name, kind = host, "DNS"
        else:
            name, kind = ip or "?", "IP"
        port = str(r.get("dst_port") or "")
        net = str(r.get("network") or "").upper()
        proto = "UDP/QUIC" if net == "UDP" and port in ("443", "8443") else net
        key = (_app_of(r), proto, port, name, r.get("chains") or "")
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"app": key[0], "proto": proto, "port": port, "name": name, "chains": key[4],
                               "kinds": set(), "conns": 0, "up": 0, "down": 0, "ips": [], "asn": [], "geo": [],
                               "cdn": [], "base": ""}
        g["kinds"].add(kind)
        g["conns"] += 1
        g["up"] += int(r.get("upload") or 0)
        g["down"] += int(r.get("download") or 0)
        for field, val in (("ips", ip), ("asn", r.get("asn")), ("geo", r.get("geoip")), ("cdn", r.get("cdn"))):
            if val and val != "-" and val not in g[field]:
                g[field].append(val)
        if kind != "IP" and not g["base"]:
            g["base"] = r.get("base_domain") or name
    out = list(groups.values())
    for g in out:
        g["kind"] = "SNI" if "SNI" in g["kinds"] else ("DNS" if "DNS" in g["kinds"] else "IP")
    out.sort(key=lambda g: (-(g["up"] + g["down"]), g["name"]))
    return out, total, dropped


# Nama pemilik IP (kolom ASN) milik operator seluler. Host yang di-resolve ke IP seperti ini biasanya cache lokal
# operator yang dijawab DNS operator (terlihat di log Spotify: scdn.co/spotifycdn.com -> AS24203 PT XL Axiata).
OPERATOR_ASN_HINTS = ("xl axiata", "xlsmart", "telkomsel", "telekomunikasi selular", "indosat", "hutchison", "smartfren")


def is_operator_ip(g):
    return any(h in str(a).lower() for a in g.get("asn", []) for h in OPERATOR_ASN_HINTS)


def _notes(g):
    n = []
    if is_operator_ip(g):
        n.append("IP operator (cache lokal?)")
    if g["port"] == "80":
        n.append("HTTP polos")
    if g["down"] < 1024:
        n.append("respons kecil")
    if g["kind"] == "DNS":
        n.append("host dari DNS, bukan SNI")
    elif g["kind"] == "IP":
        n.append("tanpa SNI")
    return ", ".join(n)


def _ips(g, top=3):
    shown = g["ips"][:top]
    extra = len(g["ips"]) - len(shown)
    return ", ".join(shown) + (f" +{extra}" if extra > 0 else "")


def render_markdown(rows, source="", min_download=1):
    rows = list(rows)
    groups, total, dropped = aggregate_ok(rows, min_download)
    ok_conns = total - dropped
    up, down = sum(g["up"] for g in groups), sum(g["down"] for g in groups)
    hosts = {g["name"] for g in groups if g["kind"] != "IP"}
    L = ["# Hasil sniffer — koneksi yang menerima data", ""]
    L.append(f"> Dibuat {time.strftime('%Y-%m-%d %H:%M:%S')}" + (f" · sumber: {_md(source)}" if source else ""))
    L += ["", f"- Total koneksi terekam: **{total}** · menerima data: **{ok_conns}** · dibuang (download 0 B): **{dropped}**",
          f"- Hasil gabungan: **{len(groups)}** baris · host unik: **{len(hosts)}**",
          f"- Trafik: ↑ {human_bytes(up)} · ↓ {human_bytes(down)} · total {human_bytes(up + down)}", ""]
    if not groups:
        L += ["_Tidak ada koneksi yang menerima data pada rekaman ini._", ""]
        return "\n".join(L)

    by_app = {}
    for g in groups:
        by_app.setdefault(g["app"], []).append(g)
    for app, items in sorted(by_app.items(), key=lambda kv: -sum(g["up"] + g["down"] for g in kv[1])):
        L += [f"## Aplikasi: `{_md(app)}`", "",
              "| # | Host (SNI) | Port | Proto | Konek | IP | ASN · Geo | Chain | ↑ Up | ↓ Down | Total | Catatan |",
              "|--:|---|--:|---|--:|---|---|---|--:|--:|--:|---|"]
        for i, g in enumerate(items, 1):
            asn_geo = " · ".join(x for x in (", ".join(g["asn"]), ",".join(g["geo"]), ", ".join(g["cdn"])) if x)
            L.append(f"| {i} | {_md(g['name'])} | {_md(g['port'])} | {g['proto']} | {g['conns']} | {_md(_ips(g))} | "
                     f"{_md(asn_geo)} | {_md(g['chains'])} | {human_bytes(g['up'])} | {human_bytes(g['down'])} | "
                     f"{human_bytes(g['up'] + g['down'])} | {_md(_notes(g))} |")
        L.append("")

    base = {}
    for g in groups:
        if g["kind"] == "IP":
            continue
        b = base.setdefault(g["base"] or g["name"], {"hosts": set(), "conns": 0, "up": 0, "down": 0})
        b["hosts"].add(g["name"]); b["conns"] += g["conns"]; b["up"] += g["up"]; b["down"] += g["down"]
    if base:
        L += ["## Per domain dasar", "", "| Domain dasar | Host unik | Konek | ↑ Up | ↓ Down | Total |", "|---|--:|--:|--:|--:|--:|"]
        for name, b in sorted(base.items(), key=lambda kv: -(kv[1]["up"] + kv[1]["down"])):
            L.append(f"| {_md(name)} | {len(b['hosts'])} | {b['conns']} | {human_bytes(b['up'])} | "
                     f"{human_bytes(b['down'])} | {human_bytes(b['up'] + b['down'])} |")
        L.append("")

    sni = list(dict.fromkeys(g["name"] for g in groups if g["kind"] == "SNI"))
    addr = list(dict.fromkeys(
        f"{g['name']}:{g['port']}" + (" # udp" if g["proto"] != "TCP" else "") if g["port"] else g["name"]
        for g in groups))
    wild = ["+." + b for b in base]
    op_hosts = list(dict.fromkeys(g["name"] for g in groups if g["kind"] != "IP" and is_operator_ip(g)))
    op_block = []
    if op_hosts:
        op_block = [f"### Host di IP milik operator — {len(op_hosts)}", "",
                    "Di-resolve ke IP operator (cache lokal); biasanya hanya terjawab lewat DNS operator dan paling mungkin jalur gratis.",
                    "", "```text", *op_hosts, "```", ""]
    L += ["## Kandidat SNI / Address", "",
          "Hanya yang **membalas data** saat direkam. Urut dari trafik terbesar.", "",
          f"### SNI (host hasil sniff) — {len(sni)}", "", "```text", *sni, "```", "",
          f"### Address (host:port) — {len(addr)}", "", "```text", *addr, "```", "",
          f"### Wildcard domain (format rule-set Mihomo) — {len(wild)}", "", "```text", *wild, "```", "",
          *op_block,
          "> Catatan: \"kandidat\" artinya host itu membalas data, bukan jaminan gratis atau bisa dipakai sebagai bug-host. "
          "Bukti paling kuat hanya kalau rekaman diambil di SIM **tanpa kuota reguler**; uji ulang tiap host sebelum dipakai. "
          "Koneksi dengan \"respons kecil\" atau \"HTTP polos\" bisa berupa redirect/halaman operator, jadi jangan langsung dipercaya.", ""]
    return "\n".join(L)


def export_markdown(rows, path, source="", min_download=1):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(rows, source, min_download))
    return path


def rows_from_file(path):
    """Baca rekaman hasil ekspor (JSON atau CSV) kembali menjadi list row."""
    try:
        if path.lower().endswith(".csv"):
            with open(path, "r", encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f))
            for r in rows:
                for k in ("upload", "download"):
                    r[k] = int(float(r.get(k) or 0))
            return rows
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise SnifferError(f"Tidak bisa membaca {path}: {e}")
    if not isinstance(data, list):
        raise SnifferError(f"{path}: isi harus berupa daftar koneksi (hasil ekspor sniffer)")
    return data


def main(argv=None):
    """python3 sniffer.py laporan koneksi_XXXX.json [laporan.md]  -> tabel markdown dari rekaman lama."""
    argv = sys.argv[1:] if argv is None else list(argv)
    if len(argv) < 2 or argv[0] != "laporan":
        print("Pemakaian: python3 sniffer.py laporan <koneksi.json|koneksi.csv> [keluaran.md]")
        return 2
    src = argv[1]
    out = argv[2] if len(argv) > 2 else os.path.splitext(src)[0] + ".md"
    try:
        path = export_markdown(rows_from_file(src), out, source=os.path.basename(src))
    except SnifferError as e:
        print(e)
        return 1
    print(f"Tersimpan: {path}")
    return 0


# ---------- controller ----------
def controller_url(addr):
    """'0.0.0.0:9090' / ':9090' / '[::]:9090' -> 'http://127.0.0.1:9090' (alamat bind bukan alamat tujuan)."""
    a = str(addr or "").strip()
    if a.startswith(("http://", "https://")):
        return a.rstrip("/")
    host, port = _split_addr(a)
    if host in ("", "0.0.0.0", "::", "*"):
        host = "127.0.0.1"
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{port or '9090'}"


def fetch_connections(base, secret="", timeout=5):
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    req = urllib.request.Request(base.rstrip("/") + "/connections", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise SnifferError("secret ditolak (401) — samakan dengan secret di config / setting LuCI")
        raise SnifferError(f"controller membalas HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise SnifferError(f"controller tidak terjangkau di {base} — core belum jalan, atau alamat salah ({e})")
    except ValueError:
        raise SnifferError("balasan controller bukan JSON (alamat itu bukan API Mihomo?)")
    conns = data.get("connections") if isinstance(data, dict) else None
    return conns if isinstance(conns, list) else []


# ---------- update daftar CIDR resmi ----------
def _http_get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "hikari-clash"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse_aws_cloudfront(text):
    """ip-ranges.json -> daftar CIDR layanan CLOUDFRONT (edge; CLOUDFRONT_ORIGIN_FACING sengaja tidak ikut)."""
    data = json.loads(text)
    out = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT" and p.get("ip_prefix")]
    out += [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT" and p.get("ipv6_prefix")]
    return out


def update_cdn_ranges(cache_dir, fetch=_http_get):
    """Unduh daftar resmi. Return list[(nama, jumlah_cidr, error)]. Satu sumber gagal tidak membatalkan yang lain."""
    os.makedirs(cache_dir, exist_ok=True)
    results = []
    try:
        cf = []
        for url in CLOUDFLARE_URLS:
            cf += [ln.strip() for ln in fetch(url).splitlines() if ln.strip()]
        nets = _parse_nets(cf)
        if not nets:
            raise ValueError("daftar kosong / format tidak dikenal")
        _write_cidr(os.path.join(cache_dir, CLOUDFLARE_FILE), [str(n) for n in nets], "Cloudflare", ", ".join(CLOUDFLARE_URLS))
        results.append(("Cloudflare", len(nets), None))
    except (OSError, ValueError) as e:
        results.append(("Cloudflare", 0, f"{type(e).__name__}: {e}"))
    try:
        fr = parse_aws_cloudfront(fetch(AWS_RANGES_URL))
        nets = _parse_nets(fr)
        if not nets:
            raise ValueError("tidak ada prefix CLOUDFRONT di ip-ranges.json")
        _write_cidr(os.path.join(cache_dir, CLOUDFRONT_FILE), [str(n) for n in nets], "CloudFront", AWS_RANGES_URL)
        results.append(("CloudFront", len(nets), None))
    except (OSError, ValueError) as e:
        results.append(("CloudFront", 0, f"{type(e).__name__}: {e}"))
    return results


def _write_cidr(path, cidrs, label, source):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(f"# {label} — sumber: {source}\n# diunduh {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n".join(cidrs) + "\n")
    os.replace(tmp, path)


if __name__ == "__main__":
    raise SystemExit(main())
