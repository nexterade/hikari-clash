#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sub2yaml.py  -  bagian dari Hikari /.CLASH
Subscription (base64 / plain) -> `proxies:` Clash Mihomo. Tiap node DITES LEWAT MIHOMO (URL-test sungguhan:
connect lewat node -> gstatic generate_204, lalu dikonfirmasi sekali lagi ke URL berbeda). Hanya node yang
benar-benar "muncul ping" yang disimpan ke ./hasil/proxy (diurutkan per negara) + laporan (report.txt).
Jumlah node bebas (--top N): tes berhenti begitu N node lolos. Core mihomo diunduh otomatis bila belum ada:
ke ./bin, atau ke ~/.hikari-clash/bin kalau folder script ada di /sdcard (penyimpanan bersama Android tidak
boleh menjalankan file).

Source (src/):
  Saat pertama kali dijalankan, sumber diambil dari file .txt di folder ./src
  (barry-far.txt, 0xRadikal.txt). Perbarui isinya kapan saja lewat menu [8] Update source
  atau `--update-source`. File .txt lain yang kamu taruh di src/ ikut terbaca.

Output (./hasil/proxy/):
  free.yaml            node yang LOLOS tes tanpa custom config (default 100 node, --top untuk ubah)
  custom-sni.yaml      HANYA node yang berhasil dengan SNI custom
  custom-host.yaml     HANYA node yang berhasil dengan Host custom
  custom-address.yaml  HANYA node yang berhasil dengan Address (server) custom
  custom-combined.yaml node yang berhasil jika semua field custom dipakai sekaligus (bila >1 field)
  (juga custom-port / custom-path / custom-alpn / custom-fp bila field itu diisi)
  report.txt           semua node: berhasil / gagal (+alasan) / tidak dites, per profil

Format YAML = block style seperti active.yaml (tanpa `{}` / `[]` inline), nilai berisiko
(angka-like, true/false, karakter khusus) otomatis diberi tanda kutip.

Tiap field custom dites TERPISAH, tapi semua profil dites dalam satu kali URL-test mihomo.

PENTING: tes TCP hanya mengecek port terbuka - TIDAK berarti node bisa dipakai (di HP dengan Box/Nikki/VPN
aktif, semua koneksi TCP dijawab proxy lokal sehingga SEMUA node tampak "hidup" dengan ping 1-3ms).
Karena itu mihomo wajib; --tcp-only hanya untuk keadaan terpaksa. Matikan Box/VPN saat menjalankan tes.
SNI custom biasanya juga butuh --insecure (sertifikat server tidak cocok dengan SNI).

Contoh:
  python3 sub2yaml.py                                  # menu interaktif
  python3 sub2yaml.py --update-source                  # unduh ulang src/*.txt lalu keluar
  python3 sub2yaml.py --top 30 --no-menu               # 30 node yang lolos tes (core diunduh otomatis)
  python3 sub2yaml.py --mihomo ./mihomo                # hanya free.yaml
  python3 sub2yaml.py --sni instagram.com --insecure --mihomo ./mihomo
  python3 sub2yaml.py --sni a.com --host b.com --server 1.2.3.4 --insecure --mihomo ./mihomo
  python3 sub2yaml.py --only type=vless,network=ws --host a.b.c --top 80
  python3 sub2yaml.py src/0xRadikal.txt URL2 --tcp-only --sort ping
"""
import argparse
import asyncio
import atexit
import base64
import glob
import gzip
import io
import json
import os
import platform
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor

# ---------- PATH CONFIG (relatif ke lokasi script, bukan cwd) ----------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:  # supaya banner.py ketemu walau dijalankan dari folder lain
    sys.path.insert(0, SCRIPT_DIR)
SRC_DIR = os.path.join(SCRIPT_DIR, "src")
DEFAULT_OUTDIR = os.path.join(SCRIPT_DIR, "hasil", "proxy")
CORE_DIR = os.path.join(SCRIPT_DIR, "bin")   # tempat core mihomo hasil unduh otomatis

# (nama file di src/, label, URL) - dipakai pertama kali jalan & menu [8] Update source
SOURCES = [
    ("barry-far.txt", "barry-far/V2ray-config (All_Configs)",
     "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_base64_Sub.txt"),
    ("0xRadikal.txt", "0xRadikal/Free-v2ray-Configs (verified)",
     "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt"),
    ("roosterkid.txt", "roosterkid/openproxylist (V2RAY, teks biasa)",
     "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY.txt"),
]
TEST_URL = "https://www.gstatic.com/generate_204"
VERIFY_URL = "https://cp.cloudflare.com/generate_204"   # URL kedua untuk konfirmasi node yang lolos

SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "chacha20-ietf", "xchacha20", "rc4-md5",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "none",
}
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge",
                "360", "qq", "random", "randomized"}


# ---------- ANSI / Style (sama dengan hikari_converter.py + banner.py) ----------
class C:
    _on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET   = "\033[0m"  if _on else ""
    BOLD    = "\033[1m"  if _on else ""
    DIM     = "\033[2m"  if _on else ""
    RED     = "\033[91m" if _on else ""
    GREEN   = "\033[92m" if _on else ""
    YELLOW  = "\033[93m" if _on else ""
    CYAN    = "\033[96m" if _on else ""
    MAGENTA = "\033[95m" if _on else ""
    WHITE   = "\033[97m" if _on else ""
    GRAY    = "\033[90m" if _on else ""


TTY = sys.stdout.isatty()

try:  # banner yang sama dengan Hikari /.CLASH
    from banner import banner as _show_banner
except ImportError:  # sub2yaml.py dipakai sendirian tanpa banner.py
    def _show_banner(mode="SUB2YAML", description="", **_):
        print()
        print(f"{C.CYAN}[] {C.RESET}{C.BOLD}{C.MAGENTA}H I K A R I{C.RESET}{C.CYAN} /.CLASH{C.RESET}"
              f"{C.GRAY} // {C.RESET}{C.BOLD}{C.CYAN}{mode}{C.RESET}")
        print(f"{C.GRAY}{description}{C.RESET}{C.CYAN}Box / Nikki / OpenClash{C.RESET}")
        print(C.GRAY + "─" * 50 + C.RESET)


def clear_screen():
    if TTY:
        os.system('cls' if os.name == 'nt' else 'clear')


def sep(width=50, color=None):
    return (color or C.GRAY) + "─" * width + C.RESET


def section(title, width=50):
    t = f" {title} "; pad = max(0, width - len(t)); left = pad // 2; right = pad - left
    print(C.GRAY + "─" * left + C.RESET + C.BOLD + C.WHITE + t + C.RESET + C.GRAY + "─" * right + C.RESET)


def banner():
    _show_banner(mode="SUB2YAML", description="Subscription ➜ proxies Mihomo (tes + urut otomatis) untuk ")
    print()


def ok(msg):   print(f"{C.GREEN}✓{C.RESET} {msg}")
def err(msg):  print(f"{C.RED}✗ {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}! {msg}{C.RESET}")
def info(msg): print(f"  {C.DIM}{msg}{C.RESET}")


def ask(prompt):
    """input() yang aman: EOF (Ctrl+D / stdin habis) = keluar bersih."""
    try:
        return input(prompt)
    except EOFError:
        print()
        raise SystemExit(0)


def pause(msg="Tekan Enter untuk kembali..."):
    ask(f"\n{C.DIM}{msg}{C.RESET}")


def _show_cursor():
    if TTY:
        sys.stdout.write("\033[?25h"); sys.stdout.flush()


atexit.register(_show_cursor)


class Live:
    """Spinner animasi (frame sama dengan Hikari) + bar progres opsional.
    Non-terminal: tidak beranimasi, cukup satu baris hasil di akhir.
        with Live("TCP test", total=400) as lv:
            lv.update(done)          # atau lv.set(msg=..., done=..., total=...)
            lv.done("400 target")    # baris ✓ penutup (opsional)"""
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, msg, total=None, unit="", quiet=False):
        self.msg, self.total, self.unit, self.n = msg, total, unit, 0
        self.quiet, self._stop, self._t, self._t0, self._closed = quiet, threading.Event(), None, 0.0, False

    def set(self, msg=None, done=None, total=None):
        if msg is not None:
            self.msg = msg
        if done is not None:
            self.n = done
        if total is not None:
            self.total = total

    def update(self, done, total=None):
        self.n = done
        if total is not None:
            self.total = total

    def _line(self, frame):
        width = shutil_columns()
        tail = ""
        if self.total:
            frac = min(1.0, self.n / self.total)
            fill = int(round(frac * 16))
            tail = (f"  {C.CYAN}{'█' * fill}{C.GRAY}{'░' * (16 - fill)}{C.RESET}"
                    f" {self.n}/{self.total}{self.unit}")
        elif self.n:
            tail = f"  {C.DIM}{self.n}{self.unit}{C.RESET}"
        plain = len(self.msg) + 2 + (2 + 16 + 1 + len(f"{self.n}/{self.total}{self.unit}") if self.total else 0)
        msg = self.msg if plain < width - 4 else self.msg[:max(8, width - 28)] + "…"
        return f"\r\033[K{C.CYAN}{frame}{C.RESET} {msg}{tail}"

    def _run(self):
        i = 0
        while not self._stop.is_set():
            sys.stdout.write(self._line(self.FRAMES[i % len(self.FRAMES)])); sys.stdout.flush()
            i += 1
            self._stop.wait(0.08)

    def __enter__(self):
        self._t0 = time.time()
        if TTY and not self.quiet:
            sys.stdout.write("\033[?25l")
            self._t = threading.Thread(target=self._run, daemon=True)
            self._t.start()
        return self

    def _halt(self):
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._t:
            self._t.join()
            sys.stdout.write("\r\033[K\033[?25h"); sys.stdout.flush()

    def done(self, text=""):
        self._halt()
        el = time.time() - self._t0
        if not self.quiet:
            ok(f"{self.msg}  {C.DIM}{text + '  ' if text else ''}({el:.1f}s){C.RESET}")

    def fail(self, text=""):
        self._halt()
        err(f"{self.msg}  {text}")

    def __exit__(self, et, ev, tb):
        self._halt()
        return False


def shutil_columns():
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def spinner(msg, duration=0.6):
    """Spinner pendek (sama dengan hikari_converter.spinner)."""
    if not TTY:
        return
    with Live(msg):
        time.sleep(duration)


def log(*a):
    """Pesan proses kecil (abu-abu), sejajar dengan baris ✓ dari Live."""
    print(f"  {C.DIM}{' '.join(str(x) for x in a)}{C.RESET}", flush=True)


def rel(path):
    """Path untuk ditampilkan: relatif ke folder script kalau berada di dalamnya."""
    try:
        r = os.path.relpath(path, SCRIPT_DIR)
        return path if r.startswith("..") else r
    except ValueError:
        return path


def human_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def human_age(ts):
    d = max(0, time.time() - ts)
    if d < 90:
        return "baru saja"
    for lim, div, unit in ((3600, 60, "menit"), (86400, 3600, "jam"), (86400 * 60, 86400, "hari")):
        if d < lim:
            return f"{int(d // div)} {unit} lalu"
    return f"{int(d // (86400 * 30))} bulan lalu"


# --------------------------------------------------------------------------
# Ambil & decode subscription
# --------------------------------------------------------------------------
def fetch(src, live=None):
    """Baca file lokal atau unduh URL. live = Live untuk menampilkan ukuran yang sudah diunduh."""
    if os.path.isfile(src):
        with open(src, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    req = urllib.request.Request(src, headers={"User-Agent": "Mozilla/5.0 sub2yaml"})
    with urllib.request.urlopen(req, timeout=60) as r:
        try:
            total = int(r.headers.get("Content-Length") or 0)
        except ValueError:
            total = 0
        label = live.msg if live else ""
        buf = bytearray()
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            buf += chunk
            if live:
                live.set(msg=f"{label}  {human_size(len(buf))}" + (f" / {human_size(total)}" if total else ""))
        if live:
            live.set(msg=label)
        return bytes(buf).decode("utf-8", "ignore")


def b64decode_loose(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


_LINK_START = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_LINK_ANY = re.compile(r"(?<![A-Za-z0-9])(?!https?://)[A-Za-z][A-Za-z0-9+.\-]*://\S+")
_FLAG_PREFIX = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def extract_links(text):
    t = text.strip()
    if "://" not in t:  # base64 tidak pernah mengandung "://"
        try:
            t = b64decode_loose("".join(t.split())).decode("utf-8", "ignore")
        except Exception:
            pass
    out = []
    for ln in t.splitlines():
        ln = ln.strip().replace("&amp;", "&")  # sebagian sumber menulis query dengan entitas HTML
        if "://" not in ln or ln.startswith("#"):  # "#support-url: https://..." = metadata, bukan node
            continue
        if _LINK_START.match(ln):
            if not ln.lower().startswith(("http://", "https://")):  # URL biasa (donasi, website) bukan node
                out.append(ln)
            continue
        # Format "🇩🇪 vless://... 85ms DE [ISP]" (mis. openproxylist): bendera di depan, keterangan di belakang.
        m = _LINK_ANY.search(ln)
        if not m:
            continue  # "Website=https://..." dan sejenisnya
        link = m.group()
        flag_ = _FLAG_PREFIX.search(ln[:m.start()])
        if flag_ and not _FLAG_PREFIX.search(link.partition("#")[2]):
            link = link.partition("#")[0] + "#" + flag_.group() + " " + link.partition("#")[2]  # bendera -> remark
        out.append(link)
    return out


# --------------------------------------------------------------------------
# Parser link -> dict proxy Mihomo
# --------------------------------------------------------------------------
def truthy(v):
    return str(v).lower() in ("1", "true", "yes")


def qs(query):
    return {k.lower(): v[0] for k, v in
            urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def split_hostport(s):
    s = s.strip().rstrip("/")
    if s.startswith("["):
        host, _, port = s[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = s.rpartition(":")
    return host.strip(), int(port)


def apply_tls(p, q, fallback_sni="", trojan=False):
    sni = q.get("sni") or q.get("peer") or fallback_sni
    if trojan:
        if sni:
            p["sni"] = sni
    else:
        p["tls"] = True
        if sni:
            p["servername"] = sni
    if q.get("alpn"):
        alpn = [a for a in q["alpn"].split(",") if a]
        if alpn:
            p["alpn"] = alpn
    fp = (q.get("fp") or "").lower()
    if fp in FINGERPRINTS:
        p["client-fingerprint"] = fp
    if truthy(q.get("allowinsecure") or q.get("insecure") or ""):
        p["skip-cert-verify"] = True


def set_transport(p, net, path, host, service, header_type, tls):
    """Isi network + *-opts. Return False kalau transport tidak didukung."""
    net = (net or "tcp").lower()
    if net == "tcp":
        if (header_type or "").lower() == "http":
            opts = {"method": "GET", "path": [p_ for p_ in (path or "/").split(",") if p_]}
            if host:
                opts["headers"] = {"Host": [h for h in host.split(",") if h]}
            p["network"] = "http"
            p["http-opts"] = opts
        return True
    if net in ("ws", "websocket", "httpupgrade"):
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        if net == "httpupgrade":
            opts["v2ray-http-upgrade"] = True
        p["network"] = "ws"
        p["ws-opts"] = opts
        return True
    if net == "grpc":
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": service or (path or "")}
        return True
    if net in ("h2", "http"):
        if not tls:
            return False
        opts = {"path": path or "/"}
        if host:
            opts["host"] = [h for h in host.split(",") if h]
        p["network"] = "h2"
        p["h2-opts"] = opts
        return True
    return False  # kcp, quic, xhttp, dll.


def parse_vmess(rest, query, frag):
    d = json.loads(b64decode_loose(rest).decode("utf-8", "ignore"))
    q = {str(k).lower(): str(v) for k, v in d.items() if v is not None}
    net = q.get("net", "tcp").lower()
    tls = q.get("tls", "").lower() in ("tls", "1", "true")
    cipher = q.get("scy", "auto")
    p = {
        "name": q.get("ps") or frag,
        "type": "vmess",
        "server": q["add"].strip(),
        "port": int(q["port"]),
        "uuid": q["id"].strip(),
        "alterId": int(q.get("aid") or 0),
        "cipher": cipher if cipher in VMESS_CIPHERS else "auto",
        "udp": True,
    }
    if tls:
        apply_tls(p, q, q.get("host", "") if net in ("ws", "h2", "httpupgrade") else "")
    if not set_transport(p, net, q.get("path"), q.get("host"), q.get("path"),
                         q.get("type"), tls):
        return None
    return p


def parse_vless(rest, query, frag):
    q = qs(query)
    if q.get("encryption", "none") not in ("none", ""):
        return None
    sec = q.get("security", "none").lower()
    if sec not in ("tls", "reality", "none", ""):
        return None
    flow = q.get("flow", "")
    if flow and flow != "xtls-rprx-vision":
        return None
    user, _, hp = rest.rpartition("@")
    host, port = split_hostport(hp)
    net = q.get("type", "tcp").lower()
    p = {"name": frag, "type": "vless", "server": host, "port": port,
         "uuid": urllib.parse.unquote(user), "udp": True}
    if flow:
        p["flow"] = flow
    tls = sec in ("tls", "reality")
    if tls:
        apply_tls(p, q, q.get("host", "") if net in ("ws", "h2", "http", "httpupgrade") else "")
    if sec == "reality":
        if not q.get("pbk"):
            return None
        p["reality-opts"] = {"public-key": q["pbk"], "short-id": q.get("sid", "")}
        p.setdefault("client-fingerprint", "chrome")
    if not set_transport(p, net, q.get("path"), q.get("host"), q.get("servicename"),
                         q.get("headertype"), tls):
        return None
    return p


def parse_trojan(rest, query, frag):
    q = qs(query)
    if q.get("security", "tls").lower() not in ("tls", ""):
        return None
    user, _, hp = rest.rpartition("@")
    host, port = split_hostport(hp)
    p = {"name": frag, "type": "trojan", "server": host, "port": port,
         "password": urllib.parse.unquote(user), "udp": True}
    apply_tls(p, q, trojan=True)
    if not set_transport(p, q.get("type", "tcp"), q.get("path"), q.get("host"),
                         q.get("servicename"), q.get("headertype"), True):
        return None
    return p


def parse_ss(rest, query, frag):
    q = qs(query)
    if "@" in rest:
        user, _, hp = rest.rpartition("@")
        try:
            cred = b64decode_loose(user).decode("utf-8")
            if ":" not in cred:
                raise ValueError
        except Exception:
            cred = urllib.parse.unquote(user)
    else:  # format lama: base64(method:pass@host:port)
        dec = b64decode_loose(rest).decode("utf-8", "ignore")
        cred, _, hp = dec.rpartition("@")
    host, port = split_hostport(hp)
    method, _, password = cred.partition(":")
    if method not in SS_CIPHERS:
        return None
    p = {"name": frag, "type": "ss", "server": host, "port": port,
         "cipher": method, "password": password, "udp": True}
    plugin = urllib.parse.unquote(q.get("plugin", ""))
    if plugin:
        parts = plugin.split(";")
        opts = {x.partition("=")[0]: x.partition("=")[2] for x in parts[1:] if x}
        if parts[0] in ("obfs-local", "simple-obfs"):
            mode = opts.get("obfs", "http")
            if mode not in ("http", "tls"):
                return None
            p["plugin"] = "obfs"
            p["plugin-opts"] = {"mode": mode, "host": opts.get("obfs-host", "")}
        elif parts[0] == "v2ray-plugin":
            if opts.get("mode", "websocket") != "websocket":
                return None
            po = {"mode": "websocket"}
            if opts.get("host"):
                po["host"] = opts["host"]
            if opts.get("path"):
                po["path"] = opts["path"]
            if "tls" in opts:
                po["tls"] = True
            p["plugin"] = "v2ray-plugin"
            p["plugin-opts"] = po
        else:
            return None
    return p


_HOST_OK = re.compile(r"[^\s<>\"'`\\/@#?{}|^]+")
_UUID_OK = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def validate_proxy(p):
    """Cek ketat field yang ditolak mihomo. Return alasan (str) kalau tidak valid, None kalau aman.
    Dijalankan offline, jadi hasil TCP-only pun tidak berisi node yang bikin config gagal dimuat."""
    t = p["type"]
    for k in ("server", "servername", "sni"):
        v = p.get(k)
        if v and not _HOST_OK.fullmatch(v):
            return f"{k} tidak valid"
    if t in ("vless", "vmess") and not _UUID_OK.fullmatch(p.get("uuid", "")):
        return "UUID bukan format UUID"
    if t in ("trojan", "ss") and not p.get("password"):
        return "password kosong"
    ro = p.get("reality-opts")
    if ro:
        pk = ro.get("public-key", "")
        try:
            if len(base64.urlsafe_b64decode(pk + "=" * (-len(pk) % 4))) != 32:
                raise ValueError
        except Exception:
            return "reality public-key tidak valid"
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", ro.get("short-id", "")):
            return "reality short-id bukan hex (<=16 karakter, genap)"
        if p.get("network", "tcp") not in ("tcp", "grpc", "h2"):
            return f"reality tidak didukung untuk network {p.get('network')}"
    if p.get("flow") and p.get("network", "tcp") != "tcp":
        return "flow hanya untuk network tcp"
    if "alpn" in p and any(not a.strip() for a in p["alpn"]):
        return "alpn kosong"
    return None


PARSERS = {"vmess": parse_vmess, "vless": parse_vless,
           "trojan": parse_trojan, "ss": parse_ss}


_INVISIBLE = re.compile("[\x00-\x1f\x7f-\x9f\u200b\u200c\u200e\u200f\u2028-\u202e\u2060-\u2069\ufeff"
                        "\U000E0000-\U000E007F\ue000-\uf8ff]")  # kontrol, bidi, tag-char, private-use


def clean_name(s, fallback):
    s = _INVISIBLE.sub("", s or "")  # ZWJ (\u200d) & VS16 (\ufe0f) sengaja dipertahankan: bagian dari emoji
    s = re.sub(r"\s+", " ", s).strip()
    return s[:48] or fallback


def parse_all(links):
    proxies, seen_keys, seen_names = [], set(), {}
    stats = {"unsupported": 0, "invalid": 0, "duplicate": 0}
    skipped = []  # (jenis, scheme, remark)

    def skip(kind, scheme, frag, link, why=""):
        stats[kind] += 1
        skipped.append((kind, scheme, (urllib.parse.unquote(frag) or link[:60]) + (f"  [{why}]" if why else "")))

    for link in links:
        scheme, _, rest = link.partition("://")
        scheme = scheme.lower()
        rest, _, frag = rest.partition("#")
        rest, _, query = rest.partition("?")
        parser = PARSERS.get(scheme)
        if not parser:
            skip("unsupported", scheme, frag, link)
            continue
        frag = urllib.parse.unquote(frag)
        try:
            p = parser(rest, query, frag)
        except Exception:
            skip("invalid", scheme, frag, link)
            continue
        if not p:
            skip("unsupported", scheme, frag, link)
            continue
        if not p.get("server") or not (1 <= int(p.get("port", 0)) <= 65535):
            skip("invalid", scheme, frag, link, "server/port kosong")
            continue
        why = validate_proxy(p)
        if why:
            skip("invalid", scheme, frag, link, why)
            continue
        key = json.dumps({k: v for k, v in p.items() if k != "name"}, sort_keys=True)
        if key in seen_keys:
            skip("duplicate", scheme, frag, link)
            continue
        seen_keys.add(key)
        name = clean_name(p["name"], f"{p['server']}:{p['port']}")
        seen_names[name] = seen_names.get(name, 0) + 1
        if seen_names[name] > 1:
            name = f"{name} #{seen_names[name]}"
        p["name"] = name
        proxies.append(p)
    return proxies, stats, skipped


# --------------------------------------------------------------------------
# Tulis YAML - block style (seperti active.yaml), tanpa PyYAML
# --------------------------------------------------------------------------
# Plain scalar hanya dipakai kalau pasti aman; selain itu di-"kutip" (JSON string = YAML valid).
_UNSAFE_START = set("-?:,[]{}#&*!|>'\"%@`")
_UNSAFE_ANY = set("{}[],\"'\\`")
_RESERVED = {"", "true", "false", "yes", "no", "on", "off", "y", "n", "null", "~", "=", "<<"}
_NUMLIKE = re.compile(
    r"[-+]?(?:\d[\d_]*(?:\.\d*)?(?:e[-+]?\d+)?|\.\d+|\.inf|\.nan|0x[0-9a-f_]+|0o?[0-7_]+"
    r"|\d+(?::[0-5]?\d)+(?:\.\d*)?)|\d{4}-\d{1,2}-\d{1,2}.*", re.I)
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\ufeff]")


def _quote(s):
    q = json.dumps(s, ensure_ascii=False)
    return q.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").replace("\x85", "\\u0085")


def y_str(s):
    safe = (s == s.strip() and s.lower() not in _RESERVED and s[0] not in _UNSAFE_START
            and not (_UNSAFE_ANY & set(s)) and ": " not in s and " #" not in s and not s.endswith(":")
            and not _CTRL.search(s) and not _NUMLIKE.fullmatch(s)) if s else False
    return s if safe else _quote(s)


def y_scalar(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return repr(v)
    return y_str(str(v))


def y_key(k):
    k = str(k)
    return k if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.\-/]*", k) and k.lower() not in _RESERVED else _quote(k)


def _emit(obj, ind, out):
    pad = " " * ind
    for k, v in obj.items():
        if isinstance(v, dict):
            if v:  # dict kosong dibuang (tidak ada `{}`)
                out.append(f"{pad}{y_key(k)}:")
                _emit(v, ind + 2, out)
        elif isinstance(v, (list, tuple)):
            if not v:
                continue
            out.append(f"{pad}{y_key(k)}:")
            for it in v:
                if isinstance(it, dict) and it:
                    sub = []
                    _emit(it, ind + 4, sub)
                    sub[0] = f"{pad}  - " + sub[0][ind + 4:]
                    out += sub
                else:
                    out.append(f"{pad}  - {y_scalar(it)}")
        else:
            out.append(f"{pad}{y_key(k)}: {y_scalar(v)}")


def to_yaml(cfg, header=""):
    lines = [header.rstrip("\n")] if header else []
    _emit(cfg, 0, lines)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Tahap 1: tes TCP
# --------------------------------------------------------------------------
async def tcp_ping(host, port, timeout, attempts=2):
    best = None
    for _ in range(attempts):
        t0 = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except Exception:
            break  # mati / timeout -> tidak usah diulang
        ms = (time.perf_counter() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        best = ms if best is None else min(best, ms)
    return None if best is None else max(1, round(best))


async def tcp_stage(items, timeout, concurrency, live=None):
    """items: [(index, proxy)] -> {index: ms} untuk yang merespon."""
    sem = asyncio.Semaphore(concurrency)
    done = 0
    if live:
        live.set(done=0, total=len(items))

    async def one(i, p):
        nonlocal done
        async with sem:
            ms = await tcp_ping(p["server"], p["port"], timeout)
        done += 1
        if live:
            live.update(done)
        return i, ms

    res = await asyncio.gather(*(one(i, p) for i, p in items))
    return {i: ms for i, ms in res if ms is not None}


# --------------------------------------------------------------------------
# Tahap 2: URL-test sungguhan lewat binary mihomo
# --------------------------------------------------------------------------
def _core_check(path):
    """(True, "") kalau `path` core Mihomo (Meta) yang bisa dijalankan; selain itu (False, alasan sebenarnya)."""
    try:
        r = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=30)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:160]
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode == 0 and ("mihomo" in out.lower() or "meta" in out.lower()):
        return True, ""
    return False, f"kode {r.returncode}: {out[:120] or '(tanpa output)'}"


def _core_ok(path):
    return _core_check(path)[0]


# Folder tujuan core hasil unduh, urut prioritas. Folder script bisa di penyimpanan bersama (/sdcard) yang
# TIDAK boleh mengeksekusi file ("Permission denied"), jadi ada cadangan di home Termux/Linux.
def core_dirs():
    home = os.path.join(os.path.expanduser("~"), ".hikari-clash", "bin")
    shared = SCRIPT_DIR.startswith(("/storage/", "/sdcard", "/mnt/sdcard"))  # penyimpanan bersama Android = noexec
    return [home, CORE_DIR] if shared else [CORE_DIR, home]


def core_version(path):
    try:
        r = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=15)
        return ((r.stdout or r.stderr or "").strip().splitlines() or ["?"])[0][:60]
    except Exception:
        return "?"


def find_core(extra=None):
    """Cari core Mihomo: --mihomo, env HIKARI_MIHOMO, ./bin, folder script, PATH, lokasi umum Box/Termux/OpenClash."""
    cands = [extra, os.environ.get("HIKARI_MIHOMO")]
    for d in core_dirs() + [SCRIPT_DIR]:
        cands += [os.path.join(d, "mihomo"), os.path.join(d, "mihomo.exe")]
    for name in ("mihomo", "clash-meta", "clash.meta", "clash_meta"):
        cands.append(shutil.which(name))
    prefix = os.environ.get("PREFIX")
    if prefix:
        cands.append(os.path.join(prefix, "bin", "mihomo"))
    cands += ["/usr/local/bin/mihomo",
              "/usr/bin/mihomo", "/etc/openclash/core/clash_meta"]
    seen = set()
    for c in cands:
        if c and c not in seen and os.path.isfile(c) and os.access(c, os.X_OK):
            seen.add(c)
            if _core_ok(c):
                return c
    return None


# Nama aset rilis MetaCubeX/mihomo per platform ({v} = tag versi, mis. v1.19.2). Urutan = prioritas.
def core_asset_templates():
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
            "armv8l": "armv7", "armv7l": "armv7", "i386": "386", "i686": "386"}.get(platform.machine().lower())
    if not arch:
        return []
    android = bool(os.environ.get("TERMUX_VERSION") or os.environ.get("ANDROID_ROOT")
                   or os.path.exists("/system/build.prop"))
    if sys.platform.startswith("win"):
        osn, ext = "windows", "zip"
    elif sys.platform == "darwin":
        osn, ext = "darwin", "gz"
    else:
        osn, ext = "linux", "gz"
    t = []
    if android and arch == "arm64":
        t.append("mihomo-android-arm64-v8-{v}.gz")
    if arch == "amd64":
        t += [f"mihomo-{osn}-amd64-compatible-{{v}}.{ext}", f"mihomo-{osn}-amd64-{{v}}.{ext}"]
    else:
        t.append(f"mihomo-{osn}-{arch}-{{v}}.{ext}")
    return t


def pick_asset(names, templates):
    """Pilih nama aset pertama yang cocok dengan salah satu template (urut prioritas)."""
    for t in templates:
        rx = re.compile(r"v\d+(?:\.\d+)+".join(re.escape(x) for x in t.split("{v}")))
        for n in names:
            if rx.fullmatch(n):
                return n
    return None


def _http_get(url, timeout=60, live=None):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 sub2yaml"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        total = int(r.headers.get("Content-Length") or 0)
        buf, label = bytearray(), (live.msg if live else "")
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            buf += chunk
            if live:
                live.set(msg=f"{label}  {human_size(len(buf))}" + (f" / {human_size(total)}" if total else ""))
        return bytes(buf), r.geturl()


def _download(url, part, live=None, tries=8):
    """Unduh url -> file `part` dengan RESUME (Range). Koneksi putus / terpotong = lanjut dari byte terakhir,
    bukan ulang dari awal. File `part` dibiarkan ada, jadi menjalankan ulang pun melanjutkan."""
    os.makedirs(os.path.dirname(part), exist_ok=True)
    label = live.msg if live else ""
    for attempt in range(tries):
        have = os.path.getsize(part) if os.path.exists(part) else 0
        headers = {"User-Agent": "Mozilla/5.0 sub2yaml"}
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
                if have and r.status != 206:  # server tidak mendukung Range -> mulai ulang
                    have = 0
                clen = int(r.headers.get("Content-Length") or 0)
                total = have + clen if clen else 0
                with open(part, "ab" if have else "wb") as f:
                    while True:
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
                        have += len(chunk)
                        if live:
                            live.set(msg=f"{label}  {human_size(have)}" + (f" / {human_size(total)}" if total else ""))
            if total and have < total:
                raise IOError("koneksi terputus sebelum selesai")
            return True
        except urllib.error.HTTPError as e:
            if e.code == 416:  # sudah lengkap
                return True
        except Exception:
            pass
        if live:
            live.set(msg=f"{label}  terputus, melanjutkan ({attempt + 1}/{tries})")
        time.sleep(min(5, 1 + attempt))
    return False


def download_core(dest_dir=None):
    """Unduh core Mihomo terbaru dari GitHub (MetaCubeX/mihomo). Coba tiap varian yang cocok dengan perangkat
    (mis. android-arm64 lalu linux-arm64) dan tiap folder tujuan sampai ada yang BENAR-BENAR bisa dijalankan.
    Return path atau None; alasan kegagalan ditampilkan apa adanya."""
    dirs = [dest_dir] if dest_dir else core_dirs()
    temps = core_asset_templates()
    if not temps:
        warn(f"Platform {sys.platform}/{platform.machine()} belum dikenali - unduh mihomo manual "
             "lalu pakai --mihomo /path/mihomo")
        return None
    repo = "https://github.com/MetaCubeX/mihomo/releases"
    reasons = []
    with Live("Unduh core mihomo") as lv:
        cands = []  # [(url, nama)]
        try:  # jalur utama: API GitHub (daftar aset resmi)
            data, _ = _http_get("https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", 30)
            assets = {a["name"]: a["browser_download_url"] for a in json.loads(data).get("assets", [])}
            for t_ in temps:
                nm = pick_asset(list(assets), [t_])
                if nm:
                    cands.append((assets[nm], nm))
        except Exception:
            pass
        if not cands:  # cadangan: tag dari redirect /releases/latest, nama aset ditebak dari template
            try:
                _, final = _http_get(repo + "/latest", 30)
                tag = final.rstrip("/").rsplit("/", 1)[-1]
                cands = [(f"{repo}/download/{tag}/{t_.replace('{v}', tag)}", t_.replace("{v}", tag)) for t_ in temps]
            except Exception as e:
                lv.fail(f"GitHub tidak terjangkau: {str(e)[:80]}")
                return None
        for url, name in cands:
            part = os.path.join(dirs[0], name + ".part")
            lv.set(msg=f"Unduh {name}")
            if not _download(url, part, lv):
                reasons.append(f"{name}: unduhan gagal (file sebagian disimpan; jalankan lagi untuk melanjutkan)")
                continue
            try:
                with open(part, "rb") as f:
                    raw = f.read()
                if name.endswith(".zip"):
                    with zipfile.ZipFile(io.BytesIO(raw)) as z:
                        raw = z.read(next(n for n in z.namelist() if n.lower().endswith(".exe")))
                else:
                    raw = gzip.decompress(raw)
            except Exception as e:
                try:
                    os.remove(part)  # korup: buang supaya percobaan berikutnya mengunduh bersih
                except OSError:
                    pass
                reasons.append(f"{name}: file korup ({str(e)[:60]}), dibuang - coba lagi")
                continue
            for d in dirs:
                path = os.path.join(d, "mihomo.exe" if os.name == "nt" else "mihomo")
                try:
                    os.makedirs(d, exist_ok=True)
                    with open(path + ".tmp", "wb") as f:
                        f.write(raw)
                    os.chmod(path + ".tmp", 0o755)
                    os.replace(path + ".tmp", path)
                except OSError as e:
                    reasons.append(f"{name} -> {rel(d)}: tidak bisa menulis ({e.strerror or e})")
                    continue
                good, why = _core_check(path)
                if good:
                    try:
                        os.remove(part)
                    except OSError:
                        pass
                    lv.set(msg="Unduh core mihomo")
                    lv.done(f"{name} -> {rel(path)}")
                    return path
                reasons.append(f"{name} di {rel(d)}: tidak bisa dijalankan ({why})")
                try:
                    os.remove(path)
                except OSError:
                    pass
        lv.fail("tidak ada varian core yang bisa dijalankan di perangkat ini")
    for r in reasons:
        log(r)
    return None


def resolve_core(args):
    """Core untuk URL-test: --mihomo / yang sudah ada / unduh otomatis (kecuali --no-download)."""
    if args.mihomo:
        p = os.path.expanduser(args.mihomo)
        if os.path.isfile(p) and os.access(p, os.X_OK) and _core_ok(p):
            return p
        err(f"--mihomo '{args.mihomo}' bukan binary Mihomo yang bisa dijalankan.")
        return None
    core = find_core()
    if core or args.no_download:
        return core
    warn("Binary mihomo belum ada -> mengunduh otomatis dari GitHub (MetaCubeX/mihomo)")
    return download_core()


def tcp_intercepted(ms_values):
    """Ping TCP yang nyaris semuanya <=3ms = koneksi dijawab proxy/VPN lokal (Box, Nikki, TUN),
    bukan server aslinya -> tes TCP tidak berarti apa-apa."""
    return len(ms_values) >= 20 and sum(1 for m in ms_values if m <= 3) / len(ms_values) > 0.5


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def mihomo_delays(core, proxies, test_url, timeout_ms, workers, base=None, live=None,
                  verify_url=None, max_ping=0, tick=None):
    """Satu batch URL-test lewat mihomo. proxies: {id: dict}. base: {id: index node asal} (penolakan satu
    node ikut menolak semua varian-nya). Node lolos hanya kalau delay > 0 di test_url DAN (bila verify_url)
    di URL kedua juga, dengan rata-rata <= max_ping (0 = tanpa batas).
    Return (ok {id: ms}, gagal {id: (jenis, pesan)}, ditolak {id: pesan});
    jenis: urltest | unstable | slow. tick(ok: bool) dipanggil tiap node selesai."""
    work = tempfile.mkdtemp(prefix="sub2yaml_")
    proc = None
    try:
        port = free_port()
        order = list(proxies)
        rejected = {}
        cfg_path = os.path.join(work, "config.yaml")

        def build():
            plist = []
            for i in order:
                q = dict(proxies[i])
                q["name"] = f"p{i}"
                plist.append(q)
            return to_yaml({"log-level": "error", "allow-lan": False, "unified-delay": True,
                            "external-controller": f"127.0.0.1:{port}",
                            "proxies": plist})

        # Satu proxy invalid bikin mihomo menolak seluruh config -> buang satu-satu.
        for _ in range(500):
            if not order:
                return {}, {}, rejected
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(build())
            r = subprocess.run([core, "-t", "-d", work, "-f", cfg_path],
                               capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                break
            out = (r.stdout or "") + (r.stderr or "")
            m = re.search(r"proxy (\d+):\s*([^\n]*)", out, re.I)
            if not m or int(m.group(1)) >= len(order):
                raise RuntimeError("config ditolak mihomo: " + out.strip()[-300:])
            bad, msg = order.pop(int(m.group(1))), m.group(2).strip()[:120]
            rejected[bad] = msg
            if base:  # node yang sama di profil lain pasti ditolak juga -> tidak perlu diulang
                for g in [g for g in order if base[g] == base[bad]]:
                    order.remove(g)
                    rejected[g] = msg
        else:
            raise RuntimeError("terlalu banyak node yang ditolak mihomo")
        if not order:
            return {}, {}, rejected

        proc = subprocess.Popen([core, "-d", work, "-f", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        api = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # abaikan env proxy
        for _ in range(80):
            if proc.poll() is not None:
                raise RuntimeError("mihomo berhenti sendiri")
            try:
                opener.open(api + "/version", timeout=1).read()
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("API mihomo tidak merespon")

        def probe(i, url):
            q = f"{api}/proxies/p{i}/delay?" + urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
            try:
                with opener.open(q, timeout=timeout_ms / 1000 + 5) as r:
                    d = json.load(r).get("delay")
                    return (int(d), None) if d else (None, "delay 0")
            except urllib.error.HTTPError as e:
                try:
                    return None, str(json.load(e).get("message", f"HTTP {e.code}"))[:100]
                except Exception:
                    return None, f"HTTP {e.code}"
            except Exception as e:
                return None, str(e)[:100]

        def one(i):
            ms, e = probe(i, test_url)
            res = (i, ms, None)
            if not ms:
                res = (i, None, ("urltest", e or "gagal"))
            elif verify_url:  # konfirmasi di URL kedua: buang node yang cuma "kebetulan" lolos sekali
                ms2, e2 = probe(i, verify_url)
                if not ms2:
                    res = (i, None, ("unstable", f"lolos tes 1 tapi gagal verifikasi ulang: {e2}"))
                else:
                    res = (i, (ms + ms2) // 2, None)
            if res[1] and max_ping and res[1] > max_ping:
                res = (i, None, ("slow", f"{res[1]}ms > batas {max_ping}ms"))
            if tick:
                tick(bool(res[1]))
            return res

        ok, fails = {}, {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for i, ms, bad in ex.map(one, order):
                if ms:
                    ok[i] = max(1, ms)
                else:
                    fails[i] = bad
        return ok, fails, rejected
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------
# Deteksi negara (bendera di remark -> nama negara -> kode 2 huruf -> TLD)
# --------------------------------------------------------------------------
COUNTRIES = {
    "US": "United States|USA|America", "GB": "United Kingdom|Britain|England",
    "DE": "Germany|Deutschland", "FR": "France", "NL": "Netherlands|Holland",
    "SG": "Singapore", "JP": "Japan", "KR": "South Korea|Korea",
    "HK": "Hong Kong", "TW": "Taiwan", "CN": "China", "IN": "India",
    "ID": "Indonesia", "MY": "Malaysia", "TH": "Thailand", "VN": "Vietnam",
    "PH": "Philippines", "AU": "Australia", "NZ": "New Zealand", "CA": "Canada",
    "BR": "Brazil", "AR": "Argentina", "MX": "Mexico", "CL": "Chile",
    "RU": "Russia", "UA": "Ukraine", "PL": "Poland", "SE": "Sweden",
    "NO": "Norway", "FI": "Finland", "DK": "Denmark", "CH": "Switzerland",
    "AT": "Austria", "BE": "Belgium", "IE": "Ireland", "ES": "Spain",
    "PT": "Portugal", "IT": "Italy", "GR": "Greece", "TR": "Turkey|Turkiye",
    "IL": "Israel", "AE": "UAE|Emirates", "SA": "Saudi Arabia", "IR": "Iran",
    "KZ": "Kazakhstan", "CZ": "Czech", "RO": "Romania", "BG": "Bulgaria",
    "HU": "Hungary", "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia",
    "MD": "Moldova", "RS": "Serbia", "ZA": "South Africa", "EG": "Egypt",
    "PK": "Pakistan", "BD": "Bangladesh", "LU": "Luxembourg", "IS": "Iceland",
    "CY": "Cyprus", "AM": "Armenia", "GE": "Georgia", "SK": "Slovakia",
    "HR": "Croatia", "SI": "Slovenia", "AL": "Albania", "BY": "Belarus",
    "KH": "Cambodia", "LK": "Sri Lanka", "NP": "Nepal", "MN": "Mongolia",
    "MO": "Macau|Macao", "CO": "Colombia", "PE": "Peru", "PA": "Panama",
}
NAME_RES = sorted(
    ((re.compile(r"(?<![a-z])" + re.escape(n) + r"(?![a-z])", re.I), cc)
     for cc, names in COUNTRIES.items() for n in names.split("|")),
    key=lambda t: -len(t[0].pattern))
CODE_AMBIGUOUS = {"IN", "IS", "IT", "AT", "ID", "CO", "PA", "AM", "GE", "MO", "SK", "NO", "BY"}
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}|\U0001F3F3\uFE0F?")


def flag(cc):
    if cc == "XX":
        return "\U0001F3F3\uFE0F"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)


def detect_country(remark, server):
    m = re.search("[\U0001F1E6-\U0001F1FF]{2}", remark)
    if m:
        cc = "".join(chr(ord(c) - 0x1F1E6 + 65) for c in m.group())
        if cc == "UK":
            cc = "GB"
        return cc
    for rx, cc in NAME_RES:
        if rx.search(remark):
            return cc
    for tok in re.findall(r"(?<![A-Za-z])[A-Z]{2}(?![A-Za-z])", remark):
        if tok in COUNTRIES and tok not in CODE_AMBIGUOUS:
            return tok
        if tok == "UK":
            return "GB"
    first = re.match(r"[A-Za-z]{2}(?![A-Za-z])", remark.strip())  # mis. "hk-01", "sg_3"
    if first:
        tok = first.group().upper()
        if tok in COUNTRIES and tok not in CODE_AMBIGUOUS:
            return tok
    tld = server.rsplit(".", 1)[-1].upper() if "." in server else ""
    if tld == "UK":
        return "GB"
    if tld in COUNTRIES and tld not in ("CO", "ID", "IS", "IT", "AT", "IN", "AM", "PA", "MO"):
        return tld
    return "XX"


def strip_flags(name, fallback):
    s = FLAG_RE.sub("", name)
    s = re.sub(r"\s+", " ", s)  # sisa spasi ganda setelah bendera dibuang
    s = re.sub(r"^[\s\-|_\[\]()]+|[\s\-|_\[\]()]+$", "", s)
    return s or fallback


def build_output(proxies, chosen, result, sort_mode, ccs, tag=""):
    """Beri nama final (bendera + remark + ms [tag]) dan urutkan. Return (out, counts, names{idx: nama})."""
    items = [(ccs[i], result[i], i) for i in chosen]
    if sort_mode == "country":  # grup per negara (A-Z, Unknown terakhir), di dalamnya ping terkecil dulu
        items.sort(key=lambda t: (t[0] == "XX", t[0], t[1]))
    else:
        items.sort(key=lambda t: t[1])
    used, out, counts, names = {}, [], {}, {}
    for cc, ms, i in items:
        p = dict(proxies[i])
        name = f"{flag(cc)} {strip_flags(p['name'], p['server'])} | {ms}ms"
        if tag:
            name += f" [{tag}]"
        used[name] = used.get(name, 0) + 1
        if used[name] > 1:
            name += f" #{used[name]}"
        p["name"] = name
        names[i] = name
        out.append(p)
        counts[cc] = counts.get(cc, 0) + 1
    return out, counts, names


# --------------------------------------------------------------------------
# Bulk edit config (override)
# --------------------------------------------------------------------------
OV_KEYS = ("sni", "host", "path", "server", "port", "alpn", "fp", "insecure")
ONLY_KEYS = ("type", "network", "tls", "country")


def new_overrides():
    d = {k: None for k in OV_KEYS}
    d["set"], d["only"] = {}, {}
    return d


def ov_active(ov):
    return any(ov[k] is not None for k in OV_KEYS) or bool(ov["set"])


def only_str(only):
    return ",".join(f"{k}={'|'.join(sorted(v))}" for k, v in only.items())


def ov_describe(ov):
    parts = [f"{k}={','.join(ov[k]) if k == 'alpn' else ov[k]}" for k in OV_KEYS if ov[k] is not None]
    parts += [f"{k}={json.dumps(v)}" for k, v in ov["set"].items()]
    if ov["only"]:
        parts.append(f"[hanya node: {only_str(ov['only'])}]")
    return " ".join(parts) if parts else "(tidak ada)"


def norm_field(key, v):
    if key == "port":
        if not str(v).isdigit() or not 1 <= int(v) <= 65535:
            raise ValueError("port harus 1-65535")
        return int(v)
    if key == "alpn":
        a = [x.strip() for x in v.split(",") if x.strip()] if isinstance(v, str) else list(v)
        if not a:
            raise ValueError("alpn kosong")
        return a
    if key == "fp":
        if str(v).lower() not in FINGERPRINTS:
            raise ValueError("fp harus salah satu: " + ", ".join(sorted(FINGERPRINTS)))
        return str(v).lower()
    if key == "insecure":
        return v if isinstance(v, bool) else truthy(v)
    return str(v)


def parse_only(s):
    only = {}
    for part in s.split(","):
        if not part.strip():
            continue
        k, sep, v = part.partition("=")
        k = k.strip().lower()
        if not sep or k not in ONLY_KEYS or not v.strip():
            raise ValueError(f"filter tidak valid '{part}' (format: {'|'.join(ONLY_KEYS)}=nilai1|nilai2)")
        only[k] = {x.strip().lower() for x in v.split("|") if x.strip()}
    return only


def parse_set(s):
    d = {}
    for part in s.split(","):
        if not part.strip():
            continue
        k, sep, v = part.partition("=")
        if not sep or not k.strip():
            raise ValueError(f"format harus key=value: '{part}'")
        try:
            d[k.strip()] = json.loads(v)
        except Exception:
            d[k.strip()] = v
    return d


def build_overrides(args):
    ov = new_overrides()
    if args.overrides:
        with open(args.overrides, "r", encoding="utf-8") as f:
            d = json.load(f)
        for k in OV_KEYS:
            if d.get(k) is not None:
                ov[k] = norm_field(k, d[k])
        ov["set"].update(d.get("set") or {})
        if d.get("only"):
            ov["only"] = parse_only(d["only"])
    for k in ("sni", "host", "path", "server", "port", "alpn", "fp"):
        v = getattr(args, k)
        if v is not None:
            ov[k] = norm_field(k, v)
    if args.insecure:
        ov["insecure"] = True
    for item in args.set or []:
        ov["set"].update(parse_set(item))
    if args.only:
        ov["only"] = parse_only(args.only)
    return ov


PRIMARY = ("sni", "host", "server", "port", "path", "alpn", "fp")
PROFILE_META = {  # field -> (file, judul, tag di nama node)
    "sni": ("custom-sni.yaml", "Custom SNI", "sni"),
    "host": ("custom-host.yaml", "Custom Host", "host"),
    "server": ("custom-address.yaml", "Custom Address", "addr"),
    "port": ("custom-port.yaml", "Custom Port", "port"),
    "path": ("custom-path.yaml", "Custom Path", "path"),
    "alpn": ("custom-alpn.yaml", "Custom ALPN", "alpn"),
    "fp": ("custom-fp.yaml", "Custom Fingerprint", "fp"),
}


def make_profiles(ov, combined=True):
    """free = config asli. Tiap field custom yang diisi = 1 profil sendiri (dites terpisah).
    insecure / set / only adalah pelengkap yang ikut ke semua profil custom."""
    prim = [k for k in PRIMARY if ov[k] is not None]

    def sub(keys):
        d = new_overrides()
        for k in keys:
            d[k] = ov[k]
        d["insecure"], d["set"], d["only"] = ov["insecure"], dict(ov["set"]), ov["only"]
        return d

    profs = [{"key": "free", "file": "free.yaml", "title": "Free (tanpa custom config)",
              "tag": "", "ov": None, "prim": ()}]
    for k in prim:
        f, title, tag = PROFILE_META[k]
        profs.append({"key": k, "file": f, "title": title, "tag": tag, "ov": sub([k]), "prim": (k,)})
    if combined and len(prim) > 1:
        profs.append({"key": "combined", "file": "custom-combined.yaml", "tag": "combo",
                      "title": "Custom gabungan (semua field sekaligus)",
                      "ov": sub(prim), "prim": tuple(prim)})
    return profs


def matches(p, only):
    for k, vals in only.items():
        if k == "type":
            v = p["type"]
        elif k == "network":
            v = p.get("network", "tcp")
        elif k == "tls":
            v = str(bool(p.get("tls") or p["type"] == "trojan")).lower()
        else:
            v = detect_country(p["name"], p["server"])
        if v.lower() not in vals:
            return False
    return True


def apply_overrides(p, ov):
    """Return (proxy baru, daftar field yang benar-benar berubah)."""
    q = json.loads(json.dumps(p))
    ch = []
    t, net = q["type"], q.get("network", "tcp")
    tls = bool(q.get("tls")) or t == "trojan"
    if ov["server"]:
        q["server"] = ov["server"]
        ch.append("server")
    if ov["port"]:
        q["port"] = ov["port"]
        ch.append("port")
    if ov["sni"] and tls:
        q["sni" if t == "trojan" else "servername"] = ov["sni"]
        ch.append("sni")
    if ov["host"]:
        h, plugin = ov["host"], q.get("plugin")
        if net == "ws":
            q.setdefault("ws-opts", {}).setdefault("headers", {})["Host"] = h
        elif net == "h2":
            q.setdefault("h2-opts", {})["host"] = [h]
        elif net == "http":
            q.setdefault("http-opts", {}).setdefault("headers", {})["Host"] = [h]
        elif plugin in ("obfs", "v2ray-plugin"):
            q["plugin-opts"]["host"] = h
        else:
            h = None
        if h:
            ch.append("host")
    if ov["path"]:
        pa, plugin = ov["path"], q.get("plugin")
        if net == "ws":
            q.setdefault("ws-opts", {})["path"] = pa
        elif net == "h2":
            q.setdefault("h2-opts", {})["path"] = pa
        elif net == "http":
            q.setdefault("http-opts", {})["path"] = [pa]
        elif net == "grpc":
            q.setdefault("grpc-opts", {})["grpc-service-name"] = pa
        elif plugin == "v2ray-plugin":
            q["plugin-opts"]["path"] = pa
        else:
            pa = None
        if pa:
            ch.append("path")
    if ov["alpn"] and tls:
        q["alpn"] = ov["alpn"]
        ch.append("alpn")
    if ov["fp"] and tls:
        q["client-fingerprint"] = ov["fp"]
        ch.append("fp")
    if ov["insecure"] is not None and tls:
        q["skip-cert-verify"] = bool(ov["insecure"])
        ch.append("insecure")
    for k, v in ov["set"].items():
        q[k] = v
        ch.append(k)
    return q, ch


def eff_sni(p):
    return p.get("servername") or p.get("sni") or ""


def eff_host(p):
    net = p.get("network", "tcp")
    if net == "ws":
        return p.get("ws-opts", {}).get("headers", {}).get("Host", "")
    if net == "h2":
        return ",".join(p.get("h2-opts", {}).get("host", []))
    if net == "http":
        return ",".join(p.get("http-opts", {}).get("headers", {}).get("Host", []))
    return (p.get("plugin-opts") or {}).get("host", "")


# --------------------------------------------------------------------------
# Source (src/*.txt) - baca, hitung, update
# --------------------------------------------------------------------------
def valid_source(s):
    return bool(re.match(r"https?://\S+$", s)) or os.path.isfile(s)


def src_files():
    return sorted(glob.glob(os.path.join(SRC_DIR, "*.txt")))


_LINK_CACHE = {}


def count_links(path):
    """Jumlah link di file source (cache per mtime supaya menu tetap cepat)."""
    try:
        key = (path, os.path.getmtime(path))
        if key not in _LINK_CACHE:
            _LINK_CACHE[key] = len(extract_links(fetch(path)))
        return _LINK_CACHE[key]
    except OSError:
        return 0


def src_label(s):
    return rel(s) if os.path.isfile(s) else s


def update_source(fname, url):
    """Unduh url -> src/fname. File lama baru diganti kalau isi baru valid (atomik)."""
    path = os.path.join(SRC_DIR, fname)
    old = count_links(path) if os.path.isfile(path) else None
    with Live(f"Unduh {fname}") as lv:
        try:
            links = extract_links(text := fetch(url, lv))
            if not links:
                raise ValueError("isi bukan subscription (base64 / daftar link) yang valid")
            os.makedirs(SRC_DIR, exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, path)
        except Exception as e:
            lv.fail(f"{type(e).__name__}: {str(e)[:90]}" + ("  (file lama tidak diubah)" if old is not None else ""))
            return False
        lv.done(f"{len(links)} link" + (f", sebelumnya {old}" if old is not None else "")
                + f", {human_size(len(text))}")
    return True


def update_menu():
    clear_screen(); banner(); section("Update source")
    print(f"  {C.DIM}Unduh ulang file di src/ dari URL aslinya. File lama tetap aman kalau unduhan gagal.{C.RESET}\n")
    for n, (fname, label, url) in enumerate(SOURCES, 1):
        path = os.path.join(SRC_DIR, fname)
        st = (f"{human_size(os.path.getsize(path))}, {count_links(path)} link, "
              f"{human_age(os.path.getmtime(path))}") if os.path.isfile(path) else "belum ada"
        print(f"  {C.CYAN}[{n}]{C.RESET} {fname:<15} {C.DIM}{st}{C.RESET}\n      {label}\n      {C.GRAY}{url}{C.RESET}")
    print(f"\n  {C.CYAN}[A]{C.RESET} Semua {C.DIM}(default){C.RESET}   {C.CYAN}[Enter]{C.RESET} Batal\n{sep(50)}")
    v = ask(f"{C.YELLOW}Update nomor (pisah koma) / A ❯{C.RESET} ").strip().lower()
    if not v:
        return False
    if v in ("a", "semua"):
        idx = list(range(1, len(SOURCES) + 1))
    else:
        try:
            idx = [int(x) for x in v.replace(" ", "").split(",") if x]
        except ValueError:
            idx = []
        if not idx or any(not 1 <= i <= len(SOURCES) for i in idx):
            err("Pilihan tidak valid."); time.sleep(0.8)
            return False
    print()
    good = [update_source(SOURCES[i - 1][0], SOURCES[i - 1][2]) for i in dict.fromkeys(idx)]
    pause("Tekan Enter untuk kembali ke menu...")
    return any(good)


def ensure_sources():
    """Pertama kali jalan (src/ kosong): unduh semua source preset."""
    if src_files():
        return
    warn("Folder src/ masih kosong - mengunduh source bawaan ...")
    for fname, _, url in SOURCES:
        update_source(fname, url)
    print()


def pick_source(sources):
    clear_screen(); banner(); section("Pilih source (file)")
    files = src_files()
    if not files:
        warn("Belum ada file .txt di src/. Pakai [8] Update source untuk mengunduhnya.")
        pause()
        return sources
    print(f"  {C.DIM}File di {rel(SRC_DIR)}/  (* = sedang dipakai){C.RESET}\n")
    for n, f in enumerate(files, 1):
        mark = f"{C.GREEN}*{C.RESET}" if f in sources else " "
        print(f" {mark}{C.CYAN}[{n}]{C.RESET} {os.path.basename(f):<18} "
              f"{C.DIM}{human_size(os.path.getsize(f))}, {count_links(f)} link, {human_age(os.path.getmtime(f))}{C.RESET}")
    print(f"\n  {C.CYAN}[A]{C.RESET} Semua file {C.DIM}(gabungkan){C.RESET}   {C.CYAN}[Enter]{C.RESET} Batal\n{sep(50)}")
    v = ask(f"{C.YELLOW}Nomor (pisah koma, mis. 1,2) / A / path file ❯{C.RESET} ").strip().strip("\"'")
    if not v:
        return sources
    if v.lower() in ("a", "semua"):
        return files
    try:
        idx = [int(x) for x in v.replace(" ", "").split(",") if x]
    except ValueError:
        idx = []
    if idx and all(1 <= i <= len(files) for i in idx):
        return [files[i - 1] for i in dict.fromkeys(idx)]
    if os.path.isfile(v):
        return [os.path.abspath(v)]
    err("Nomor / path tidak valid."); time.sleep(0.8)
    return sources


def ask_source(prompt):
    s = ask(prompt).strip().strip("\"'")
    if not s:
        return None
    if not valid_source(s):
        err("Harus URL http(s):// atau path file yang ada."); time.sleep(1.0)
        return None
    return s if s.startswith("http") else os.path.abspath(s)


# --------------------------------------------------------------------------
# Menu interaktif
# --------------------------------------------------------------------------
SIMPLE_FIELDS = [("sni", "SNI"), ("host", "Host header"), ("server", "Address (server)")]
ADV_FIELDS = [("port", "Port"), ("path", "Path (gRPC: service name)"), ("alpn", "ALPN"),
              ("fp", "Client fingerprint"), ("insecure", "Skip cert verify (insecure)"),
              ("set", "Field tambahan (key=value)"), ("only", "Filter node (terapkan hanya ke ...)")]
FIELD_HINTS = {"port": "1-65535", "alpn": "mis. h2,http/1.1", "insecure": "y/n",
               "fp": "chrome/firefox/safari/ios/...", "set": "key=value, pisah koma, mis. udp=false",
               "only": "mis. type=vless,network=ws  (kunci: type, network, tls, country)"}


def show_value(ov, key):
    if key == "set":
        return ",".join(f"{k}={json.dumps(v)}" for k, v in ov["set"].items()) or "-"
    if key == "only":
        return only_str(ov["only"]) or "-"
    v = ov[key]
    if v is None:
        return "-"
    if key == "alpn":
        return ",".join(v)
    if key == "insecure":
        return "ya" if v else "tidak"
    return str(v)


def edit_field(ov, key, label):
    hint = f" {C.DIM}({FIELD_HINTS[key]}){C.RESET}" if key in FIELD_HINTS else ""
    print(f"\n{C.BOLD}{label}{C.RESET}{hint}")
    v = ask(f"{C.YELLOW}Nilai baru [{show_value(ov, key)}] (Enter = batal, '-' = hapus) ❯{C.RESET} ").strip()
    if not v:
        return
    if v == "-":
        if key == "set":
            ov["set"] = {}
        elif key == "only":
            ov["only"] = {}
        else:
            ov[key] = None
        return
    try:
        if key == "set":
            ov["set"].update(parse_set(v))
        elif key == "only":
            ov["only"] = parse_only(v)
        elif key == "insecure":
            ov[key] = v.lower() in ("y", "ya", "yes", "1", "true", "t")
        else:
            ov[key] = norm_field(key, v)
    except ValueError as e:
        err(str(e)); time.sleep(1.2)
        return
    if key == "sni" and ov["insecure"] is None:
        warn("Tip: SNI custom biasanya butuh 'Skip cert verify' (Edit config > Opsi lanjutan).")
        time.sleep(1.5)


def adv_menu(ov):
    while True:
        clear_screen(); banner(); section("Opsi lanjutan")
        print(f"  {C.DIM}port/path/alpn/fingerprint -> file custom sendiri; insecure/field tambahan/filter")
        print(f"  -> pelengkap yang berlaku ke semua file custom{C.RESET}\n")
        for n, (key, label) in enumerate(ADV_FIELDS, 1):
            f = PROFILE_META[key][0] if key in PROFILE_META else "(pelengkap)"
            print(f"  {C.CYAN}[{n}]{C.RESET} {label:<36} {C.GREEN}[{show_value(ov, key)}]{C.RESET}  {C.DIM}{f}{C.RESET}")
        print(f"  {C.CYAN}[Enter]{C.RESET} Kembali\n{sep(50)}")
        c = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if c == "":
            return
        if c.isdigit() and 1 <= int(c) <= len(ADV_FIELDS):
            edit_field(ov, *ADV_FIELDS[int(c) - 1])
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


def config_menu(ov):
    while True:
        clear_screen(); banner(); section("Edit config")
        print(f"  {C.DIM}Aktif: {ov_describe(ov)}")
        print(f"  Tiap field yang diisi dites TERPISAH dan disimpan ke file sendiri.{C.RESET}\n")
        for n, (key, label) in enumerate(SIMPLE_FIELDS, 1):
            print(f"  {C.CYAN}[{n}]{C.RESET} Edit {label:<18} {C.GREEN}[{show_value(ov, key)}]{C.RESET}  "
                  f"{C.DIM}-> {PROFILE_META[key][0]}{C.RESET}")
        print(f"  {C.CYAN}[4]{C.RESET} Opsi lanjutan {C.DIM}(port, path, alpn, fingerprint, ...){C.RESET}")
        print(f"  {C.CYAN}[5]{C.RESET} Hapus semua custom config")
        print(f"  {C.CYAN}[Enter]{C.RESET} Kembali\n{sep(50)}")
        c = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if c == "":
            return
        if c in ("1", "2", "3"):
            edit_field(ov, *SIMPLE_FIELDS[int(c) - 1])
        elif c == "4":
            adv_menu(ov)
        elif c == "5":
            ov.clear()
            ov.update(new_overrides())
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


_CORE_MEMO = {}


def menu(args, sources, ov):
    while True:
        clear_screen(); banner(); section("MENU UTAMA")
        top = "100 (default)" if args.top is None else ("semua" if args.top == 0 else args.top)
        print(f"  {C.DIM}Source{C.RESET}   : " + (f"\n{' ' * 12}".join(
            f"{C.WHITE}{src_label(x)}{C.RESET}" for x in sources) if sources else f"{C.RED}(belum ada){C.RESET}"))
        print(f"  {C.DIM}Node{C.RESET}     : {C.WHITE}{top}{C.RESET} {C.DIM}(free.yaml){C.RESET}   "
              f"{C.DIM}Urut{C.RESET}: {C.WHITE}{args.sort}{C.RESET}")
        print(f"  {C.DIM}Output{C.RESET}   : {C.WHITE}{rel(args.outdir)}/{C.RESET}")
        if args.tcp_only:
            print(f"  {C.DIM}Tes{C.RESET}      : {C.YELLOW}TCP saja (tidak menjamin node bisa dipakai){C.RESET}")
        else:
            if "core" not in _CORE_MEMO:
                _CORE_MEMO["core"] = (os.path.expanduser(args.mihomo) if args.mihomo else find_core())
            c_ = _CORE_MEMO["core"]
            print(f"  {C.DIM}Tes{C.RESET}      : {C.WHITE}URL-test mihomo{C.RESET} "
                  + (f"{C.DIM}({rel(c_)}){C.RESET}" if c_ else
                     f"{C.YELLOW}(core belum ada - diunduh otomatis saat Mulai, atau pilih [9]){C.RESET}"))
        print(f"  {C.DIM}Custom{C.RESET}   : {C.WHITE}{ov_describe(ov)}{C.RESET}")
        print(f"  {C.DIM}File{C.RESET}     : {C.WHITE}" + ", ".join(p["file"] for p in make_profiles(ov)) + C.RESET)
        print(sep(50))
        print(f"  {C.CYAN}[1]{C.RESET} Pilih source (file)")
        print(f"  {C.CYAN}[2]{C.RESET} URL custom (base64)")
        print(f"  {C.CYAN}[3]{C.RESET} Tambah URL (gabungkan beberapa sumber)")
        print(f"  {C.CYAN}[4]{C.RESET} Ubah jumlah node free.yaml {C.DIM}(bebas; hanya node yang lolos URL-test, 0 = semua){C.RESET}")
        print(f"  {C.CYAN}[5]{C.RESET} Ubah folder output")
        print(f"  {C.CYAN}[6]{C.RESET} Ganti urutan {C.DIM}(negara / ping){C.RESET}")
        print(f"  {C.CYAN}[7]{C.RESET} Edit config {C.DIM}(SNI / Host / Address / dll){C.RESET}")
        print(f"  {C.CYAN}[8]{C.RESET} Update source")
        print(f"  {C.CYAN}[9]{C.RESET} Unduh / perbarui core mihomo {C.DIM}(untuk tes URL-test){C.RESET}")
        print(sep(50))
        print(f"  {C.GREEN}[Enter]{C.RESET} Mulai    {C.RED}[0]{C.RESET} Keluar")
        print(sep(50))
        c = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if c == "":
            if sources:
                return sources
            err("Belum ada source. Pilih [1] / [2] / [8] dulu."); time.sleep(1.2)
        elif c == "0":
            clear_screen(); print(f"\n  {C.GREEN}Terima kasih sudah pakai Hikari /.CLASH!{C.RESET}\n"); sys.exit(0)
        elif c == "1":
            sources = pick_source(sources)
        elif c == "2":
            clear_screen(); banner(); section("URL custom (base64)")
            print(f"  {C.DIM}Ganti sumber dengan satu URL subscription (isi base64 / daftar link).{C.RESET}\n")
            x = ask_source(f"{C.YELLOW}URL ❯{C.RESET} ")
            if x:
                sources = [x]
        elif c == "3":
            clear_screen(); banner(); section("Tambah URL")
            print(f"  {C.DIM}Tambahkan sumber lain; semua sumber digabung & duplikat dibuang.{C.RESET}\n")
            x = ask_source(f"{C.YELLOW}URL tambahan ❯{C.RESET} ")
            if x and x not in sources:
                sources = sources + [x]
        elif c == "4":
            v = ask(f"{C.YELLOW}Jumlah node yang diinginkan (0 = semua yang lolos, maks 5000) ❯{C.RESET} ").strip()
            if v.isdigit() and 0 <= int(v) <= 5000:
                args.top = int(v)
            else:
                err("Angka tidak valid."); time.sleep(0.8)
        elif c == "5":
            v = ask(f"{C.YELLOW}Folder output [{rel(args.outdir)}] ❯{C.RESET} ").strip().strip("\"'")
            if v:
                args.outdir = resolve_dir(v)
        elif c == "6":
            args.sort = "ping" if args.sort == "country" else "country"
        elif c == "7":
            config_menu(ov)
        elif c == "8":
            if update_menu() and not sources:
                sources = src_files()
        elif c == "9":
            clear_screen(); banner(); section("Core mihomo")
            _CORE_MEMO["core"] = download_core() or _CORE_MEMO.get("core")
            pause()
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


def resolve_dir(p):
    """Folder relatif = relatif ke lokasi script (bukan cwd), sama seperti hikari_converter."""
    p = os.path.expanduser(p)
    return p if os.path.isabs(p) else os.path.normpath(os.path.join(SCRIPT_DIR, p))


def collect_links(sources):
    links = []
    for s in sources:
        with Live(f"Membaca {src_label(s)}") as lv:
            try:
                got = extract_links(fetch(s, lv))
            except Exception as e:
                lv.fail(f"{type(e).__name__}: {str(e)[:90]}")
                continue
            lv.done(f"{len(got)} link")
        links += got
    return links


# --------------------------------------------------------------------------
# Laporan
# --------------------------------------------------------------------------
FAIL_REASONS = [
    ("tcp_dead", "TCP gagal (timeout / port tertutup / DNS gagal)"),
    ("urltest", "URL-test gagal lewat mihomo (tidak bisa konek / tidak ada respon)"),
    ("unstable", "Lolos tes pertama tapi GAGAL verifikasi ulang (tidak stabil)"),
    ("slow", "Terlalu lambat (di atas --max-ping)"),
    ("rejected", "Ditolak mihomo (config tidak valid)"),
    ("not_tested", "Tidak dites (target jumlah node sudah tercapai / di luar --prefilter)"),
]
SKIP_REASONS = [
    ("filtered", "Di luar filter --only (tidak diubah, tidak dites)"),
    ("no_override", "Override tidak berlaku pada node ini, mis. tanpa TLS / tanpa transport terkait (tidak dites)"),
]


def fmt_row(n, r, note=""):
    p, cc = r["proxy"], r["cc"]
    ms = f"{r['ms']}ms" if r["ms"] else "-"
    chg = f"  [diubah: {','.join(r['changes'])}]" if r["changes"] else ""
    det = f"  -> {r['detail']}" if r.get("detail") else ""
    return (f"{n:>4}. {flag(cc)} {cc if cc != 'XX' else '??':<2} {ms:>7}  {p['type']:<6} "
            f"{p.get('network', 'tcp'):<5} {p['server']}:{p['port']}  "
            f"sni={eff_sni(p) or '-'} host={eff_host(p) or '-'}  | {r.get('final') or p['name']}{chg}{note}{det}")


def group(recs, status, reason):
    idx = [i for i, r in enumerate(recs) if r["status"] == status and r["reason"] == reason]
    idx.sort(key=lambda i: (recs[i]["cc"] == "XX", recs[i]["cc"], recs[i]["proxy"]["name"]))
    return idx


def write_yaml_file(path, proxies, header):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_yaml({"proxies": proxies}, header))


def profile_lines(prof, cap):
    recs, L = prof["recs"], []
    ok_all, chosen = prof["report_ok"], set(prof["chosen"])
    n_fail = sum(1 for r in recs if r["status"] == "fail")
    n_skip = sum(1 for r in recs if r["status"] == "skip")
    L += ["=" * 78, f"PROFIL: {prof['title']}  ->  {prof['file']}", "=" * 78,
          "Config   : " + (ov_describe(prof["ov"]) if prof["ov"] else "(tidak ada - config asli node)"),
          f"Berhasil : {len(ok_all)} (masuk file: {len(chosen)}) | Gagal: {n_fail} | Tidak dites: {n_skip}"]
    for key, title in FAIL_REASONS:
        n = len(group(recs, "fail", key))
        if n:
            L.append(f"    - {title}: {n}")
    for key, title in SKIP_REASONS:
        n = len(group(recs, "skip", key))
        if n:
            L.append(f"    - {title.split(' (')[0]}: {n}")
    if prof["counts"]:
        L.append("Per negara (masuk file): " + ", ".join(
            f"{flag(cc)}{cc if cc != 'XX' else '?'} {n}" for cc, n in
            sorted(prof["counts"].items(), key=lambda t: (t[0] == 'XX', t[0]))))
    L.append("")

    def section(title, idx, note_fn=None):
        L.append("-" * 78)
        L.append(f"{title} ({len(idx)})")
        L.append("-" * 78)
        for n, i in enumerate(idx if cap is None else idx[:cap], 1):
            L.append(fmt_row(n, recs[i], note_fn(i) if note_fn else ""))
        if cap is not None and len(idx) > cap:
            L.append(f"  ... {len(idx) - cap} baris lagi, lihat file laporan lengkap")
        L.append("")

    section("✅ BERHASIL", ok_all, lambda i: "" if i in chosen else "  [di luar batas jumlah node]")
    for key, title in FAIL_REASONS:
        idx = group(recs, "fail", key)
        if idx:
            section("❌ GAGAL - " + title, idx)
    for key, title in SKIP_REASONS:
        idx = group(recs, "skip", key)
        if idx:
            section("⏭  TIDAK DITES - " + title, idx)
    return L


def report_lines(c, full=True, cap=None):
    L = ["=" * 78, "LAPORAN HASIL TES - sub2yaml", "=" * 78,
         f"Waktu        : {time.strftime('%Y-%m-%d %H:%M:%S')}",
         f"Sumber       : {'; '.join(c['sources'])}",
         f"Metode tes   : {c['method']}" + (f"  ({c['note']})" if c["note"] else ""),
         f"Folder output: {c['outdir']}/   | urutan: {c['sort']}",
         f"Link terbaca : {c['n_links']}  | node valid: {c['n_nodes']}  | dilewati saat parse: "
         f"{sum(c['stats'].values())} ({c['stats']['unsupported']} tidak didukung, "
         f"{c['stats']['invalid']} rusak, {c['stats']['duplicate']} duplikat)", "",
         f"{'Profil':<40}{'File':<22}{'Berhasil':>9}{'Gagal':>7}{'Skip':>6}"]
    for prof in c["profiles"]:
        rs = prof["recs"]
        L.append(f"{prof['title']:<40}{prof['file']:<22}{len(prof['report_ok']):>9}"
                 f"{sum(1 for r in rs if r['status'] == 'fail'):>7}"
                 f"{sum(1 for r in rs if r['status'] == 'skip'):>6}")
    L.append("")
    for prof in c["profiles"]:
        L += profile_lines(prof, cap)
    if full and c["skipped"]:
        L += ["-" * 78, f"LINK DILEWATI SAAT PARSE ({len(c['skipped'])})", "-" * 78]
        label = {"unsupported": "tidak didukung", "invalid": "rusak", "duplicate": "duplikat"}
        for n, (kind, scheme, remark) in enumerate(c["skipped"], 1):
            L.append(f"{n:>5}. {scheme:<8} {label[kind]:<15} | {remark}")
        L.append("")
    return L


# --------------------------------------------------------------------------
def paint(line):
    """Warnai satu baris laporan untuk layar (report.txt tetap polos)."""
    st = line.lstrip()
    if not st:
        return line
    if st.startswith(("====", "----")):
        return f"{C.GRAY}{line}{C.RESET}"
    if st.startswith(("LAPORAN HASIL", "PROFIL:")):
        return f"{C.BOLD}{C.MAGENTA if st.startswith('LAPORAN') else C.CYAN}{line}{C.RESET}"
    if st.startswith("✅"):
        return f"{C.BOLD}{C.GREEN}{line}{C.RESET}"
    if st.startswith("❌"):
        return f"{C.BOLD}{C.RED}{line}{C.RESET}"
    if st.startswith("⏭"):
        return f"{C.BOLD}{C.YELLOW}{line}{C.RESET}"
    head, sep_, rest = line.partition(" : ")
    if sep_ and len(head) <= 14 and not head[:1].isdigit():
        return f"{C.DIM}{head}{C.RESET} : {rest}"
    if st.startswith(("Berhasil", "Config", "Per negara")):
        k, _, v = line.partition(":")
        return f"{C.DIM}{k}{C.RESET}:{v}"
    return line


def main():
    ap = argparse.ArgumentParser(
        description="Subscription -> proxies Mihomo: tes, custom config per profil, laporan detail",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Contoh:")[1])
    ap.add_argument("source", nargs="*", help="URL atau file subscription (boleh lebih dari satu). "
                    "Kosong = pakai semua file di src/ (dengan menu interaktif jika di terminal)")
    ap.add_argument("-o", "--outdir", default=DEFAULT_OUTDIR,
                    help="folder output (default: hasil/proxy di samping script; path relatif = relatif ke script)")
    ap.add_argument("--update-source", action="store_true",
                    help="unduh ulang file di src/ dari URL aslinya, lalu keluar")
    ap.add_argument("--top", type=int, default=None,
                    help="jumlah node di free.yaml - hanya node yang LOLOS URL-test mihomo (default 100; "
                         "0 = semua yang lolos). Tes berhenti begitu jumlah ini tercapai")
    ap.add_argument("--custom-top", type=int, default=0,
                    help="batas node per file custom-*.yaml (default 0 = semua yang berhasil)")
    ap.add_argument("--sort", choices=("country", "ping"), default="country",
                    help="urutan isi file: country (per negara, default) atau ping")
    ap.add_argument("--no-menu", action="store_true", help="jangan tampilkan menu interaktif")
    ap.add_argument("--timeout", type=float, default=3.0, help="timeout tes TCP, detik")
    ap.add_argument("--concurrency", type=int, default=200, help="koneksi TCP paralel")
    ap.add_argument("--prefilter", type=int, default=0,
                    help="free: batasi jumlah kandidat yang di-URL-test; 0 = semua (default; tes berhenti "
                         "sendiri saat target --top tercapai)")
    ap.add_argument("--custom-prefilter", type=int, default=0,
                    help="profil custom: jumlah node tercepat yang di-URL-test; 0 = semua (default)")
    ap.add_argument("--mihomo", help="path binary mihomo (default: cari ./bin, PATH, lokasi Box; kalau tidak ada "
                    "diunduh otomatis ke ./bin)")
    ap.add_argument("--no-download", action="store_true", help="jangan unduh mihomo otomatis")
    ap.add_argument("--tcp-only", action="store_true",
                    help="HANYA tes port TCP (tanpa mihomo). Tidak menjamin node bisa dipakai - jangan dipakai "
                         "kecuali terpaksa")
    ap.add_argument("--test-url", default=TEST_URL)
    ap.add_argument("--verify-url", default=VERIFY_URL,
                    help="URL kedua untuk konfirmasi node yang lolos (default: cp.cloudflare.com)")
    ap.add_argument("--no-verify", action="store_true", help="lewati konfirmasi ke-2 (lebih cepat, kurang ketat)")
    ap.add_argument("--max-ping", type=int, default=3000,
                    help="buang node yang rata-rata delay-nya di atas ini, ms (default 3000; 0 = tanpa batas)")
    ap.add_argument("--test-timeout", type=int, default=5000, help="timeout URL-test, ms")
    ap.add_argument("--workers", type=int, default=50, help="URL-test paralel")
    ap.add_argument("--batch", type=int, default=200, help="jumlah node per batch URL-test (default 200)")
    g = ap.add_argument_group("custom config (tiap field yang diisi dites TERPISAH -> custom-<field>.yaml)")
    g.add_argument("--sni", help="ganti SNI (servername / sni trojan) - hanya node ber-TLS -> custom-sni.yaml")
    g.add_argument("--host", help="ganti Host header (ws/h2/http/plugin) -> custom-host.yaml")
    g.add_argument("--server", help="ganti Address/server (IP atau domain) -> custom-address.yaml")
    g.add_argument("--port", help="ganti port -> custom-port.yaml")
    g.add_argument("--path", help="ganti path (ws/h2/http) / service name (grpc) -> custom-path.yaml")
    g.add_argument("--alpn", help="ganti ALPN, pisah koma -> custom-alpn.yaml")
    g.add_argument("--fp", help="ganti client-fingerprint -> custom-fp.yaml")
    g.add_argument("--no-combined", action="store_true",
                   help="jangan buat custom-combined.yaml (tes semua field custom sekaligus)")
    g.add_argument("--insecure", action="store_true",
                   help="[bersama] skip-cert-verify: true di semua profil custom (biasanya perlu untuk SNI custom)")
    g.add_argument("--set", action="append", metavar="KEY=VAL",
                   help="[bersama] field bebas tingkat node di semua profil custom (mis. udp=false)")
    g.add_argument("--only", help="[bersama] terapkan custom hanya ke node tertentu: "
                   "type=vless|trojan,network=ws,tls=true,country=DE|SG")
    g.add_argument("--overrides", metavar="FILE.json", help="baca custom config dari file JSON")
    r = ap.add_argument_group("laporan")
    r.add_argument("--report", default=None, help="file laporan (default: <outdir>/report.txt; '' = tidak dibuat)")
    r.add_argument("--save-failed", action="store_true", help="simpan juga node gagal ke <outdir>/failed-<profil>.yaml")
    r.add_argument("--verbose", action="store_true", help="tampilkan semua baris laporan di layar")
    args = ap.parse_args()
    args.outdir = resolve_dir(args.outdir)

    if args.update_source:
        banner(); section("Update source")
        good = [update_source(f, u) for f, _, u in SOURCES]
        sys.exit(0 if all(good) else 1)

    try:
        ov = build_overrides(args)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        sys.exit(f"Custom config tidak valid: {e}")
    for x in args.source:
        if not valid_source(x):
            sys.exit(f"Sumber tidak valid: {x}")
    interactive = not args.source and sys.stdin.isatty() and not args.no_menu
    if args.source:
        sources = [x if x.startswith("http") else os.path.abspath(x) for x in args.source]
    else:  # pertama kali jalan: ambil dari file .txt di src/
        if not interactive:
            banner()
        ensure_sources()
        sources = src_files()
        if interactive:
            sources = menu(args, sources, ov)
    if not sources:
        sys.exit("Belum ada source. Jalankan: python3 sub2yaml.py --update-source")

    if interactive:
        clear_screen(); banner()
    elif args.source:
        banner()
    section("PROSES")
    top = 100 if args.top is None else args.top
    profs = make_profiles(ov, combined=not args.no_combined)
    if len(profs) == 1 and ov_active(ov):
        warn("Custom config tidak punya field SNI/Host/Address/Port/Path/ALPN/FP -> hanya free.yaml dibuat "
             "(insecure / --set / --only hanya pelengkap).")
    info("File yang akan dibuat: " + ", ".join(p["file"] for p in profs))
    print()

    links = collect_links(sources)
    with Live("Parse & buang duplikat") as lv:
        nodes, st, skipped = parse_all(links)
        lv.done(f"{len(nodes)} node valid dari {len(links)} link")
    if sum(st.values()):
        log(f"dilewati: {st['unsupported']} tidak didukung, {st['invalid']} rusak, {st['duplicate']} duplikat")
    if not nodes:
        err("Tidak ada node yang bisa diparse."); sys.exit(1)
    ccs = [detect_country(p["name"], p["server"]) for p in nodes]

    # --- bangun rekaman per profil per node (+ terapkan custom config)
    if ov["sni"] and not ov["insecure"]:
        warn("SNI custom biasanya butuh --insecure (sertifikat tidak cocok); "
             "tanpa itu node TLS bisa gagal semua di custom-sni.")
    for prof in profs:
        pov, recs = prof["ov"], []
        for i, p in enumerate(nodes):
            r = {"orig": p, "proxy": p, "cc": ccs[i], "status": None, "reason": "",
                 "detail": "", "ms": None, "changes": []}
            if pov is not None:
                if pov["only"] and not matches(p, pov["only"]):
                    r.update(status="skip", reason="filtered")
                else:
                    r["proxy"], r["changes"] = apply_overrides(p, pov)
                    if not any(k in r["changes"] for k in prof["prim"]):
                        r.update(status="skip", reason="no_override")
            recs.append(r)
        prof["recs"] = recs
        if pov is not None:
            n_ok = sum(1 for r in recs if r["status"] is None)
            log(f"{prof['file']}: {n_ok} node terkena custom config, {len(recs) - n_ok} tidak berlaku/di luar filter")
    if not any(r["status"] is None for prof in profs for r in prof["recs"]):
        err("Tidak ada node yang terkena custom config (cek --only / jenis node)."); sys.exit(1)

    # --- siapkan core mihomo. TANPA URL-test, "berhasil" cuma berarti port terbuka (bukan berarti bisa dipakai),
    #     jadi core wajib kecuali --tcp-only dipilih sengaja.
    core = None
    if args.tcp_only:
        warn("--tcp-only: hanya cek port terbuka. Node di hasil BELUM tentu bisa dipakai (SNI/Host/path tidak dites).")
    else:
        core = resolve_core(args)
        if not core:
            err("Binary mihomo tidak ditemukan dan tidak bisa diunduh otomatis -> tes dihentikan.")
            log("Solusi: taruh binary di ./bin/mihomo, atau jalankan dengan --mihomo /path/mihomo, atau set HIKARI_MIHOMO.")
            log("Tes TCP saja (--tcp-only) tidak menjamin node bisa dipakai, jadi tidak dijalankan otomatis.")
            sys.exit(2)
        ok(f"Core: {rel(core)}  {C.DIM}({core_version(core)}){C.RESET}")

    # --- tahap 1: TCP (target unik: server+port), dipakai bersama oleh semua profil
    targets = {}
    for prof in profs:
        for r in prof["recs"]:
            if r["status"] is None:
                pr = r["proxy"]
                targets[(pr["server"], pr["port"])] = {"server": pr["server"], "port": pr["port"]}
    with Live(f"Tes TCP {len(targets)} target", total=len(targets)) as lv:
        tcp = asyncio.run(tcp_stage(list(targets.items()), args.timeout, args.concurrency, lv))
        if not tcp:
            lv.fail("semua target timeout - cek koneksi internet kamu")
            sys.exit(1)
        lv.done(f"{len(tcp)}/{len(targets)} merespon")
    method, note = "TCP", ""
    tcp_fake = bool(core) and tcp_intercepted(list(tcp.values()))
    if tcp_fake:
        note = "ping TCP dicegat proxy/VPN lokal -> tahap TCP dilewati, semua node langsung di-URL-test"
        warn("Hampir semua ping TCP <=3ms: koneksi dicegat proxy/VPN lokal (Box / Nikki / VPN aktif?). "
             "Hasil TCP diabaikan; sebaiknya matikan Box/VPN saat menjalankan sub2yaml agar tes mihomo akurat.")

    rnd = random.Random()
    queues, jobs, jmap, base = {}, {}, {}, {}
    for prof in profs:
        pf = args.prefilter if prof["key"] == "free" else args.custom_prefilter
        alive = []
        for i, r in enumerate(prof["recs"]):
            if r["status"] is not None:
                continue
            ms = tcp.get((r["proxy"]["server"], r["proxy"]["port"]))
            if ms is None and not tcp_fake:
                r.update(status="fail", reason="tcp_dead")
                continue
            r["tcp"] = ms
            alive.append(i)
        if tcp_fake:
            rnd.shuffle(alive)  # urutan TCP palsu tidak berarti; acak supaya batch tidak bias
        else:
            alive.sort(key=lambda i: prof["recs"][i]["tcp"])
        cand = alive[:pf] if pf else alive
        for i in alive[len(cand):]:
            prof["recs"][i].update(status="fail", reason="not_tested", detail="di luar batas --prefilter")
        q = deque()
        for i in cand:
            gid = len(jobs)
            jobs[gid], jmap[gid], base[gid] = prof["recs"][i]["proxy"], (prof, i), i
            q.append(gid)
        queues[prof["key"]] = q

    # --- tahap 2: URL-test mihomo per batch. Berhenti begitu tiap profil punya cukup node yang LOLOS
    #     (free = --top, custom = --custom-top; 0 = uji semuanya).
    done_real = False
    if core:
        method = "URL-test mihomo" + ("" if args.no_verify else " (2 kali, URL berbeda)")
        verify_url = None if args.no_verify else args.verify_url
        want = {p["key"]: ((top if p["key"] == "free" else args.custom_top) or None) for p in profs}
        okc = {p["key"]: 0 for p in profs}
        total, cnt, bad_chunks = len(jobs), [0, 0], 0  # cnt = [selesai diuji, lolos]

        def tick(good):
            cnt[0] += 1
            cnt[1] += 1 if good else 0
            lv.set(msg=f"URL test mihomo  {cnt[1]} lolos", done=cnt[0])

        with Live("URL test mihomo", total=total) as lv:
            while True:
                chunk, ck = {}, {}
                for prof in profs:
                    k, q = prof["key"], queues[prof["key"]]
                    if q and (want[k] is None or okc[k] < want[k]):
                        for _ in range(min(args.batch, len(q))):
                            gid = q.popleft()
                            chunk[gid], ck[gid] = jobs[gid], base[gid]
                if not chunk:
                    break
                ok_, fails, rej, last_err = None, {}, {}, None
                for _try in range(2):  # satu batch gagal (mihomo mati/timeout) -> ulangi sekali, jangan hentikan semua
                    try:
                        ok_, fails, rej = mihomo_delays(core, chunk, args.test_url, args.test_timeout, args.workers,
                                                        ck, None, verify_url, args.max_ping, tick)
                        break
                    except Exception as e:
                        last_err = e
                if ok_ is None:
                    bad_chunks += 1
                    if not cnt[1] and bad_chunks >= 3:
                        lv.fail(str(last_err)[:120])
                        err("URL-test mihomo gagal berulang -> tes dihentikan (tidak jatuh ke TCP-only karena hasilnya menyesatkan).")
                        sys.exit(2)
                    note = (note + "; " if note else "") + f"1 batch dilewati karena mihomo error: {str(last_err)[:80]}"
                    ok_, fails, rej = {}, {g: ("urltest", f"mihomo error: {str(last_err)[:60]}") for g in chunk}, {}
                    cnt[0] += len(chunk)
                cnt[0] += len(rej)  # node yang ditolak validator mihomo tidak melewati tick()
                for gid in chunk:
                    prof, i = jmap[gid]
                    r = prof["recs"][i]
                    if gid in ok_:
                        r.update(status="ok", ms=ok_[gid])
                        okc[prof["key"]] += 1
                    elif gid in rej:
                        r.update(status="fail", reason="rejected", detail=rej[gid])
                    else:
                        kind, msg = fails.get(gid, ("urltest", ""))
                        r.update(status="fail", reason=kind, detail=msg)
            lv.set(msg="URL test mihomo")
            lv.done(f"{cnt[1]} lolos dari {cnt[0]} node yang diuji")
        done_real = True
        for prof in profs:  # sisa antrean = target jumlah sudah tercapai
            for gid in queues[prof["key"]]:
                p2, i = jmap[gid]
                p2["recs"][i].update(status="fail", reason="not_tested", detail=(
                    f"target {want[prof['key']]} node sudah tercapai" if want[prof["key"]] and okc[prof["key"]] >= want[prof["key"]]
                    else "tes terhenti sebelum sempat diuji"))
        if not cnt[1]:
            warn("Tidak ada satu pun node lolos URL-test. Cek internet; matikan Box/VPN/proxy lain yang aktif; "
                 "atau naikkan --test-timeout.")
    else:
        for gid, (prof, i) in jmap.items():
            prof["recs"][i].update(status="ok", ms=prof["recs"][i]["tcp"])
        note = (note + "; " if note else "") + "TCP-only: 'berhasil' hanya berarti port terbuka, BUKAN jaminan node bisa dipakai"

    # --- pilih, urutkan, tulis file per profil
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    written = []
    with Live("Menulis file YAML") as lv:
        for prof in profs:
            recs = prof["recs"]
            ok_idx = sorted((i for i, r in enumerate(recs) if r["status"] == "ok"), key=lambda i: recs[i]["ms"])
            lim = top if prof["key"] == "free" else args.custom_top
            chosen = ok_idx[:lim] if lim else ok_idx
            out, counts, names = build_output([r["proxy"] for r in recs], chosen,
                                              {i: recs[i]["ms"] for i in chosen}, args.sort, ccs, prof["tag"])
            for i in chosen:
                recs[i]["final"] = names[i]  # nama persis seperti di file YAML
            prof.update(chosen=chosen, counts=counts, written=None, report_ok=(
                sorted(ok_idx, key=lambda i: (recs[i]["cc"] == "XX", recs[i]["cc"], recs[i]["ms"]))
                if args.sort == "country" else ok_idx))
            if out:
                summary = ", ".join(f"{flag(cc)}{cc if cc != 'XX' else '?'} {n}"
                                    for cc, n in sorted(counts.items(), key=lambda t: (t[0] == "XX", t[0])))
                header = (f"# Dibuat oleh sub2yaml.py - {stamp}\n"
                          f"# Profil: {prof['title']} | {len(out)} node lolos (tes: {method}, urut: {args.sort})\n"
                          f"# Custom config: {ov_describe(prof['ov']) if prof['ov'] else '(tidak ada)'}\n"
                          f"# Negara: {summary}\n")
                path = os.path.join(outdir, prof["file"])
                write_yaml_file(path, out, header)
                prof["written"] = path
                written.append((prof, len(out)))
            if args.save_failed:
                failed = [r["proxy"] for r in recs if r["status"] == "fail"]
                if failed:
                    write_yaml_file(os.path.join(outdir, f"failed-{prof['key']}.yaml"), failed,
                                    f"# Node GAGAL ({len(failed)}) - profil {prof['title']}\n")
        lv.done(f"{len(written)} file")

    ctx = {"profiles": profs, "sources": [src_label(x) for x in sources], "method": method, "note": note,
           "sort": args.sort, "outdir": rel(outdir), "n_links": len(links), "n_nodes": len(nodes),
           "stats": st, "skipped": skipped}
    report_path = (os.path.join(outdir, "report.txt") if args.report is None else args.report)
    if report_path:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines(ctx, full=True)) + "\n")

    # --- ringkasan di layar
    print()
    print("\n".join(paint(ln) for ln in report_lines(ctx, full=False, cap=None if args.verbose else 15)))
    print(sep(78))
    section("HASIL")
    for prof in profs:
        if prof["written"]:
            ms = [prof["recs"][i]["ms"] for i in prof["chosen"]]
            ok(f"{rel(prof['written']):<34} {C.BOLD}{len(prof['chosen']):>4}{C.RESET} node  "
               f"{C.DIM}(min {min(ms)}ms, median {int(statistics.median(ms))}ms, max {max(ms)}ms){C.RESET}")
        else:
            old = os.path.join(outdir, prof["file"])
            err(f"{prof['file']:<34} tidak ada node yang berhasil"
                + ("  (file lama TIDAK diubah)" if os.path.exists(old) else ""))
    if report_path:
        info(f"Laporan lengkap (semua node, semua profil) ➜ {rel(report_path)}")
    free = profs[0]
    if free["written"] and top and len(free["chosen"]) < top:
        left = sum(1 for r in free["recs"] if r["reason"] == "not_tested")
        warn(f"Hanya {len(free['chosen'])} node yang lolos dari target {top}. "
             + (f"{left} node belum sempat diuji (lihat 'Metode tes' di report.txt untuk alasannya); jalankan ulang. "
                if left else "Sumber sudah habis diuji; ")
             + "Tambah sumber (menu [3]), update source (menu [8]), atau coba lagi nanti.")
    if free["written"] and not os.environ.get("HIKARI_PARENT"):  # dari Hikari, langkah impornya muncul otomatis
        info("Pasang ke Hikari /.CLASH: menu 1 ➜ 4 (Free node), atau salin free.yaml ke folder proxy platform.")
    print()
    if not written:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _show_cursor()
        print(f"\n\n  {C.RED}Program dihentikan.{C.RESET}\n")
        sys.exit(0)
