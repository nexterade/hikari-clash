#!/usr/bin/env python3
"""
HIKARI /.CLASH — CONVERTER  v3
URI <-> Clash (Mihomo) converter + generator config untuk Box / Nikki / OpenClash.
(sebelumnya "Hikari Subclash" / Hikari-SC)
"""

import base64
import copy
import glob
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import subprocess
import sys
import time
import unicodedata
from urllib.parse import parse_qs, quote, unquote, urlsplit

from banner import banner as _show_banner

try:
    import yaml
except ImportError:
    print("[!] PyYAML belum terpasang. Jalankan: pip install pyyaml")
    sys.exit(1)

# ---------- PATH CONFIG (semua relatif ke lokasi script, bukan cwd) ----------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:          # supaya banner.py / mrs_codec.py / nodetest.py / routetest.py ketemu
    sys.path.insert(0, SCRIPT_DIR)

BASE_DIR = os.path.join(SCRIPT_DIR, "hasil")
RULESET_SOURCE = os.path.join(SCRIPT_DIR, "ruleset")
SUBSCRIPTION_SOURCE = os.path.join(SCRIPT_DIR, "subscription.yaml")   # node gratis (template v1.0+): dipakai sebagai cache awal subs.yaml
SEED_FILES = {"subs.yaml": SUBSCRIPTION_SOURCE}                      # file provider yang disemai dari repo saat generate
FREE_NODE_FILE = "free.yaml"                                         # provider "📄 Free" (group ☘️ FREE NODE) — diisi sub2yaml
SUB2YAML_SCRIPT = os.path.join(SCRIPT_DIR, "sub2yaml.py")            # dijalankan interaktif dari menu 1 → 4
SUB2YAML_OUT_DIR = os.path.join(BASE_DIR, "proxy")                   # keluaran sub2yaml: hasil/proxy/free.yaml (+ custom-*.yaml, report.txt)
USER_NODE_FILES = ("active.yaml", "trial.yaml")                      # file node milik pengguna; free.yaml/subs.yaml bukan sumber regenerate
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "template")
TEMPLATE_PATH = os.path.join(TEMPLATE_DIR, "template.yaml")  # working copy (boleh diedit lewat menu)
TEMPLATE_GLOB = "config_v*.yaml"                             # master di template/; dipakai kalau template.yaml belum ada
SNIFFER_TEMPLATE = os.path.join(TEMPLATE_DIR, "sniffer_only.yaml")   # config pengintai: tanpa node, semua DIRECT (menu Misc > Sniffer Only)
BUGTEST_DIR = os.path.join(BASE_DIR, "bugtest")                     # hasil Uji Bug: hasil/bugtest/<tanggal_jam>/custom-*.yaml + report.txt
SNIFFER_OUT_DIR = os.path.join(BASE_DIR, "sniffer")                 # hasil/sniffer/<platform>/config.yaml + cache CIDR CDN
SNIFFER_ASN_URL = "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb"

# node dari link biasanya pakai bug-host/SNI custom -> cert tidak cocok.
# Kalau link eksplisit bilang allowInsecure=0 maka dihormati — KECUALI node memakai SNI custom
# (servername beda dari server & host): di kasus itu tetap dipaksa true (lihat fix_skip_verify).
DEFAULT_SKIP_CERT_VERIFY = True

EMOJI_PATH = os.path.join(SCRIPT_DIR, "emoji.json")        # daftar emoji nama node (bisa diedit lewat menu)
# Emoji nama node mengikuti METODE node (bukan acak). Bawaan = isi emoji.json bawaan repo
# (dipakai kalau file hilang / rusak / di-Reset lewat menu). Catatan: 🐬 juga dipakai nama group "🐬 HIJACK" di template
# (hanya mirip secara visual; nama lengkap node tetap beda).
DEFAULT_EMOJI_MAP = {
    "original":     "🌠",   # node asli tanpa custom
    "cloudfront":   "🌌",   # node asli CloudFront tanpa custom
    "bug-sni":      "🎬",
    "bug-addr":     "💭",
    "ip-edge":      "🐬",
    "sni-ip":       "☕",
    "bug-addr-sni": "🏞️",
    "ip-bug-sni":   "🏖️",
    "wildcard":     "🏙️",
    "wildcard-sni": "🌇",
    "host-bug":     "🌁",
    "host-bug-sni": "🪲",
    "ganti-path":   "🧸",
}
EMOJI_METHOD_LABEL = {
    "original": "node asli, tanpa custom", "cloudfront": "node asli CloudFront, tanpa custom",
    "bug-sni": "SNI = bug", "bug-addr": "Address = bug", "ip-edge": "Address = IP edge CDN",
    "sni-ip": "SNI = IP", "bug-addr-sni": "Address + SNI = bug", "ip-bug-sni": "IP edge + SNI = bug",
    "wildcard": "Host/SNI = <bug>.<server>", "wildcard-sni": "wildcard + varian IP edge",
    "host-bug": "Host = bug", "host-bug-sni": "Host + SNI = bug", "ganti-path": "path diganti awalan bug",
}
DEFAULT_EMOJIS = list(DEFAULT_EMOJI_MAP.values())          # daftar datar (kompatibilitas / tes)
# Metode Lazy (bugtest.py) yang namanya tidak ada di daftar emoji dipetakan ke kunci terdekat.
EMOJI_METHOD_ALIAS = {
    "host-ip": "sni-ip", "wildcard-ip": "wildcard-sni",
    "http-direct": "original", "http-bug-addr": "bug-addr", "http-ip-edge": "ip-edge", "http-host-ip": "sni-ip",
    "http-wildcard": "wildcard", "http-wildcard-ip": "wildcard-sni", "http-host-bug": "host-bug",
    "path-bug-addr": "ganti-path", "path-bug-addr-sni": "ganti-path", "path-host-bug": "ganti-path",
    "path-host-bug-sni": "ganti-path", "http-path-bug-addr": "ganti-path", "http-path-host-bug": "ganti-path",
    # tag uji per-field (Uji Bug mode biasa): [sni:x] [host:x] [addr:x] [path:x] [phantom:x]
    "sni": "bug-sni", "host": "host-bug", "addr": "bug-addr", "path": "ganti-path", "phantom": "bug-sni",
}

NIKKI_RUN_DIR = "/etc/nikki/run"
WIFI_PROVIDER = "WifiClients"

PLATFORMS = {
    "box": {
        "label": "Box for Root (Android)", "out": "full_config_box",
        "proxy_dir": "proxy", "rule_dir": "ruleset", "prefix": "./",
    },
    "nikki": {
        "label": "Nikki (OpenWrt)", "out": "full_config_nikki",
        "proxy_dir": "proxy", "rule_dir": "ruleset", "prefix": NIKKI_RUN_DIR + "/",
    },
    "openclash": {
        "label": "OpenClash (OpenWrt)", "out": "full_config_openclash",
        "proxy_dir": "proxy_provider", "rule_dir": "rule_provider", "prefix": "./",
    },
}

# Port & key khusus Box for Root (diambil dari template v0.1 varian BFR)
BOX_TOP_LEVEL = {
    "mixed-port": 7890, "port": 7891, "socks-port": 7892,
    "redir-port": 9797, "tproxy-port": 9898,
    "external-controller": "127.0.0.1:9090",   # Android: jangan buka ke LAN
    "find-process-mode": "always",              # dashboard > Connections nampilin package app
    "geodata-mode": True,
    "experimental": {"quic-go-disable-gso": True},
    "external-ui": "./dashboard",               # folder dashboard dibawa modul Box (bukan bagian repo ini)
}
BOX_DNS_LISTEN = "0.0.0.0:1053"                 # Box tproxy ngarahin DNS ke port ini
BOX_TUN = {                                     # TUN dikelola Box (settings.ini) -> default off
    "enable": False, "mtu": 9000, "device": "meta", "stack": "mixed",
    "dns-hijack": ["any:53", "tcp://any:53"],
    "auto-route": True, "strict-route": True, "auto-redirect": True,
    "auto-detect-interface": True,
    "include-android-user": [0, 10, 999], "exclude-package": [], "include-package": [],
}


# ---------- Pengaturan pengguna (settings.json, dibuat saat dibutuhkan) ----------
SETTINGS_PATH = os.path.join(SCRIPT_DIR, "settings.json")

# Profil ISP: DNS milik ISP yang HARUS ada supaya tunneling jalan di jaringan tertentu.
# XL Axiata: 112.215.203.254 (dulu ada di default-nameserver & fallback template v0.2).
ISP_PROFILES = {
    "none": {"label": "Umum (tanpa DNS ISP)", "ips": [], "fields": []},
    "xl":   {"label": "XL Axiata", "ips": ["112.215.203.254"],
             "fields": ["default-nameserver", "proxy-server-nameserver"]},
}
ISP_FIELD_CHOICES = ["default-nameserver", "proxy-server-nameserver", "direct-nameserver", "fallback"]
ISP_PLATFORMS = ("nikki", "openclash")      # profil ISP hanya disuntik ke platform ini

# Operator/ISP: menentukan nama file config (<operator>.yaml) dan folder provider (proxy/<operator>/).
OPERATORS = {"xl": "XL", "axis": "Axis", "smartfren": "Smartfren", "telkomsel": "Telkomsel",
             "byu": "by.U", "indosat": "Indosat", "three": "Three"}
OPERATOR_ISP = {"xl": "xl"}                 # operator -> profil DNS ISP (ISP_PROFILES); lainnya = "none"


def safe_name(raw):
    """Nama aman untuk file/folder: huruf kecil, spasi -> '-', hanya a-z 0-9 . _ -. Kosong kalau tidak ada yang tersisa."""
    s = re.sub(r"\s+", "-", str(raw or "").strip().lower())
    s = re.sub(r"[^a-z0-9._-]", "", s).strip(".-_")
    return s[:40]


def config_filename(operator=None):
    return f"{operator}.yaml" if operator else "config.yaml"


def isp_for_operator(operator):
    return OPERATOR_ISP.get(operator or "", "none")


def load_settings():
    """{'isp': id, 'isp_fields': [...]} dari settings.json; nilai tidak valid -> default."""
    cfg = {"isp": "none", "isp_fields": [], "operator": ""}
    try:
        data = json.loads(read_text(SETTINGS_PATH))
    except (OSError, ValueError):
        return cfg
    if isinstance(data, dict):
        if data.get("isp") in ISP_PROFILES:
            cfg["isp"] = data["isp"]
        fl = data.get("isp_fields")
        if isinstance(fl, list):
            cfg["isp_fields"] = [f for f in fl if f in ISP_FIELD_CHOICES]
        if isinstance(data.get("operator"), str):
            cfg["operator"] = safe_name(data["operator"])      # operator terakhir yang dipakai saat generate
    return cfg


def save_settings(cfg):
    """Tulis settings.json; kunci lain yang sudah ada (mis. "info" milik sysinfo.py) dipertahankan."""
    data = {}
    try:
        data = json.loads(read_text(SETTINGS_PATH))
    except (OSError, ValueError):
        pass
    if not isinstance(data, dict):
        data = {}
    data.update(cfg)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def isp_fields_for(pid):
    st = load_settings()
    if st["isp"] == pid and st["isp_fields"]:
        return st["isp_fields"]
    return list(ISP_PROFILES[pid]["fields"])


# ---------- ANSI / Style ----------
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


def clear_screen():
    if sys.stdout.isatty():
        os.system('cls' if os.name == 'nt' else 'clear')


def sep(width=50, color=None):
    return (color or C.GRAY) + "─" * width + C.RESET


def section(title, width=50):
    t = f" {title} "; pad = max(0, width - len(t)); left = pad // 2; right = pad - left
    print(C.GRAY + "─" * left + C.RESET + C.BOLD + C.WHITE + t + C.RESET + C.GRAY + "─" * right + C.RESET)


def banner(mode="CONVERTER", info="compact"):
    """Banner Hikari /.CLASH (definisi visual ada di banner.py) + info pengguna di bawahnya (sysinfo.py).
    info: "full" (menu utama) / "compact" (satu baris, layar lain) / None. Pengaturan pengguna jadi batas atas."""
    _show_banner(mode=mode, info=info)
    print()


def spinner(msg, duration=0.6):
    if not sys.stdout.isatty():
        return
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]; end = time.time() + duration; i = 0
    while time.time() < end:
        sys.stdout.write(f"\r{C.CYAN}{frames[i % len(frames)]}{C.RESET} {msg}"); sys.stdout.flush(); time.sleep(0.05); i += 1
    sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r"); sys.stdout.flush()


def truncate(text, length):
    return text if len(text) <= length else text[:length - 3] + "..."


def ask(prompt):
    """input() yang aman: EOF (Ctrl+D / stdin habis) = keluar bersih, bukan loop tak berujung."""
    try:
        return input(prompt)
    except EOFError:
        print()
        raise SystemExit(0)


def ask_choice(prompt, valid, default=None, cancel=()):
    """Tanya sampai jawabannya salah satu dari `valid` (tanpa beda huruf besar/kecil). Enter = `default` kalau ada.
    Jawaban asal TIDAK diproses diam-diam: tampil pesan dan ditanya lagi. `cancel` = jawaban yang dikembalikan apa adanya.
    Return jawaban (huruf kecil)."""
    ok_set = {str(v).lower() for v in valid}
    stop = {str(v).lower() for v in cancel}
    while True:
        raw = ask(prompt).strip().lower()
        if not raw and default is not None:
            return str(default).lower()
        if raw in ok_set or raw in stop:
            return raw
        err(f"Pilihan '{truncate(raw, 20)}' tidak valid. Pilih: " + ", ".join(sorted(ok_set | stop)) + ("" if default is None else " (atau Enter)") + ".")


def ask_yn(prompt, default=False):
    """Ya/tidak. Enter = default; jawaban selain y/ya/n/tidak ditolak dan ditanya ulang. Return bool."""
    while True:
        raw = ask(prompt).strip().lower()
        if not raw:
            return default
        if raw in ("y", "ya", "yes"):
            return True
        if raw in ("n", "t", "tidak", "no"):
            return False
        err(f"'{truncate(raw, 20)}' bukan jawaban y/n.")


def pause(msg="Tekan Enter untuk kembali..."):
    ask(f"\n{C.DIM}{msg}{C.RESET}")


def ok(msg):   print(f"{C.GREEN}✓{C.RESET} {msg}")
def err(msg):  print(f"{C.RED}✗ {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}! {msg}{C.RESET}")


# =====================================================================
#  Parser URI -> node Clash
# =====================================================================
def _qs(query):
    return {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}


def _flag(value, default):
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def sni_is_custom(node):
    """True kalau node TLS memakai SNI "bug" (servername beda dari server DAN dari header Host/host ws/h2).
    Sertifikat server hampir pasti tidak cocok dengan SNI seperti itu."""
    if not isinstance(node, dict) or not (node.get("tls") or node.get("type") == "trojan"):
        return False
    sni = str(node.get("servername") or node.get("sni") or "").strip().lower()
    if not sni:
        return False
    names = {str(node.get("server") or "").strip().lower()}
    ws = (node.get("ws-opts") or {}).get("headers") or {}
    names.add(str(ws.get("Host") or ws.get("host") or "").strip().lower())
    names.add(str((node.get("httpupgrade-opts") or {}).get("host") or "").strip().lower())
    h2 = (node.get("h2-opts") or {}).get("host")
    if isinstance(h2, list):
        names.update(str(x).strip().lower() for x in h2)
    elif h2:
        names.add(str(h2).strip().lower())
    names.discard("")
    return sni not in names


def fix_skip_verify(node):
    """Paksa skip-cert-verify: true untuk node dengan SNI custom (lihat sni_is_custom), walau link/YAML
    bilang false atau allowInsecure=0 — kalau tidak, handshake TLS gagal dan node cuma timeout.
    Return True kalau ada yang diubah. Node dengan SNI = host/server tetap dihormati (verifikasi normal)."""
    if isinstance(node, dict) and not node.get("skip-cert-verify") and sni_is_custom(node):
        node["skip-cert-verify"] = True
        return True
    return False


def _userinfo(p):
    return unquote(p.netloc.rpartition("@")[0])


def _host_port(p, default_port=443):
    try:
        port = p.port
    except ValueError:
        raise ValueError("port tidak valid")
    if not p.hostname:
        raise ValueError("server kosong")
    return p.hostname, int(port or default_port)


def _alpn(value):
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def _apply_transport(node, net, path, host_hdr, service_name=""):
    """Isi network + opts transport. Transport yang belum didukung -> error jelas (bukan node rusak diam-diam)."""
    net = (net or "tcp").lower()
    if net in ("tcp", "raw", ""):
        node["network"] = "tcp"
    elif net == "ws":
        node["network"] = "ws"
        opts = {"path": path or "/"}
        if host_hdr:
            opts["headers"] = {"Host": host_hdr}
        node["ws-opts"] = opts
    elif net == "httpupgrade":
        node["network"] = "ws"
        opts = {"path": path or "/", "v2ray-http-upgrade": True}
        if host_hdr:
            opts["headers"] = {"Host": host_hdr}
        node["ws-opts"] = opts
    elif net == "grpc":
        node["network"] = "grpc"
        node["grpc-opts"] = {"grpc-service-name": service_name or ""}
    elif net in ("h2", "http"):
        node["network"] = "h2"
        opts = {"path": path or "/"}
        if host_hdr:
            opts["host"] = [host_hdr]
        node["h2-opts"] = opts
    else:
        raise ValueError(f"transport '{net}' belum didukung")


def parse_vless(uri):
    p = urlsplit(uri); q = _qs(p.query)
    host, port = _host_port(p)
    uuid = _userinfo(p)
    if not uuid:
        raise ValueError("UUID kosong")
    sec = q.get("security", "none").lower()
    net = q.get("type", "tcp").lower()
    sni = q.get("sni") or q.get("peer") or q.get("host") or host
    tls = sec in ("tls", "reality")

    node = {"name": unquote(p.fragment).strip() or f"{host}:{port}", "type": "vless",
            "server": host, "port": port, "uuid": uuid, "udp": True, "tls": tls}
    if tls:
        node["servername"] = sni
        node["skip-cert-verify"] = _flag(q.get("allowInsecure") or q.get("insecure"), DEFAULT_SKIP_CERT_VERIFY)
        alpn = _alpn(q.get("alpn"))
        if alpn:
            node["alpn"] = alpn
    if q.get("flow"):
        node["flow"] = q["flow"]
    fp = q.get("fp")
    if fp or sec == "reality":
        node["client-fingerprint"] = fp or "chrome"
    if sec == "reality":
        if not q.get("pbk"):
            raise ValueError("reality tanpa public key (pbk)")
        node["reality-opts"] = {"public-key": q["pbk"], "short-id": q.get("sid", "")}
    _apply_transport(node, net, q.get("path", "/"), q.get("host") or (sni if net in ("ws", "httpupgrade") else ""),
                     q.get("serviceName", ""))
    fix_skip_verify(node)
    return node


def parse_vmess(uri):
    raw = uri[len("vmess://"):].strip().replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        d = json.loads(base64.b64decode(raw).decode("utf-8"))
    except Exception:
        raise ValueError("Base64/JSON vmess tidak valid")
    server = d.get("add")
    if not server:
        raise ValueError("server kosong")
    if not d.get("id"):
        raise ValueError("UUID kosong")
    try:
        port = int(d.get("port") or 443)
    except (TypeError, ValueError):
        raise ValueError("port tidak valid")
    net = str(d.get("net", "tcp") or "tcp").lower()
    tls = str(d.get("tls", "")).lower() in ("tls", "reality")
    sni = d.get("sni") or d.get("host") or server
    node = {"name": str(d.get("ps") or f"{server}:{port}").strip(), "type": "vmess",
            "server": server, "port": port, "uuid": d["id"],
            "alterId": int(d.get("aid", 0) or 0), "cipher": d.get("scy") or "auto",
            "udp": True, "tls": tls}
    if tls:
        node["servername"] = sni
        node["skip-cert-verify"] = DEFAULT_SKIP_CERT_VERIFY
        alpn = _alpn(d.get("alpn"))
        if alpn:
            node["alpn"] = alpn
        if d.get("fp"):
            node["client-fingerprint"] = d["fp"]
    path = d.get("path", "") or ""
    _apply_transport(node, net, path or "/", d.get("host") or (sni if net in ("ws", "httpupgrade", "h2") else ""),
                     path)
    fix_skip_verify(node)
    return node


def parse_trojan(uri):
    p = urlsplit(uri); q = _qs(p.query)
    host, port = _host_port(p)
    password = _userinfo(p)          # di-unquote: %40 -> @, dst
    if not password:
        raise ValueError("password kosong")
    net = q.get("type", "tcp").lower()
    sni = q.get("sni") or q.get("peer") or host
    node = {"name": unquote(p.fragment).strip() or f"{host}:{port}", "type": "trojan",
            "server": host, "port": port, "password": password, "sni": sni, "udp": True,
            "skip-cert-verify": _flag(q.get("allowInsecure") or q.get("insecure"), DEFAULT_SKIP_CERT_VERIFY)}
    alpn = _alpn(q.get("alpn"))
    if alpn:
        node["alpn"] = alpn
    if q.get("fp"):
        node["client-fingerprint"] = q["fp"]
    _apply_transport(node, net, q.get("path", "/"), q.get("host") or (sni if net in ("ws", "httpupgrade") else ""),
                     q.get("serviceName", ""))
    fix_skip_verify(node)
    return node


def convert_line(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith("vless://"):  return parse_vless(line)
    if line.startswith("vmess://"):  return parse_vmess(line)
    if line.startswith("trojan://"): return parse_trojan(line)
    raise ValueError("bukan vless/vmess/trojan")


EMOJI_WARNING = ""      # diisi load_emoji_cfg() kalau emoji.json bermasalah; ditampilkan di startup & Check Status


def load_emoji_cfg():
    """{'enabled': bool, 'methods': {kunci_metode: emoji}} dari emoji.json.
    File tidak ada -> default. JSON rusak -> coba perbaiki koma berlebih, kalau tetap gagal pakai default.
    Kunci yang hilang diisi default. Format lama ({"emojis": [...]}, acak) diabaikan dengan pesan di EMOJI_WARNING."""
    global EMOJI_WARNING
    EMOJI_WARNING = ""
    cfg = {"enabled": True, "methods": dict(DEFAULT_EMOJI_MAP)}
    try:
        text = read_text(EMOJI_PATH)
    except OSError:
        return cfg
    try:
        data = json.loads(text)
    except ValueError as e:
        try:
            data = json.loads(re.sub(r",(\s*[\]}])", r"\1", text))
            EMOJI_WARNING = f"emoji.json tidak valid ({e}); koma berlebih diabaikan — perbaiki filenya atau simpan ulang lewat menu"
        except ValueError:
            EMOJI_WARNING = f"emoji.json rusak ({e}); memakai emoji bawaan"
            return cfg
    if not isinstance(data, dict):
        EMOJI_WARNING = "emoji.json harus berupa objek {\"enabled\": ..., \"methods\": {...}}; memakai emoji bawaan"
        return cfg
    if isinstance(data.get("enabled"), bool):
        cfg["enabled"] = data["enabled"]
    methods = data.get("methods")
    if isinstance(methods, dict):
        for k, v in methods.items():
            if k in DEFAULT_EMOJI_MAP and isinstance(v, str) and v.strip():
                cfg["methods"][k] = v.strip()
    elif "emojis" in data:
        EMOJI_WARNING = "emoji.json format lama (daftar emoji acak) diabaikan; kini emoji mengikuti metode node — simpan ulang lewat Edit Configuration → Emoji Node"
    return cfg


def save_emoji_cfg(cfg):
    with open(EMOJI_PATH, "w", encoding="utf-8") as f:
        json.dump({"enabled": bool(cfg.get("enabled", True)), "methods": cfg.get("methods") or dict(DEFAULT_EMOJI_MAP)},
                  f, ensure_ascii=False, indent=2)
        f.write("\n")


def starts_with_emoji(name):
    """True kalau nama sudah diawali emoji/simbol (🪟, 🇸🇬, ⭐, ✅, ...), apa pun emojinya."""
    name = str(name).lstrip()
    if not name:
        return False
    ch = name[0]
    return 0x1F000 <= ord(ch) <= 0x1FAFF or unicodedata.category(ch) in ("So", "Sk")


def _node_domains(node):
    """Semua nama host yang terkait node: server, SNI, Host ws/h2/http."""
    out = [node.get("server"), node.get("servername"), node.get("sni")]
    ws = node.get("ws-opts") or {}
    out.append((ws.get("headers") or {}).get("Host") if isinstance(ws.get("headers"), dict) else None)
    h2 = node.get("h2-opts") or {}
    hh = h2.get("host")
    out += hh if isinstance(hh, list) else [hh]
    ho = node.get("http-opts") or {}
    hh = (ho.get("headers") or {}).get("Host") if isinstance(ho.get("headers"), dict) else None
    out += hh if isinstance(hh, list) else [hh]
    return [str(x).strip().lower() for x in out if x]


def is_cloudfront_node(node):
    """Node asli CloudFront: server/SNI/Host berakhiran .cloudfront.net, atau namanya menyebut 'cloudfront'."""
    if "cloudfront" in str(node.get("name", "")).lower():
        return True
    return any(d == "cloudfront.net" or d.endswith(".cloudfront.net") for d in _node_domains(node))


def node_method(node):
    """Kunci metode emoji sebuah node (kunci DEFAULT_EMOJI_MAP).
    Node hasil Uji Bug membawa tag di akhir nama: 'Nama [bug-sni:instagram.com:443]' (Lazy) atau '[sni:x]' (per field).
    Tag tak dikenal ([port:..], [alpn:..], [combo], teks bebas) = tetap node asli."""
    m = re.search(r"\[([^\[\]]+)\]\s*$", str(node.get("name", "")))
    if m:
        label, _, rest = m.group(1).partition(":")
        label = label.strip().lower()
        key = label if label in DEFAULT_EMOJI_MAP else EMOJI_METHOD_ALIAS.get(label)
        if key == "bug-addr" and label == "addr" and ip_literal(rest.split(":")[0]):
            key = "ip-edge"                      # [addr:13.35.1.58] = IP edge, bukan bug
        if key and key not in ("original", "cloudfront"):
            return key
    return "cloudfront" if is_cloudfront_node(node) else "original"


def ip_literal(text):
    try:
        ipaddress.ip_address(str(text).strip("[]"))
        return True
    except ValueError:
        return False


def apply_emoji(nodes, cfg=None):
    """Awali nama node dengan emoji sesuai metodenya: 'Singapore' -> '🌠 Singapore' (asli),
    'SG [bug-sni:x.com:443]' -> '🎬 SG [...]'. Nama yang SUDAH diawali emoji/simbol dibiarkan (tidak dobel)."""
    cfg = cfg or load_emoji_cfg()
    if not cfg["enabled"]:
        return 0
    count = 0
    for node in nodes:
        name = str(node["name"])
        if starts_with_emoji(name):
            continue
        emoji = cfg["methods"].get(node_method(node)) or DEFAULT_EMOJI_MAP["original"]
        node["name"] = f"{emoji} {name}"
        count += 1
    return count


def dedupe_names(nodes, taken=()):
    """Nama proxy harus unik. Duplikat jadi 'Nama (2)', 'Nama (3)', ..."""
    seen = set(taken)
    for n in nodes:
        base = n["name"]; name = base; i = 2
        while name in seen:
            name = f"{base} ({i})"; i += 1
        n["name"] = name; seen.add(name)
    return nodes


# =====================================================================
#  Parser node Clash -> URI
# =====================================================================
def _qv(s, safe="", encoding=None, errors=None):
    return quote(str(s), safe="")


def _query(params):
    return "&".join(f"{quote(str(k), safe='')}={_qv(v)}" for k, v in params.items())


def _fmt_host(server):
    server = str(server)
    return f"[{server}]" if ":" in server and not server.startswith("[") else server


def build_uri_from_proxy(p):
    t = str(p.get("type", "")).lower()
    name = str(p.get("name", "Node"))
    server = p.get("server", ""); port = p.get("port", 443)
    host_uri = _fmt_host(server)
    net = str(p.get("network", "tcp") or "tcp").lower()
    ws = p.get("ws-opts") or {}
    grpc = p.get("grpc-opts") or {}
    h2 = p.get("h2-opts") or {}
    if net == "ws" and ws.get("v2ray-http-upgrade"):
        net = "httpupgrade"
    host_hdr = (ws.get("headers") or {}).get("Host", "") or (h2.get("host") or [""])[0]
    path = ws.get("path") or h2.get("path") or ""
    alpn = ",".join(p["alpn"]) if isinstance(p.get("alpn"), list) else (p.get("alpn") or "")

    if t == "vmess":
        d = {"v": "2", "ps": name, "add": server, "port": str(port), "id": p.get("uuid", ""),
             "aid": str(p.get("alterId", 0)), "scy": p.get("cipher", "auto"), "net": net,
             "type": "none", "host": host_hdr, "path": path, "tls": "tls" if p.get("tls") else "",
             "sni": p.get("servername", "")}
        if net == "grpc":
            d["path"] = grpc.get("grpc-service-name", "")
        if alpn:
            d["alpn"] = alpn
        if p.get("client-fingerprint"):
            d["fp"] = p["client-fingerprint"]
        return "vmess://" + base64.b64encode(json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode()).decode()

    params = {}
    if t == "vless":
        params["encryption"] = "none"
        sec = "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")
        if sec != "none":
            params["security"] = sec
        if net != "tcp":
            params["type"] = net
        if p.get("flow"):
            params["flow"] = p["flow"]
        if p.get("servername"):
            params["sni"] = p["servername"]
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        if alpn:
            params["alpn"] = alpn
        if sec == "tls" and p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if net in ("ws", "httpupgrade", "h2"):
            if path:
                params["path"] = path
            if host_hdr:
                params["host"] = host_hdr
        elif net == "grpc" and grpc.get("grpc-service-name"):
            params["serviceName"] = grpc["grpc-service-name"]
        ro = p.get("reality-opts") or {}
        if ro.get("public-key"): params["pbk"] = ro["public-key"]
        if ro.get("short-id"):   params["sid"] = ro["short-id"]
        return f"vless://{quote(str(p.get('uuid', '')), safe='')}@{host_uri}:{port}?{_query(params)}#{quote(name, safe='')}"

    if t == "trojan":
        params["security"] = "tls"
        if p.get("sni"):
            params["sni"] = p["sni"]
        if net != "tcp":
            params["type"] = net
        if alpn:
            params["alpn"] = alpn
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        if p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if net in ("ws", "httpupgrade", "h2"):
            if path:
                params["path"] = path
            if host_hdr:
                params["host"] = host_hdr
        elif net == "grpc" and grpc.get("grpc-service-name"):
            params["serviceName"] = grpc["grpc-service-name"]
        return f"trojan://{quote(str(p.get('password', '')), safe='')}@{host_uri}:{port}?{_query(params)}#{quote(name, safe='')}"
    return None


# =====================================================================
#  Template: lokasi, baca, edit teks (komentar template dijaga)
# =====================================================================
def _ver_key(path):
    m = re.search(r"v(\d+(?:\.\d+)*)", os.path.basename(path))
    return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)


def list_master_templates():
    return sorted(glob.glob(os.path.join(TEMPLATE_DIR, TEMPLATE_GLOB)), key=_ver_key)


def find_template():
    """template/template.yaml (working copy) > template/config_vX.Y.yaml terbaru."""
    if os.path.isfile(TEMPLATE_PATH):
        return TEMPLATE_PATH
    masters = list_master_templates()
    return masters[-1] if masters else None


def ensure_working_template():
    """Edit selalu dilakukan di template/template.yaml; master template/config_v*.yaml dibiarkan utuh."""
    if os.path.isfile(TEMPLATE_PATH):
        return TEMPLATE_PATH
    src = find_template()
    if not src:
        return None
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    shutil.copyfile(src, TEMPLATE_PATH)
    return TEMPLATE_PATH


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def backup_file(path):
    try:
        shutil.copyfile(path, path + ".bak")
    except OSError:
        pass


def load_template_cfg(path=None):
    path = path or find_template()
    if not path:
        raise FileNotFoundError("template tidak ditemukan (template/template.yaml / template/config_v*.yaml)")
    cfg = yaml.safe_load(read_text(path))
    if not isinstance(cfg, dict):
        raise ValueError("template bukan YAML mapping")
    return cfg


def _template_secret():
    """Secret yang tertulis di template aktif ('hikari' secara default). '' kalau kosong / template tidak terbaca."""
    try:
        return str(load_template_cfg().get("secret") or "")
    except Exception:
        return ""


def reserved_names():
    try:
        cfg = load_template_cfg()
    except Exception:
        return set()
    names = {x.get("name") for x in (cfg.get("proxies") or []) if isinstance(x, dict)}
    names |= {x.get("name") for x in (cfg.get("proxy-groups") or []) if isinstance(x, dict)}
    return {n for n in names if n}


def set_top_scalar(content, key, value_text):
    """Ganti 'key: ...' level-atas (kolom 0). Return (content_baru, ditemukan)."""
    pat = re.compile(rf"^{re.escape(key)}:.*$", re.M)
    if not pat.search(content):
        return content, False
    return pat.sub(lambda m: f"{key}: {value_text}", content, count=1), True


def yaml_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def _block_bounds(lines, key):
    start = next((i for i, l in enumerate(lines) if re.match(rf"^{re.escape(key)}:\s*(#.*)?$", l)), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].strip() and lines[j][0] not in (" ", "\t"):
            end = j; break
    return start, end


def block_set_list(content, block, key, items):
    """Ganti daftar `key` di dalam blok level-atas `block` (mis. dns/nameserver). Format asli (indent) dijaga."""
    lines = content.split("\n")
    b = _block_bounds(lines, block)
    if not b:
        return content, False
    s, e = b
    for i in range(s + 1, e):
        m = re.match(rf"^(\s+){re.escape(key)}:\s*(\[.*\])?\s*(#.*)?$", lines[i])
        if not m:
            continue
        indent = m.group(1)
        j = i + 1
        if not m.group(2):
            while j < e and re.match(r"^\s*-\s", lines[j]):
                j += 1
        lines[i:j] = [f"{indent}{key}:"] + [f"{indent}  - {_yaml_item(x)}" for x in items]
        return "\n".join(lines), True
    # key belum ada -> sisipkan di akhir blok
    last = e
    while last > s + 1 and not lines[last - 1].strip():
        last -= 1
    child_indent = next((re.match(r"^(\s+)\S", l).group(1) for l in lines[s + 1:e] if l.strip() and not l.strip().startswith("#")), "  ")
    lines[last:last] = [f"{child_indent}{key}:"] + [f"{child_indent}  - {_yaml_item(x)}" for x in items]
    return "\n".join(lines), True


# =====================================================================
#  Build config per platform (YAML dict -> patch -> dump)
# =====================================================================
class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def dump_yaml(data):
    return yaml.dump(data, Dumper=_Dumper, allow_unicode=True, sort_keys=False,
                     default_flow_style=False, width=4096, indent=2)


def _remap_path(path, platform, operator=None):
    """./proxy/x -> <prefix><proxy_dir>/x ; provider node pengguna (active/trial) masuk subfolder operator:
    ./proxy/active.yaml -> <prefix><proxy_dir>/<operator>/active.yaml (free/subs tetap bersama di proxy/)."""
    P = PLATFORMS[platform]
    if not isinstance(path, str):
        return path
    for old, folder in (("./proxy/", P["proxy_dir"]), ("./ruleset/", P["rule_dir"])):
        if path.startswith(old):
            rest = path[len(old):]
            if operator and folder == P["proxy_dir"] and rest in USER_NODE_FILES:
                rest = f"{operator}/{rest}"
            return f'{P["prefix"]}{folder}/{rest}'
    return path


def _drop_wifi(cfg):
    """Di OpenWrt semua client LAN punya IP sumber 192.168.x.x -> rule WifiClients bakal menangkap SEMUA trafik."""
    dropped_groups = set()
    rules = []
    for r in cfg.get("rules") or []:
        parts = [x.strip() for x in str(r).split(",")]
        if len(parts) >= 3 and parts[0] == "RULE-SET" and parts[1] == WIFI_PROVIDER:
            dropped_groups.add(parts[2]); continue
        rules.append(r)
    cfg["rules"] = rules
    (cfg.get("rule-providers") or {}).pop(WIFI_PROVIDER, None)
    groups = []
    for g in cfg.get("proxy-groups") or []:
        if g.get("name") in dropped_groups:
            continue
        if isinstance(g.get("proxies"), list):
            g["proxies"] = [x for x in g["proxies"] if x not in dropped_groups]
        groups.append(g)
    cfg["proxy-groups"] = groups
    return bool(dropped_groups)


def build_config(tpl_text, platform, provider_mode="template", secret_mode="template", isp=None, operator=None):
    """Return (cfg_dict, notes). provider_mode: 'template' | 'offline' (http -> file lokal). secret_mode: 'template' (apa adanya, boleh kosong) | 'random'."""
    cfg = yaml.safe_load(tpl_text)
    if not isinstance(cfg, dict):
        raise ValueError("template bukan YAML mapping")
    cfg = copy.deepcopy(cfg)
    notes = []

    if platform == "box":
        cfg.update(copy.deepcopy(BOX_TOP_LEVEL))
        if isinstance(cfg.get("dns"), dict):
            cfg["dns"]["listen"] = BOX_DNS_LISTEN
        cfg["tun"] = copy.deepcopy(BOX_TUN)
        notes.append("Box: port 9797/9898, dns 1053, blok tun (off), find-process-mode disuntik")
    else:
        if cfg.pop("tun", None) is not None:
            notes.append("tun dihapus dari profile (dikelola Nikki/OpenClash)")
        cfg.pop("find-process-mode", None)
        stale = [k for k in ("geodata-mode", "experimental", "external-ui") if cfg.pop(k, None) is not None]
        if stale:
            notes.append(f"key khusus Box dibuang dari template ({', '.join(stale)}) — template.yaml kerjamu kemungkinan turunan v0.3")
        cfg["external-controller"] = "0.0.0.0:9090"
        if _drop_wifi(cfg):
            notes.append("rule/group/provider WIFI dibuang (SRC-IP 192.168/16 menangkap semua client LAN di OpenWrt)")

    for sect in ("proxy-providers", "rule-providers"):
        for prov in (cfg.get(sect) or {}).values():
            if isinstance(prov, dict) and "path" in prov:
                prov["path"] = _remap_path(prov["path"], platform, operator if sect == "proxy-providers" else None)

    if provider_mode == "offline":
        n = 0
        for prov in (cfg.get("rule-providers") or {}).values():
            if prov.get("type") == "http":
                prov["type"] = "file"
                for k in ("url", "interval", "proxy"):
                    prov.pop(k, None)
                n += 1
        notes.append(f"mode offline: {n} rule-provider http -> file (tanpa update otomatis)")
        m = 0
        for prov in (cfg.get("proxy-providers") or {}).values():
            if isinstance(prov, dict) and prov.get("type") == "http":
                prov["type"] = "file"
                for k in ("url", "interval", "proxy"):
                    prov.pop(k, None)
                m += 1
        if m:
            notes.append(f"mode offline: {m} proxy-provider http -> file (node gratis tidak di-update otomatis; isi dari subscription.yaml)")

    if secret_mode == "random":
        cfg["secret"] = secrets.token_urlsafe(9)
        notes.append("secret dashboard dibuat acak")

    isp = isp or load_settings()["isp"]
    if platform in ISP_PLATFORMS and isp != "none":
        notes += apply_isp_profile(cfg, isp)
    return cfg, notes


def apply_isp_profile(cfg, pid):
    """Tambahkan DNS ISP (mis. XL 112.215.203.254) ke field dns terpilih. Return list catatan."""
    prof, notes = ISP_PROFILES[pid], []
    dns = cfg.get("dns")
    if not isinstance(dns, dict) or not prof["ips"]:
        return notes
    done = []
    for field in isp_fields_for(pid):
        if field == "fallback" and not dns.get("fallback"):
            notes.append("profil ISP: fallback tidak ada di template, dilewati")
            continue
        cur = [str(x) for x in (dns.get(field) or [])]
        add = [ip for ip in prof["ips"] if ip not in cur]
        if add:
            dns[field] = cur + add
        done.append(field)
    if done:
        notes.append(f"profil ISP {prof['label']}: {', '.join(prof['ips'])} ditambahkan ke dns.{', dns.'.join(done)}")
    return notes


def render_config(cfg, platform, version_hint=""):
    P = PLATFORMS[platform]
    header = (
        "# =====================================================\n"
        f"# HIKARI /.CLASH — config untuk {P['label']}\n"
        f"# Dibuat : {time.strftime('%Y-%m-%d %H:%M:%S')} oleh hikari_converter.py {version_hint}\n"
        "# File ini hasil generate: edit template-nya, lalu generate ulang.\n"
        "# =====================================================\n\n"
    )
    body = dump_yaml(cfg)
    out, first = [], True
    for line in body.split("\n"):          # baris kosong antar section biar enak dibaca
        if re.match(r"^[A-Za-z0-9_-]+:\s*$", line):    # hanya section berblok (dns:, rules:, ...)
            if not first:
                out.append("")
            first = False
        out.append(line)
    return header + "\n".join(out)


# =====================================================================
#  Validator (audit otomatis)
# =====================================================================
BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
GROUP_PROXY_TYPES = {"select", "url-test", "fallback", "load-balance", "relay"}   # tipe proxy-group Mihomo


def _port_of(addr):
    m = re.search(r":(\d+)$", str(addr or ""))
    return int(m.group(1)) if m else None


def validate_config(cfg, platform, out_dir=None):
    """Return list[(level, msg)] level: 'ERR' | 'WARN'."""
    issues = []
    E = lambda m: issues.append(("ERR", m))
    W = lambda m: issues.append(("WARN", m))
    P = PLATFORMS[platform]

    builtin = [x.get("name") for x in cfg.get("proxies") or [] if isinstance(x, dict)]
    groups = [g.get("name") for g in cfg.get("proxy-groups") or []]
    allnames = builtin + groups
    for n in {x for x in allnames if allnames.count(x) > 1}:
        E(f"nama proxy/group duplikat: {n}")
    valid_targets = set(allnames) | BUILTIN_TARGETS
    pproviders = cfg.get("proxy-providers") or {}
    rproviders = cfg.get("rule-providers") or {}

    # tipe grup tidak boleh ada di blok proxies: (itu daftar node), mis. url-test yang salah tempat
    for x in cfg.get("proxies") or []:
        if isinstance(x, dict) and x.get("type") in GROUP_PROXY_TYPES:
            E(f"'{x.get('name')}' bertipe grup ({x['type']}) tapi ada di blok proxies: — pindahkan ke proxy-groups")

    for g in cfg.get("proxy-groups") or []:
        for x in g.get("proxies") or []:
            if x in pproviders:
                E(f"group '{g['name']}' menaruh proxy-provider '{x}' di proxies: — provider hanya boleh di use:")
            elif x not in valid_targets:
                E(f"group '{g['name']}' mengacu ke '{x}' yang tidak ada")
        for u in g.get("use") or []:
            if u in groups:
                E(f"group '{g['name']}' memakai proxy-group '{u}' di use: — grup hanya boleh di proxies:")
            elif u not in pproviders:
                E(f"group '{g['name']}' memakai proxy-provider '{u}' yang tidak ada")
        if not g.get("proxies") and not g.get("use"):
            E(f"group '{g['name']}' kosong (tanpa proxies/use)")

    for r in cfg.get("rules") or []:
        parts = [x.strip() for x in str(r).split(",")]
        if parts[0] == "MATCH":
            target = parts[1] if len(parts) > 1 else ""
        elif parts[0] in ("AND", "OR", "NOT", "SUB-RULE"):
            continue
        else:
            target = parts[2] if len(parts) > 2 else ""
            if parts[0] == "RULE-SET" and len(parts) > 1 and parts[1] not in rproviders:
                E(f"rule mengacu ke rule-provider '{parts[1]}' yang tidak ada: {r}")
        if target and target not in valid_targets:
            E(f"rule menuju '{target}' yang tidak ada: {r}")
    if not (cfg.get("rules") or [""])[-1].startswith("MATCH"):
        W("rule terakhir bukan MATCH (traffic yang tidak cocok akan ke DIRECT)")

    def check_rs(items, where):
        for it in items or []:
            if isinstance(it, str) and it.startswith("rule-set:") and it[9:] not in rproviders:
                E(f"{where} mengacu ke rule-provider '{it[9:]}' yang tidak ada")
    check_rs((cfg.get("sniffer") or {}).get("skip-domain"), "sniffer.skip-domain")
    check_rs((cfg.get("sniffer") or {}).get("force-domain"), "sniffer.force-domain")
    check_rs((cfg.get("dns") or {}).get("fake-ip-filter"), "dns.fake-ip-filter")

    for sect, d in (("proxy-provider", pproviders), ("rule-provider", rproviders)):
        for name, pv in d.items():
            tgt = pv.get("proxy") if isinstance(pv, dict) else None
            if tgt and tgt not in valid_targets:
                E(f"{sect} '{name}' memakai proxy '{tgt}' yang tidak ada")

    for name, pv in rproviders.items():
        t = pv.get("type")
        if t == "http" and not pv.get("url"):
            E(f"rule-provider '{name}' type http tanpa url")
        if pv.get("format") == "mrs" and pv.get("behavior") not in ("domain", "ipcidr"):
            E(f"rule-provider '{name}' format mrs hanya untuk behavior domain/ipcidr")
        if t in ("http", "file") and not pv.get("path"):
            E(f"rule-provider '{name}' tanpa path")
        if t == "http" and not pv.get("interval"):
            W(f"rule-provider '{name}' http tanpa interval (tidak pernah auto-update)")

    # port bentrok
    used = {}
    for k in ("port", "socks-port", "redir-port", "mixed-port", "tproxy-port"):
        if cfg.get(k):
            used.setdefault(cfg[k], []).append(k)
    for k, v in (("external-controller", cfg.get("external-controller")),
                 ("dns.listen", (cfg.get("dns") or {}).get("listen"))):
        pt = _port_of(v)
        if pt:
            used.setdefault(pt, []).append(k)
    for pt, ks in used.items():
        if len(ks) > 1:
            E(f"port {pt} dipakai ganda: {', '.join(ks)}")

    ec = str(cfg.get("external-controller", ""))
    if ec and not ec.startswith(("127.", "localhost", "[::1]")) and not cfg.get("secret"):
        W("external-controller terbuka ke LAN tanpa secret (Nikki/OpenClash biasanya memakai secret dari LuCI)")
    if platform != "box":
        if "tun" in cfg:
            W("blok tun ada di profile OpenWrt (bisa bentrok dengan firewall Nikki/OpenClash)")
        if WIFI_PROVIDER in rproviders:
            E("WifiClients masih ada di profile OpenWrt: semua client LAN (192.168.x.x) akan lolos ke Direct")
    dns = cfg.get("dns") or {}
    if dns.get("respect-rules") and not dns.get("proxy-server-nameserver"):
        E("dns.respect-rules aktif tapi proxy-server-nameserver kosong")
    if dns.get("fallback") and (dns.get("fallback-filter") or {}).get("geoip") is not False:
        W("dns.fallback tanpa fallback-filter.geoip: false — filter bawaan Mihomo (geoip CN) tidak relevan di luar China dan membuat urutan nameserver→fallback sulit diprediksi")
    plain = [x for x in (dns.get("nameserver") or []) + (dns.get("fallback") or [])
             if isinstance(x, str) and "://" not in x]
    if plain:
        W("DNS polos (non-DoH) di nameserver/fallback -> bisa bocor ke ISP: " + ", ".join(map(str, plain)))

    if out_dir:
        def local(path):
            if not isinstance(path, str):
                return None
            if path.startswith(P["prefix"]):
                return os.path.join(out_dir, path[len(P["prefix"]):])
            return None
        for sect, d in (("proxy-provider", pproviders), ("rule-provider", rproviders)):
            for name, pv in d.items():
                if pv.get("type") == "file" or (sect == "rule-provider" and pv.get("path")):
                    lp = local(pv.get("path"))
                    if lp and not os.path.isfile(lp):
                        E(f"{sect} '{name}': file tidak ada -> {pv['path']}")
        for fn in glob.glob(os.path.join(out_dir, P["rule_dir"], "*.yaml")):
            try:
                if os.path.getsize(fn) > 200_000:
                    W(f"{os.path.basename(fn)} besar ({os.path.getsize(fn)//1024} KB) — rule-provider besar membebani start di perangkat kecil")
            except OSError:
                pass
    return issues


def dns_leak_audit(cfg, platform=None):
    """Audit STATIS sumber kebocoran DNS di config. Return list[(level, pesan)]; level LEAK | WARN | INFO.
    Bukan jaminan: tes sebenarnya tetap dnsleaktest.com / bash.ws dari perangkat."""
    out, dns = [], cfg.get("dns") or {}
    isp_ips = {ip for pr in ISP_PROFILES.values() for ip in pr["ips"]}
    if not dns.get("enable", True):
        out.append(("WARN", "dns.enable mati: query DNS tidak ditangani Mihomo"))
    if dns.get("enhanced-mode") != "fake-ip":
        out.append(("WARN", "enhanced-mode bukan fake-ip: domain di-resolve lokal sebelum dikirim ke proxy"))
    if not dns.get("respect-rules"):
        out.append(("WARN", "respect-rules mati: query nameserver tidak mengikuti rule (bisa keluar lewat jalur langsung)"))
    if dns.get("ipv6") or cfg.get("ipv6"):
        out.append(("WARN", "ipv6 aktif: pastikan resolver/jalur IPv6 juga lewat proxy"))
    if not dns.get("nameserver"):
        out.append(("WARN", "nameserver kosong"))
    for key in ("nameserver", "fallback"):
        for x in dns.get(key) or []:
            v, kind, is_ip, e = parse_dns_entry(x)
            host = re.sub(r"^[a-z0-9]+://", "", str(x)).split("#")[0].split("/")[0].rsplit(":", 1)[0] if e is None else str(x)
            if host in isp_ips:
                out.append(("LEAK", f"{key}: {x} adalah DNS ISP — akan muncul di dnsleak test"))
            elif e is None and kind not in SECURE_KINDS:
                out.append(("WARN", f"{key}: {x} tidak terenkripsi (aman dari ISP hanya selama respect-rules aktif & lewat proxy)"))
    for key in ("direct-nameserver", "proxy-server-nameserver"):
        plain = [str(x) for x in dns.get(key) or []
                 if "://" not in str(x) and str(x).rsplit(":", 1)[0] not in isp_ips and str(x) not in isp_ips]
        if plain:
            out.append(("INFO", f"{key} polos port 53 ({', '.join(plain)}) lewat jalur DIRECT: ISP bisa membelokkannya ke resolver sensor "
                                f"(Internet Positif) — hipotesis, belum diuji di jaringanmu. Domain yang lewat proxy aman (fake-ip). "
                                f"Kalau situs/node gagal resolve: menu DNS > Mode Anti-Blokir"))
    psn = dns.get("proxy-server-nameserver") or []
    if psn and all("://" in str(x) for x in psn):
        out.append(("INFO", "proxy-server-nameserver DoH semua (Mode Anti-Blokir): kalau ISP me-reset DoH ke 1.1.1.1/8.8.8.8 dan node memakai "
                            "domain, node bisa timeout → balikkan field itu ke IP polos (menu DNS > Custom manual)"))
    if platform in ISP_PLATFORMS:
        out.append(("INFO", "Nikki/OpenClash biasanya menimpa DNS dari setting LuCI-nya — pastikan di sana juga tidak memakai DNS ISP"))
    return out


def print_issues(issues):
    if not issues:
        ok("Validasi: tidak ada masalah.")
        return
    for lvl, msg in issues:
        (err if lvl == "ERR" else warn)(msg)


# =====================================================================
#  File operations
# =====================================================================
def migrate_legacy_layout():
    """Rapikan layout lama: Hasil/ -> hasil/, template.yaml (root) -> template/template.yaml. Return list pesan."""
    notes = []
    try:
        names = os.listdir(SCRIPT_DIR)
    except OSError:
        return notes
    old_out = os.path.join(SCRIPT_DIR, "Hasil")
    if "Hasil" in names:
        if "hasil" not in names:
            try:
                os.rename(old_out, BASE_DIR)
                notes.append("folder Hasil/ dipindah jadi hasil/")
            except OSError as e:
                notes.append(f"gagal memindah Hasil/ -> hasil/: {e}")
        else:
            notes.append("Hasil/ dan hasil/ sama-sama ada; yang dipakai hasil/ (Hasil/ lama bisa dihapus manual)")
    old_tpl = os.path.join(SCRIPT_DIR, "template.yaml")
    if os.path.isfile(old_tpl) and not os.path.exists(TEMPLATE_PATH):
        try:
            os.makedirs(TEMPLATE_DIR, exist_ok=True)
            shutil.move(old_tpl, TEMPLATE_PATH)
            if os.path.isfile(old_tpl + ".bak"):
                shutil.move(old_tpl + ".bak", TEMPLATE_PATH + ".bak")
            notes.append("template.yaml dipindah ke template/template.yaml")
        except OSError as e:
            notes.append(f"gagal memindah template.yaml: {e}")
    return notes


def template_version(path):
    """'0.4' dari penanda '# template-version:' atau nama file config_v0.4.yaml; None kalau tidak ada."""
    if not path:
        return None
    try:
        m = re.search(r"^#\s*template-version:\s*([0-9.]+)", read_text(path), re.M)
    except OSError:
        return None
    if m:
        return m.group(1)
    m = re.search(r"config_v([0-9.]+)\.yaml$", os.path.basename(path))
    return m.group(1) if m else None


def prepare_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)


def load_provider_nodes(path):
    if not os.path.isfile(path):
        return []
    try:
        data = yaml.safe_load(read_text(path))
    except Exception:
        return []
    nodes = [x for x in (data or {}).get("proxies", []) or [] if isinstance(x, dict)] if isinstance(data, dict) else []
    for n in nodes:
        fix_skip_verify(n)   # node lama hasil generate versi sebelumnya bisa punya skip-cert-verify: false + SNI custom
    return nodes


def save_proxy_yaml(proxies, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(dump_yaml({"proxies": proxies}))


def setup_full_config(proxies, target_name, platform, provider_mode="template", write_mode="replace", secret_mode="template", isp=None, operator=None):
    """Return (out_dir, notes, issues, error). operator (mis. "xl") -> file <operator>.yaml + provider di proxy/<operator>/;
    tanpa operator -> config.yaml + proxy/ (perilaku lama)."""
    tpl = find_template()
    if not tpl:
        return None, [], [], "template tidak ditemukan (template/template.yaml / template/config_v*.yaml)"
    if not os.path.isdir(RULESET_SOURCE):
        return None, [], [], f"folder 'ruleset' tidak ditemukan di samping script ({RULESET_SOURCE})"

    P = PLATFORMS[platform]
    out_dir = os.path.join(BASE_DIR, P["out"])
    operator = safe_name(operator) or None
    if operator and isp is None:
        isp = isp_for_operator(operator)
    proxy_dir = os.path.join(out_dir, P["proxy_dir"])          # free.yaml / subs.yaml bersama
    user_dir = os.path.join(proxy_dir, operator) if operator else proxy_dir   # active.yaml / trial.yaml per operator
    try:
        os.makedirs(user_dir, exist_ok=True)
        cfg, notes = build_config(read_text(tpl), platform, provider_mode, secret_mode, isp, operator)
        masters = list_master_templates()
        if masters and os.path.abspath(tpl) == os.path.abspath(TEMPLATE_PATH):
            have, latest = template_version(tpl), template_version(masters[-1])
            if latest and have != latest:
                notes.append(f"template.yaml (salinan kerja, versi {have or 'tidak diketahui'}) lebih tua dari master v{latest} — "
                             "default terbaru (mis. DNS) belum terpakai; ganti lewat Edit Configuration → Ganti File Template")

        # node: dedupe terhadap nama bawaan template (+ node lama kalau mode append)
        target_path = os.path.join(user_dir, target_name)
        existing = load_provider_nodes(target_path) if write_mode == "append" else []
        nodes = dedupe_names([dict(n) for n in proxies], reserved_names() | {x["name"] for x in existing})
        save_proxy_yaml(existing + nodes, target_path)

        other = os.path.join(user_dir, "trial.yaml" if target_name == "active.yaml" else "active.yaml")
        if not os.path.exists(other):
            with open(other, "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

        # provider bawaan template (v1.0+): free.yaml (type file, diisi manual) wajib ada supaya core tidak gagal start;
        # subs.yaml (type http) disemai dari subscription.yaml repo sebagai cache awal. File yang sudah ada tidak ditimpa.
        for pv in (cfg.get("proxy-providers") or {}).values():
            if not isinstance(pv, dict) or not isinstance(pv.get("path"), str):
                continue
            fname = os.path.basename(pv["path"])
            if fname in USER_NODE_FILES:
                continue
            dest = os.path.join(proxy_dir, fname)
            if os.path.exists(dest):
                continue
            seed = SEED_FILES.get(fname)
            if seed and os.path.isfile(seed):
                shutil.copyfile(seed, dest)
            elif pv.get("type") == "file":
                with open(dest, "w", encoding="utf-8") as f:
                    f.write("proxies: []\n")

        target_rules = os.path.join(out_dir, P["rule_dir"])
        if os.path.exists(target_rules):
            shutil.rmtree(target_rules)
        shutil.copytree(RULESET_SOURCE, target_rules)

        with open(os.path.join(out_dir, config_filename(operator)), "w", encoding="utf-8") as f:
            f.write(render_config(cfg, platform, "v3"))
    except PermissionError as e:
        return None, [], [], f"PermissionError: {e}. Taruh folder script di /storage/emulated/0/ (bukan ~ Termux)."
    except (OSError, ValueError, yaml.YAMLError) as e:
        return None, [], [], str(e)

    issues = validate_config(cfg, platform, out_dir)
    return out_dir, notes, issues, None


# =====================================================================
#  Feature: Uji Bug / Custom (SNI · Host · Address ...) — logika di bugtest.py
# =====================================================================
BUG_FIELD_MENU = [("sni", "SNI", "server_name TLS — mis. bug.example.com"),
                  ("host", "Host", "header Host ws/h2 — mis. bug.example.com"),
                  ("server", "Address", "domain/IP server pengganti"),
                  ("port", "Port", "mis. 443 8443"),
                  ("path", "Path", "mis. /ws /vless (grpc: service name)"),
                  ("alpn", "ALPN", "mis. h2,http/1.1 atau http/1.1"),
                  ("fp", "Fingerprint", "chrome firefox safari ios android edge random"),
                  ("phantom", "Phantom", "domain bug untuk PhantomNG — SNI phantom:<server>:<bug>, Host = server")]


def _bug_progress(mode, done, total):
    if sys.stdout.isatty():
        label = {"tcp": "TCP/TLS", "mihomo": "Mihomo", "v2ray": "V2Ray/Xray"}.get(mode, mode)
        sys.stdout.write(f"\r  {C.DIM}uji {label}: {done}/{total}{C.RESET}   "); sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\r" + " " * 40 + "\r")


def _bug_pick_nodes(nodes):
    """Index node yang diuji (Enter = semua) atau None kalau input salah."""
    if len(nodes) == 1:
        return [0]
    print(f"  {C.DIM}Node yang bisa diuji:{C.RESET}")
    for i, n in enumerate(nodes, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {truncate(str(n.get('name')), 24):<24} "
              f"{C.DIM}{str(n.get('type', '?')).upper():<6} {truncate(str(n.get('server')), 18)}{C.RESET}")
    while True:
        raw = ask(f"{C.YELLOW}Node yang diuji (Enter = semua, atau 1,3; 0 = batal) ❯{C.RESET} ").strip()
        if not raw:
            return list(range(len(nodes)))
        if raw.lower() in ("0", "batal"):
            return None
        try:
            idx = sorted({int(x) - 1 for x in raw.replace(" ", "").split(",") if x})
        except ValueError:
            err("Input tidak valid — pakai nomor dipisah koma."); continue
        if not idx or any(not 0 <= i < len(nodes) for i in idx):
            err(f"Nomor di luar daftar (1-{len(nodes)})."); continue
        return idx


def _bug_pick_fields():
    print(); section("Yang mau diuji")
    for i, (_, label, hint) in enumerate(BUG_FIELD_MENU, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {label:<12} {C.DIM}{hint}{C.RESET}")
    print(f"  {C.CYAN}[L]{C.RESET} {'Lazy':<12} {C.DIM}otomatis: coba semua metode address/port/host/SNI dari bug{C.RESET}")
    print(sep(50))
    while True:
        raw = ask(f"{C.YELLOW}Pilih (mis. 1,2,3 — Enter = SNI+Host+Address, L = Lazy, 0 = batal) ❯{C.RESET} ").strip() or "1,2,3"
        if raw.lower() in ("l", "lazy"):
            return ["lazy"]
        if raw.lower() in ("0", "batal"):
            return None
        try:
            nums = sorted({int(x) for x in raw.replace(" ", "").split(",") if x})
        except ValueError:
            err("Input tidak valid — pakai nomor dipisah koma, atau L."); continue
        if not nums or any(not 1 <= n <= len(BUG_FIELD_MENU) for n in nums):
            err(f"Nomor di luar daftar (1-{len(BUG_FIELD_MENU)})."); continue
        return [BUG_FIELD_MENU[n - 1][0] for n in nums]


# ---------- Daftar file hasil sniffer (dipakai sebagai kandidat Uji Bug) ----------
SNIFFER_PICK_LIMIT = 15


def sniffer_result_files():
    """File hasil sniffer yang bisa dipakai: [(path, label)] terbaru dulu. Satu entri per rekaman: .json (atau .csv bila
    .json tidak ada) + log penangkap path .jsonl. File .md (laporan) dan config tidak termasuk."""
    d = SNIFFER_OUT_DIR
    out = {}
    for pattern in ("*.json", "*.csv", "*.jsonl"):
        for fn in glob.glob(os.path.join(d, pattern)):
            stem, ext = os.path.splitext(fn)
            if ext == ".csv" and os.path.isfile(stem + ".json"):
                continue
            out[fn] = os.path.basename(fn)
    return sorted(out.items(), key=lambda kv: os.path.getmtime(kv[0]), reverse=True)


def sniffer_file_candidates(path):
    """Kandidat dari satu file hasil sniffer → {"domains", "ips", "ports", "paths", "bugpaths"} (list unik berurutan).
    Hanya koneksi yang MENERIMA data (download > 0) untuk .json/.csv. Raise OSError/ValueError bila file tak terbaca."""
    out = {"domains": [], "ips": [], "ports": [], "paths": [], "bugpaths": []}

    def add(key, val):
        val = str(val or "").strip()
        if val and val not in out[key]:
            out[key].append(val)

    if path.lower().endswith(".jsonl"):
        hc = _import_tool("httpcatch")
        if not hc:
            raise ValueError("httpcatch.py tidak bisa dimuat")
        events = hc.load_jsonl(path)
        for e in events:
            host = str(e.get("host") or "")
            (add("ips", host) if ip_literal(host) else add("domains", host))
        for c in hc.bug_candidates(events):
            add("bugpaths", c)
            seg = "/" + c.split("/", 1)[1] if "/" in c else ""
            add("paths", seg)
        return out
    sn = _import_tool("sniffer")
    if not sn:
        raise ValueError("sniffer.py tidak bisa dimuat")
    rows = sn.rows_from_file(path)
    groups, _, _ = sn.aggregate_ok(rows)
    for g in groups:
        name = g["name"]
        if g["kind"] == "IP" or ip_literal(name):
            add("ips", name)
        else:
            add("domains", name)
        for ip in g.get("ips") or []:
            add("ips", ip)
        add("ports", g.get("port"))
    return out


def _sniffer_tokens_for(field, cand):
    """Pilih bagian kandidat sniffer yang cocok untuk field Uji Bug."""
    if field == "bug":
        return cand["domains"] + cand["bugpaths"]
    if field in ("sni", "host", "phantom"):
        return cand["domains"]
    if field == "server":
        return cand["domains"] + cand["ips"]
    if field == "ip":
        return cand["ips"]
    if field == "port":
        return cand["ports"]
    if field == "path":
        return cand["paths"]
    return []


def _pick_sniffer_tokens(field, label):
    """Tampilkan daftar file hasil sniffer, minta pilihan (boleh banyak), return list token kandidat (kosong = lewati)."""
    files = sniffer_result_files()
    if not files:
        return []
    shown = files[:SNIFFER_PICK_LIMIT]
    while True:
        print(f"\n  {C.BOLD}Hasil sniffer{C.RESET} {C.DIM}(hasil/sniffer/) — pilih sebagai kandidat {label}:{C.RESET}")
        for i, (fn, name) in enumerate(shown, 1):
            when = time.strftime("%d-%m %H:%M", time.localtime(os.path.getmtime(fn)))
            print(f"  {C.CYAN}[{i}]{C.RESET} {truncate(name, 34):<34} {C.DIM}{when}  {_human_size(os.path.getsize(fn))}{C.RESET}")
        extra = f"  [L] semua ({len(files)})" if len(files) > len(shown) else ""
        raw = ask(f"{C.YELLOW}File (nomor, pisah koma{extra}; Enter = lewati) ❯{C.RESET} ").strip().lower()
        if not raw:
            return []
        if raw == "l" and len(files) > len(shown):
            shown = files; continue
        try:
            nums = sorted({int(x) for x in raw.replace(" ", "").split(",") if x})
        except ValueError:
            err("Input tidak valid — pakai nomor dipisah koma."); continue
        if not nums or any(not 1 <= n <= len(shown) for n in nums):
            err(f"Nomor di luar daftar (1-{len(shown)})."); continue
        tokens = []
        for n in nums:
            fn, name = shown[n - 1]
            try:
                tk = _sniffer_tokens_for(field, sniffer_file_candidates(fn))
            except (OSError, ValueError, Exception) as e:
                warn(f"{name}: tidak terbaca — {e}"); continue
            ok(f"{name}: {len(tk)} kandidat")
            tokens += tk
        return list(dict.fromkeys(tokens))


def _bug_collect_candidates(bt, fields):
    """Minta kandidat per field. Return {field: [nilai]} atau None kalau dibatalkan / kosong semua."""
    cands = {}
    labels = {f: (l, h) for f, l, h in BUG_FIELD_MENU}
    for f in fields:
        label, hint = labels[f]
        print(); section(f"Kandidat {label}")
        from_sniffer = _pick_sniffer_tokens(f, label)
        lines = _collect_lines([f"Paste daftar {label}, banyak sekaligus.",
                                hint,
                                "Pisah baris/spasi/koma. '@file.txt' = dari file.",
                                "Enter kosong = selesai" + (" (hasil sniffer terpilih ikut dipakai)." if from_sniffer else ".")
                                + " 'batal' = batalkan uji."])
        if lines is None:
            return None
        text, problems = bt.read_candidate_lines(from_sniffer + lines)
        for pr in problems:
            warn(f"file tidak terbaca — {pr}")
        good, bad = bt.parse_candidates(f, text)
        if bad:
            warn(f"{len(bad)} token dilewati (tidak valid): {truncate(', '.join(map(str, bad[:6])), 44)}")
        if good:
            ok(f"{len(good)} kandidat {label}")
            cands[f] = good
        else:
            print(f"  {C.DIM}{label}: kosong, dilewati.{C.RESET}")
    if not cands:
        err("Tidak ada kandidat yang valid."); return None
    return cands


def _bug_collect_lazy(bt):
    """Mode Lazy: minta bug, IP edge tambahan (opsional) dan port. Return {"bugs", "ips", "ports"} atau None (batal)."""
    got = {}
    for key, title, label, intro in (
            ("bug", "Bug (Lazy)", "bug", ["Paste domain bug, banyak sekaligus (mis. instagram.com).",
                                          "Bug berpath (mis. www.line.me/en) otomatis juga dicoba metode ganti path.",
                                          "Pisah baris/spasi/koma. '@file.txt' = dari file.",
                                          "Enter kosong = selesai. 'batal' = batalkan uji."]),
            ("ip", "IP edge tambahan (opsional)", "IP edge", ["IP edge CDN, mis. 13.35.1.58 104.18.43.252.",
                                                              "IP node & hasil resolve domain server ikut dicoba otomatis.",
                                                              "Enter kosong = lewati."])):
        print(); section(title)
        from_sniffer = _pick_sniffer_tokens(key, label)
        lines = _collect_lines(intro)
        if lines is None:
            return None
        text, problems = bt.read_candidate_lines(from_sniffer + lines)
        for pr in problems:
            warn(f"file tidak terbaca — {pr}")
        good, bad = bt.parse_candidates(key, text)
        if bad:
            warn(f"{len(bad)} token dilewati (tidak valid): {truncate(', '.join(map(str, bad[:6])), 44)}")
        if good:
            ok(f"{len(good)} {label}")
        got[key] = good
    if not got["bug"]:
        warn("Tanpa bug: hanya metode yang tidak butuh bug yang dicoba.")
    while True:
        raw = ask(f"{C.YELLOW}Port (Enter = {','.join(map(str, bt.DEFAULT_LAZY_PORTS))}) ❯{C.RESET} ").strip()
        ports, bad = bt.parse_candidates("port", raw) if raw else ([], [])
        if raw and (bad or not ports):
            err("Port tidak valid: " + truncate(", ".join(map(str, bad)) or raw, 40) + " (1-65535, pisah spasi/koma)."); continue
        break
    return {"bugs": got["bug"], "ips": got["ip"], "ports": ports or list(bt.DEFAULT_LAZY_PORTS)}


def _bug_choose_modes(bt):
    """Pilih mode + siapkan core. Return (modes, opts) atau None."""
    print(); section("Mode Tes")
    mih = bt.find_mihomo()
    v2core, v2flavor = bt.find_v2ray()
    print(f"  {C.CYAN}[1]{C.RESET} TCP/TLS     {C.DIM}cepat, tanpa core (WS: cek balasan HTTP 101){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Mihomo      {C.DIM}tes sungguhan lewat core — "
          f"{'ditemukan' if mih else 'belum ada, bisa diunduh otomatis'}{C.RESET}")
    print(f"  {C.CYAN}[3]{C.RESET} V2Ray/Xray  {C.DIM}tes sungguhan lewat core — "
          f"{(v2flavor + ' ditemukan') if v2core else 'tidak ditemukan'}{C.RESET}")
    print(f"  {C.DIM}Boleh lebih dari satu (mis. 1,2): varian harus lolos semua mode, urut dari yang termurah.{C.RESET}")
    print(sep(50))
    while True:
        raw = ask(f"{C.YELLOW}Pilih mode (Enter = 2, 0 = batal) ❯{C.RESET} ").strip() or "2"
        if raw.lower() in ("0", "batal"):
            return None
        try:
            nums = sorted({int(x) for x in raw.replace(" ", "").split(",") if x})
        except ValueError:
            err("Input tidak valid — pakai 1, 2, 3 (boleh dipisah koma)."); continue
        if not nums or any(n not in (1, 2, 3) for n in nums):
            err("Pilihan tidak valid — hanya 1, 2, 3."); continue
        break
    modes = [bt.MODES[n - 1] for n in nums]
    opts = {}
    if "mihomo" in modes:
        if not mih:
            if not ask_yn(f"  Core Mihomo belum ada. Unduh otomatis dari GitHub? (Y/n) ❯ ", default=True):
                return None
            mih = bt.download_mihomo()
            if not mih:
                err("Core Mihomo tidak tersedia (unduhan gagal). Pakai mode TCP/TLS, atau taruh binary di ./bin/mihomo."); return None
        opts["mihomo_core"] = mih
    if "v2ray" in modes:
        if not v2core:
            err("Core xray/v2ray tidak ditemukan. Taruh binary 'xray' (atau 'v2ray' >= 5) di PATH atau ./bin/, "
                "atau set HIKARI_XRAY=/path/ke/xray.")
            return None
        opts["v2ray_core"], opts["v2ray_flavor"] = v2core, v2flavor
    while True:
        raw = ask(f"{C.YELLOW}Timeout per tes, detik (Enter = 5, maks 30) ❯{C.RESET} ").strip()
        if not raw:
            opts["timeout"] = 5.0; break
        if raw.replace(".", "", 1).isdigit() and float(raw) > 0:
            opts["timeout"] = float(raw); break
        err(f"'{truncate(raw, 20)}' bukan angka detik yang valid.")
    if opts["timeout"] > 30:
        warn("Timeout dibatasi 30 detik: API Mihomo menolak nilai di atas 32 detik dengan error 'Body invalid'.")
        opts["timeout"] = 30.0
    if "tcp" in modes or "mihomo" in modes:
        ips = _pick_operator_dns("bugtest")
        if ips:
            opts["dns_servers"] = ips
            print(f"  {C.DIM}DNS operator {', '.join(ips)} dipakai untuk me-resolve address node & kandidat (TCP/TLS dan Mihomo).{C.RESET}")
    return modes, opts


def _bug_show_lazy(bt, rows, limit=5):
    """Hasil mode Lazy untuk satu node: metode/kombinasi tercepat yang lolos + tabel per metode (muat di layar sempit)."""
    good = sorted((v for v in rows if v["ok"]), key=lambda v: (v["ms"] or 10 ** 9, v["id"]))
    print(f"    {'Lazy':<11} : {C.GREEN if good else C.RED}{len(good)}/{len(rows)} lolos{C.RESET}")
    for v in good[:limit]:
        lz = v["fields"]["lazy"]
        print(f"      {C.GREEN}✓{C.RESET} {lz['method']} · port {lz['port']} {C.DIM}{(str(v['ms']) + 'ms') if v['ms'] else ''}{C.RESET}")
        print(f"        {C.DIM}address {truncate(lz['addr'], 30)}{C.RESET}")
        print(f"        {C.DIM}host    {truncate(lz['host'] or '-', 30)}{C.RESET}")
        print(f"        {C.DIM}sni     {truncate(lz['sni'] or '-', 30)}{C.RESET}")
        if lz.get("path"):
            print(f"        {C.DIM}path    {truncate(lz['path'], 30)}{C.RESET}")
    if len(good) > limit:
        print(f"      {C.DIM}... +{len(good) - limit} lainnya (lihat file hasil){C.RESET}")
    print(f"      {C.DIM}per metode (S=server B=bug IP=IP edge W=bug.server):{C.RESET}")
    for r in bt.lazy_summary(rows):
        mark = f"{C.GREEN}✓{C.RESET}" if r["ok"] else f"{C.RED}✗{C.RESET}"
        print(f"      {mark} {r['method']:<18} {C.DIM}{r['ok']}/{r['tested']}{C.RESET}")


def _bug_show_results(bt, variants, modes, limit=12):
    print(); section("Hasil Uji")
    names = {}
    for v in variants:
        names.setdefault(v["base"], v["base_name"])
    for bi in sorted(names):
        base = next((v for v in variants if v["base"] == bi and v["kind"] == "base"), None)
        print(f"  {C.BOLD}{truncate(names[bi], 40)}{C.RESET}")
        if base:
            if base["ok"]:
                print(f"    config asli : {C.GREEN}✓ OK{C.RESET} {C.DIM}{base['ms'] or ''}{'ms' if base['ms'] else ''}{C.RESET}")
            else:
                print(f"    config asli : {C.RED}✗ gagal{C.RESET} {C.DIM}{truncate(base['reason'], 30)}{C.RESET}")
        for kind in bt.RESULT_KINDS:
            rows = [v for v in variants if v["base"] == bi and v["kind"] == kind]
            if not rows:
                continue
            if kind == "lazy":
                _bug_show_lazy(bt, rows)
                continue
            good = sorted((v for v in rows if v["ok"]), key=lambda v: (v["ms"] or 10 ** 9, v["id"]))
            label = bt.FIELD_LABEL.get(kind, "Gabungan")
            col = C.GREEN if good else C.RED
            print(f"    {label:<11} : {col}{len(good)}/{len(rows)} lolos{C.RESET}")
            for v in good[:limit]:
                print(f"      {C.GREEN}✓{C.RESET} {truncate(bt.describe_fields(v), 34):<34} {C.DIM}{(str(v['ms']) + 'ms') if v['ms'] else '':>7}{C.RESET}")
            if len(good) > limit:
                print(f"      {C.DIM}... +{len(good) - limit} lainnya (lihat file hasil){C.RESET}")
    total_ok = len(bt.passing(variants))
    n_tested = sum(1 for v in variants if v["kind"] != "base")
    print(f"\n  {C.GREEN}{total_ok} varian lolos{C.RESET} dari {n_tested} diuji")
    if any(v["kind"] == "base" and not v["ok"] for v in variants) and total_ok == 0:
        print(f"  {C.DIM}Config asli juga gagal — server/UUID mungkin mati atau jaringan ini memblokirnya; "
              f"varian ikut gagal karena itu.{C.RESET}")


def feature_bugtest(nodes):
    """Uji kandidat SNI/Host/Address/... untuk `nodes` (list dict node Clash).
    Return None (batal / tidak ada yang dipakai) atau {"nodes": [varian lolos], "drop": {index node asli yang diganti}, "desc": [str]}."""
    bt = _import_tool("bugtest")
    if not bt:
        pause(); return None
    clear_screen(); banner(); section("Uji Bug / Custom Config")
    print(f"  {C.DIM}Uji banyak SNI / Host / Address sekaligus pada node ini: apakah masih bisa konek.")
    print(f"  Yang lolos jadi node varian + file YAML siap dipakai di mihomo/v2ray.{C.RESET}\n")
    picked = _bug_pick_nodes(nodes)
    if picked is None:
        time.sleep(1.2); return None
    tested = [nodes[i] for i in picked]
    fields = _bug_pick_fields()
    if fields is None:
        time.sleep(1.2); return None
    lazy = fields == ["lazy"]
    lz = cands = None
    if lazy:
        lz = _bug_collect_lazy(bt)
        if lz is None:
            time.sleep(1.2); return None
    else:
        cands = _bug_collect_candidates(bt, fields)
        if cands is None:
            time.sleep(1.2); return None
    chosen = _bug_choose_modes(bt)
    if chosen is None:
        pause(); return None
    modes, opts = chosen

    if lazy:
        print(f"\n  {C.DIM}Menyusun metode (me-resolve IP edge dari domain server)...{C.RESET}")
        variants, skipped = bt.build_lazy_variants(tested, lz["bugs"], lz["ports"], lz["ips"], opts)
    else:
        variants, skipped = bt.build_variants(tested, cands)
    for _, name, field, why in skipped:
        warn(f"{truncate(name, 24)}: {bt.FIELD_LABEL[field]} dilewati — {why}")
    n_var = sum(1 for v in variants if v["kind"] != "base")
    if not n_var:
        err("Tidak ada varian yang bisa dibuat (semua kandidat sama dengan config asli atau tidak berlaku)."); pause(); return None
    print(f"\n  {len(tested)} node · {n_var} varian + {len(tested)} config asli · mode "
          f"{' + '.join(bt.MODE_LABEL[m] for m in modes)}")
    if n_var > 400:
        warn("Jumlah tes besar — bisa lama. Ctrl+C untuk menghentikan.")
    if not ask_yn(f"{C.YELLOW}Mulai? (Y/n) ❯{C.RESET} ", default=True):
        return None

    print()
    try:
        bt.test_variants(variants, modes, opts, progress=_bug_progress)
        if bt.tcp_intercepted(variants):
            warn("Hampir semua TCP connect <3 ms: koneksi dijawab Box/Nikki/VPN lokal. Matikan dulu atau pakai mode Mihomo/V2Ray.")
        combos = [] if lazy else bt.make_combos(variants)
        if combos and ask_yn(f"\n{C.YELLOW}Uji juga gabungan terbaik tiap field ({len(combos)} node)? (Y/n) ❯{C.RESET} ", default=True):
            bt.test_variants(combos, modes, opts, progress=_bug_progress)
            variants += combos
    except RuntimeError as e:
        err(f"Uji gagal: {e}"); pause(); return None
    except KeyboardInterrupt:
        print(); warn("Uji dihentikan."); pause(); return None

    _bug_show_results(bt, variants, modes)
    ok_v = bt.passing(variants)
    out_dir = os.path.join(BUGTEST_DIR, time.strftime("%d%m%Y_%H%M%S"))
    try:
        files = bt.write_outputs(variants, modes, out_dir, lambda ns: dump_yaml({"proxies": ns}), skipped,
                                 {"when": time.strftime("%Y-%m-%d %H:%M:%S"), "test_url": bt.DEFAULT_TEST_URL})
        uris = []                                   # link vless/vmess/trojan untuk klien v2ray (v2rayNG, NekoBox, dst.)
        for v in ok_v:
            try:
                u = build_uri_from_proxy(v["node"])
            except Exception:
                u = None
            if u:
                uris.append(u)
        if uris:
            with open(os.path.join(out_dir, "bug-ok-uri.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(uris) + "\n")
            files.insert(-1, ("bug-ok-uri.txt", len(uris)))
        ph_uris = []                                # varian Phantom: link khusus PhantomNG (sni=phantom:<server>:<bug>[:rand])
        for v in ok_v:
            pn = bt.phantom_export_node(v["node"])
            try:
                u = build_uri_from_proxy(pn) if pn else None
            except Exception:
                u = None
            if u:
                ph_uris.append(u)
        if ph_uris:
            with open(os.path.join(out_dir, "bug-ok-phantom-uri.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(ph_uris) + "\n")
            files.insert(-1, ("bug-ok-phantom-uri.txt", len(ph_uris)))
        print(f"\n  {C.GREEN}✓{C.RESET} Hasil tersimpan di:\n    {C.BOLD}{C.CYAN}{out_dir}/{C.RESET}")
        for fn, n in files:
            print(f"    {C.DIM}├── {fn}{f'  ({n} node)' if n else ''}{C.RESET}")
    except OSError as e:
        warn(f"File hasil tidak bisa ditulis ({e.strerror or e}) — varian tetap bisa dipakai di bawah.")

    if not ok_v:
        pause(); return None
    print(); section("Pakai varian yang lolos")
    print(f"  {C.CYAN}[1]{C.RESET} Tambahkan {len(ok_v)} varian ke daftar node {C.DIM}(node asli tetap){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Ganti node asli yang punya varian lolos dengan varian-nya")
    print(f"  {C.CYAN}[3]{C.RESET} Jangan dipakai {C.DIM}(cukup file hasil di atas){C.RESET}")
    pick = ask_choice(f"{C.YELLOW}Pilih (Enter = 1) ❯{C.RESET} ", ("1", "2", "3"), default="1")
    if pick not in ("1", "2"):
        return None
    drop = {picked[v["base"]] for v in ok_v} if pick == "2" else set()
    return {"nodes": [bt.clean_node(v["node"]) for v in ok_v], "drop": drop,
            "desc": [bt.describe_fields(v) for v in ok_v]}


# =====================================================================
#  Feature: URI -> Clash
# =====================================================================
def _collect_lines(prompt_lines):
    for ln in prompt_lines:
        print(f"  {C.DIM}{ln}{C.RESET}")
    print(sep(50) + "\n")
    lines = []
    while True:
        try:
            s = input(f"{C.CYAN}❯{C.RESET} ")
        except EOFError:
            break
        if s.strip().lower() in ("batal", "batalkan"):
            return None
        if s.strip() == "":
            break
        lines.append(s)
    return lines


def feature_convert_to_clash():
    print()
    section("Masukkan node (Format URI)")
    lines = _collect_lines(["Paste vless:// atau vmess:// atau trojan:// (satu per baris).",
                            "Tekan Enter 2x untuk selesai.", "Ketik 'batal' untuk kembali ke menu."])
    if lines is None:
        return
    if not lines:
        err("Tidak ada input."); time.sleep(1.2); return

    extra = []          # [(node, deskripsi)] varian lolos dari Uji Bug (aksi [U]); ikut diproses saat [L]
    while True:
        valid, invalid = [], []
        for i, ln in enumerate(lines):
            if not ln.strip():
                continue
            try:
                n = convert_line(ln)
                if n:
                    n["_orig_idx"] = i; valid.append(n)
            except Exception as e:
                invalid.append((i, ln.strip(), str(e)))

        clear_screen(); banner()
        section(f"Preview Input ({len(valid)} Valid, {len(invalid)} Gagal" + (f", +{len(extra)} Varian" if extra else "") + ")")
        if valid or extra:
            print(f"  {C.BOLD}{'No':<4} | {'Tipe':<7} | {'Nama Node':<20} | {'Server'}{C.RESET}")
            print(f"  {C.GRAY}{'-'*4}-+-{'-'*7}-+-{'-'*20}-+-{'-'*15}{C.RESET}")
            for idx, p in enumerate(valid, 1):
                print(f"  {C.CYAN}{idx:<4}{C.RESET} | {p['type'].upper():<7} | "
                      f"{truncate(str(p['name']), 20):<20} | {C.DIM}{truncate(str(p['server']), 15)}{C.RESET}")
            for k, (p, desc) in enumerate(extra, len(valid) + 1):
                print(f"  {C.CYAN}{k:<4}{C.RESET} | {C.MAGENTA}{'VARIAN':<7}{C.RESET} | "
                      f"{truncate(str(p['name']), 20):<20} | {C.DIM}{truncate(str(p['server']), 15)}{C.RESET}")
                print(f"  {C.DIM}{'':<4}   ↳ {truncate(desc, 40)}{C.RESET}")
        for i, ln, reason in invalid:
            print(f"  {C.RED}✗ baris {i+1}{C.RESET} {C.DIM}{truncate(ln, 28)}{C.RESET} → {reason}")

        print()
        section("Aksi")
        print(f"  {C.YELLOW}[T]{C.RESET} Tambah node lain")
        print(f"  {C.YELLOW}[H]{C.RESET} Hapus node (nomor, mis: 1 atau 1,3)")
        print(f"  {C.CYAN}[U]{C.RESET} Uji bug / custom SNI · Host · Address {C.DIM}(banyak sekaligus){C.RESET}")
        print(f"  {C.GREEN}[L]{C.RESET} Lanjut Proses")
        print(f"  {C.RED}[B]{C.RESET} Batal / Kembali ke Menu")
        print(sep(50))
        aksi = ask(f"{C.YELLOW}Pilih Aksi ❯{C.RESET} ").strip().lower()

        if aksi == "l":
            if valid or extra:
                break
            warn("Belum ada node valid."); time.sleep(1.2)
        elif aksi == "u":
            if not valid:
                warn("Belum ada node valid untuk diuji."); time.sleep(1.2); continue
            res = feature_bugtest(valid)
            if res:
                gone = {valid[i]["_orig_idx"] for i in res["drop"]}
                lines = [ln for i, ln in enumerate(lines) if i not in gone]
                extra += list(zip(res["nodes"], res["desc"]))
        elif aksi == "b":
            return
        elif aksi == "t":
            print(); section("Tambah Node Lagi")
            more = _collect_lines(["Paste tautan baru (satu per baris).", "Enter kosong = selesai.",
                                   "Ketik 'batalkan' untuk batal nambah."])
            if more:
                lines += more
        elif aksi == "h":
            raw = ask("  Nomor yang mau dihapus ❯ ").strip()
            try:
                nums = [int(x) for x in raw.split(",") if x.strip()]
            except ValueError:
                err("Input tidak valid."); time.sleep(1.2); continue
            gone = {valid[n - 1]["_orig_idx"] for n in nums if 1 <= n <= len(valid)}
            lines = [ln for i, ln in enumerate(lines) if i not in gone]
            gone_x = {n - len(valid) - 1 for n in nums if len(valid) < n <= len(valid) + len(extra)}
            extra = [e for i, e in enumerate(extra) if i not in gone_x]
            if not any(ln.strip() for ln in lines) and not extra:
                err("Semua tautan dihapus. Kembali ke menu."); time.sleep(1.2); return
        else:
            err("Aksi tidak dikenal."); time.sleep(0.8)

    proxies = [{k: v for k, v in p.items() if k != "_orig_idx"} for p in valid] + [dict(p) for p, _ in extra]
    n_emoji = apply_emoji(proxies)
    _generate_and_report(proxies, n_emoji)


def _ask_operator(default=None):
    """Tanya operator/ISP. Return nama aman (mis. 'xl', 'byu'). Enter = `default` (operator terakhir) kalau ada.
    Nomor atau nama; [8] / nama lain = ketik sendiri. Jawaban kosong tanpa default ditolak (ditanya ulang)."""
    print(); section("Operator / ISP")
    print(f"  {C.DIM}Menentukan nama file (<operator>.yaml) dan folder provider (proxy/<operator>/).{C.RESET}")
    keys = list(OPERATORS)
    for i, k in enumerate(keys, 1):
        extra = f"  {C.DIM}(+DNS {', '.join(ISP_PROFILES['xl']['ips'])} di Nikki/OpenClash){C.RESET}" if k == "xl" else ""
        print(f"  {C.CYAN}[{i}]{C.RESET} {OPERATORS[k]:<10}{C.DIM}→ {k}.yaml{C.RESET}{extra}")
    print(f"  {C.CYAN}[{len(keys) + 1}]{C.RESET} Lainnya    {C.DIM}(ketik nama sendiri){C.RESET}")
    print(sep(50))
    hint = f"Enter = {default}" if default else "wajib diisi"
    while True:
        raw = ask(f"{C.YELLOW}Operator ({hint}) ❯{C.RESET} ").strip()
        if not raw:
            if default:
                return default
            err("Operator wajib diisi (nomor atau nama)."); continue
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(keys):
                return keys[n - 1]
            if n == len(keys) + 1:
                name = safe_name(ask("  Nama operator (huruf/angka) ❯ "))
                if name:
                    return name
                err("Nama tidak valid."); continue
            err("Nomor di luar daftar."); continue
        name = safe_name(raw)
        if name and name == raw.strip().lower().replace(" ", "-"):
            return name
        err(f"Nama '{truncate(raw, 20)}' tidak valid (hanya huruf, angka, . _ -).")


def _generate_and_report(proxies, n_emoji=0, default_plat=None, default_target=None, source_path=None, node_label="node baru",
                         default_operator=None):
    """Pilih output/target/operator/mode → setup_full_config → laporan. Dipakai Convert (node baru) dan Regenerate (node tersimpan).
    default_*: nilai saat Enter. source_path: file provider asal node; kalau sama dengan target, tidak ditanya timpa/tambah."""
    print(); section("Pilih Output Config")
    print(f"  {C.CYAN}[B]{C.RESET} Config for Box (Android)")
    print(f"  {C.CYAN}[N]{C.RESET} Config for Nikki (OpenWrt)")
    print(f"  {C.CYAN}[O]{C.RESET} Config for OpenClash (OpenWrt)")
    print(sep(50))
    platform = {"b": "box", "n": "nikki", "o": "openclash"}
    plat_hint = f", Enter={default_plat[0].upper()}" if default_plat else ""
    raw = ask_choice(f"{C.YELLOW}Pilih (B/N/O{plat_hint}) ❯{C.RESET} ", platform,
                     default=default_plat[0] if default_plat else None)
    plat = platform[raw]

    print(); section("Pilih Target Provider")
    print(f"  {C.CYAN}[1]{C.RESET} active.yaml\n  {C.CYAN}[2]{C.RESET} trial.yaml")
    print(sep(50))
    tgt_hint = f", Enter={'1' if default_target == 'active.yaml' else '2'}" if default_target else ""
    c = ask_choice(f"{C.YELLOW}Pilih (1/2{tgt_hint}) ❯{C.RESET} ", ("1", "2"),
                   default=("1" if default_target == "active.yaml" else "2") if default_target else None)
    target_name = "active.yaml" if c == "1" else "trial.yaml"

    operator = _ask_operator(default_operator or load_settings()["operator"] or None)
    try:
        save_settings({"operator": operator})
    except OSError:
        pass

    P = PLATFORMS[plat]
    target_path = os.path.join(BASE_DIR, P["out"], P["proxy_dir"], operator, target_name)
    same_as_source = bool(source_path) and os.path.abspath(source_path) == os.path.abspath(target_path)
    existing = [] if same_as_source else load_provider_nodes(target_path)
    write_mode = "replace"
    if existing:
        print()
        warn(f"{operator}/{target_name} sudah berisi {len(existing)} node.")
        print(f"  {C.CYAN}[1]{C.RESET} Ganti (timpa)   {C.CYAN}[2]{C.RESET} Tambahkan ke yang lama")
        write_mode = "append" if ask_choice(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ", ("1", "2")) == "2" else "replace"

    print(); section("Mode Rule-Provider")
    print(f"  {C.CYAN}[1]{C.RESET} Ikuti template {C.DIM}(http: auto-update dari GitHub){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Offline        {C.DIM}(file lokal saja, tanpa update){C.RESET}")
    provider_mode = "offline" if ask_choice(f"{C.YELLOW}Pilih (1/2, Enter=1) ❯{C.RESET} ", ("1", "2"), default="1") == "2" else "template"

    print(); section("Secret Dashboard")
    tpl_secret = _template_secret()
    print(f"  {C.CYAN}[1]{C.RESET} Ikuti template {C.DIM}(sekarang: {tpl_secret or 'kosong'}){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Acak           {C.DIM}(dibuat otomatis, ditampilkan setelah generate){C.RESET}")
    secret_mode = "random" if ask_choice(f"{C.YELLOW}Pilih (1/2, Enter=1) ❯{C.RESET} ", ("1", "2"), default="1") == "2" else "template"

    print()
    spinner("Membangun & memvalidasi config", 0.5)
    out_dir, notes, issues, error = setup_full_config(proxies, target_name, plat, provider_mode, write_mode, secret_mode,
                                                      isp_for_operator(operator), operator)
    if error:
        err(f"Gagal: {error}\n"); pause(); return

    cfg_name = config_filename(operator)
    ok(f"Config {P['label']} siap di:\n  {C.BOLD}{C.CYAN}{out_dir}/{C.RESET}")
    print(f"  {C.DIM}├── {cfg_name}{C.RESET}")
    print(f"  {C.DIM}├── {P['proxy_dir']}/{operator}/{target_name} ({len(proxies)} {node_label}){C.RESET}")
    print(f"  {C.DIM}└── {P['rule_dir']}/{C.RESET}\n")
    for n in notes:
        print(f"  {C.DIM}• {n}{C.RESET}")
    print()
    print_issues(issues)
    if not n_emoji:
        ecfg = load_emoji_cfg()
        why = "fitur emoji OFF (Edit Configuration → Emoji Node)" if not ecfg["enabled"] else "semua nama node sudah diawali emoji"
        print(f"\n  {C.DIM}Emoji tidak ditambahkan: {why}.{C.RESET}")
    if n_emoji:
        print(f"\n  {C.DIM}Nama node (emoji sesuai metode, ubah di Edit Configuration → Emoji Node):{C.RESET}")
        for p in proxies[:10]:
            print(f"    {p['name']}")
        if len(proxies) > 10:
            print(f"    {C.DIM}... +{len(proxies) - 10} lainnya{C.RESET}")
    secret = yaml.safe_load(read_text(os.path.join(out_dir, cfg_name))).get("secret")
    print(f"\n  Dashboard secret : {C.BOLD}{secret if secret else '(kosong)'}{C.RESET}")

    print()
    if plat == "box":
        print(f"{C.YELLOW}💡 BOX ANDROID:{C.RESET} copy SEMUA isi folder di atas ke {C.BOLD}/data/adb/box/clash/{C.RESET}")
        print(f"   {C.DIM}Kalau Box-mu membaca config.yaml, salin/ganti nama {cfg_name} jadi config.yaml.{C.RESET}")
    elif plat == "nikki":
        print(f"{C.YELLOW}💡 NIKKI:{C.RESET}")
        print(f"   1. {C.BOLD}{cfg_name}{C.RESET} → {C.BOLD}/etc/nikki/profiles/{C.RESET}")
        print(f"   2. folder {C.BOLD}proxy/{C.RESET} & {C.BOLD}ruleset/{C.RESET} → {C.BOLD}{NIKKI_RUN_DIR}/{C.RESET}")
    else:
        print(f"{C.YELLOW}💡 OPENCLASH:{C.RESET}")
        print(f"   1. {C.BOLD}{cfg_name}{C.RESET} → {C.BOLD}/etc/openclash/config/{C.RESET}")
        print(f"   2. folder {C.BOLD}proxy_provider/{C.RESET} & {C.BOLD}rule_provider/{C.RESET} → {C.BOLD}/etc/openclash/{C.RESET}")
    if plat == "box":
        bx = _import_tool("boxutil")
        if bx and bx.can_use_root() and ask_yn(f"\n{C.YELLOW}Pasang ke Box sekarang (root)? (y/N) ❯{C.RESET} "):
            box_install_flow(out_dir, operator)
            return
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: Regenerate dari node tersimpan
# =====================================================================
def stored_node_sources():
    """Provider hasil generate yang berisi node → list[(label, path, pid, target_name, nodes)]."""
    out = []
    for label, fn in provider_files():
        pid, name = label.split("/", 1)[0], os.path.basename(label)
        if name not in USER_NODE_FILES:      # free.yaml / subs.yaml bukan hasil convert pengguna
            continue
        nodes = load_provider_nodes(fn)
        if nodes:
            out.append((label, fn, pid, name, nodes))
    return out


def source_operator(label):
    """'nikki/xl/active.yaml' -> 'xl'; 'nikki/active.yaml' (lama, tanpa operator) -> None."""
    parts = label.split("/")
    return parts[1] if len(parts) == 3 else None


def regenerate_all(sources):
    """Bangun ulang config tiap platform dari node tersimpan, dengan pilihan baku
    (rule-provider & secret ikut template, profil ISP dari settings.json). Return list[(label, notes, issues, error)]."""
    results = []
    for label, _, pid, name, nodes in sources:
        op = source_operator(label)
        _, notes, issues, error = setup_full_config(nodes, name, pid, "template", "replace", "template", None, op)
        results.append((label, notes, issues, error))
    return results


def feature_regenerate():
    clear_screen(); banner(); section("Regenerate dari Node Tersimpan")
    sources = stored_node_sources()
    if not sources:
        warn("Belum ada node tersimpan di hasil/. Buat dulu lewat Convert → URI ➜ Clash.")
        pause(); return
    print(f"  {C.DIM}Membangun ulang config (<operator>.yaml) + ruleset dari node yang sudah ada — tanpa paste URI lagi.")
    print(f"  Berguna setelah mengubah template, DNS, profil ISP, atau emoji/secret.{C.RESET}\n")
    for i, (label, fn, _, _, nodes) in enumerate(sources, 1):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(fn)))
        print(f"  {C.CYAN}[{i}]{C.RESET} {label:<22} {len(nodes):>3} node  {C.DIM}(diubah {when}){C.RESET}")
    print(f"  {C.CYAN}[A]{C.RESET} Semua di atas {C.DIM}(pilihan baku: rule-provider & secret ikut template, operator dari folder asal){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
    pick = ask_choice(f"{C.YELLOW}Pilih ❯{C.RESET} ", [str(i) for i in range(1, len(sources) + 1)] + ["a"], cancel=("0", ""))
    if pick in ("", "0"):
        return
    if pick == "a":
        print(); spinner("Membangun ulang semua config", 0.5)
        for label, notes, issues, error in regenerate_all(sources):
            if error:
                err(f"{label}: {error}")
                continue
            ok(f"{label}")
            for n in notes:
                print(f"  {C.DIM}• {n}{C.RESET}")
            print_issues(issues)
        pause("Tekan Enter untuk kembali ke menu...")
        return
    label, fn, pid, name, nodes = sources[int(pick) - 1]
    work = [dict(n) for n in nodes]
    while True:
        print(f"\n  {C.DIM}{len(work)} node dari {label}. Enter = tetap di platform/provider yang sama; "
              f"pilih platform lain untuk menyalin node ke sana.{C.RESET}")
        print(f"  {C.CYAN}[U]{C.RESET} Uji bug / custom SNI · Host · Address dulu   "
              f"{C.GREEN}[L]{C.RESET} Lanjut   {C.RED}[B]{C.RESET} Batal")
        aksi = ask_choice(f"{C.YELLOW}Pilih (Enter = L) ❯{C.RESET} ", ("u", "l", "b"), default="l")
        if aksi == "l":
            break
        if aksi == "b":
            return
        if aksi == "u":
            res = feature_bugtest(work)
            if res:
                work = [n for i, n in enumerate(work) if i not in res["drop"]] + res["nodes"]
                clear_screen(); banner(); section("Regenerate dari Node Tersimpan")
                ok(f"{len(res['nodes'])} varian ditambahkan" + (f", {len(res['drop'])} node asli diganti" if res["drop"] else ""))
    _generate_and_report(work, apply_emoji(work), default_plat=pid, default_target=name,
                         source_path=fn, node_label="node dipakai ulang", default_operator=source_operator(label))


# =====================================================================
#  Feature: Clash -> URI
# =====================================================================
def provider_files():
    """Semua file provider hasil generate (hasil/full_config_*/proxy*/*.yaml)."""
    found = []
    for pid, P in PLATFORMS.items():
        d = os.path.join(BASE_DIR, P["out"], P["proxy_dir"])
        for fn in sorted(glob.glob(os.path.join(d, "*.y*ml"))):
            found.append((f"{pid}/{os.path.basename(fn)}", fn))
        for fn in sorted(glob.glob(os.path.join(d, "*", "*.y*ml"))):       # proxy/<operator>/active.yaml
            found.append((f"{pid}/{os.path.basename(os.path.dirname(fn))}/{os.path.basename(fn)}", fn))
    return found


def feature_convert_to_uri():
    clear_screen(); banner(); section("Convert Clash ke URI")
    print(f"  {C.CYAN}[1]{C.RESET} Paste Teks YAML langsung")
    print(f"  {C.CYAN}[2]{C.RESET} Baca dari file hasil generate (hasil/full_config_*/)")
    print(f"  {C.CYAN}[0]{C.RESET} Batal")
    print(sep(50))
    pilihan = ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
    yaml_text = ""

    if pilihan == "1":
        print(f"\n  {C.DIM}Paste isi YAML. Ketik 'selesai' di baris baru untuk memproses.{C.RESET}")
        print(sep(50) + "\n")
        buf = []
        while True:
            try:
                s = input()
            except EOFError:
                break
            if s.strip().lower() == "selesai":
                break
            buf.append(s)
        yaml_text = "\n".join(buf)
    elif pilihan == "2":
        print(); section("Pilih File")
        files = provider_files()
        if not files:
            err("Belum ada file provider hasil generate."); pause(); return
        for i, (label, _) in enumerate(files, 1):
            print(f"  {C.CYAN}[{i}]{C.RESET} {label}")
        print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
        while True:
            idx = ask(f"{C.YELLOW}Pilih nomor file ❯{C.RESET} ").strip()
            if idx == "0":
                return
            if idx.isdigit() and 1 <= int(idx) <= len(files):
                yaml_text = read_text(files[int(idx) - 1][1]); break
            err("Pilihan tidak valid.")
    else:
        return

    try:
        data = yaml.safe_load(yaml_text)
        if isinstance(data, dict) and "proxies" in data:
            proxies = data["proxies"]
        elif isinstance(data, list):
            proxies = data
        else:
            raise ValueError("Format YAML tidak dikenali.")
    except Exception as e:
        err(f"Gagal parse YAML: {e}"); pause(); return
    if not proxies:
        warn("Tidak ada node di dalam file tersebut."); pause(); return

    spinner("Mengkonversi ke URI...", 0.4)
    uris, gagal = [], []
    for p in proxies:
        try:
            u = build_uri_from_proxy(p)
            (uris.append(u) if u else gagal.append(str(p.get("name", "?"))))
        except Exception:
            gagal.append(str(p.get("name", "?")) if isinstance(p, dict) else "?")
    if not uris:
        err("Gagal konversi semua node. Pastikan tipe-nya VLESS/VMess/Trojan."); pause(); return

    clear_screen(); banner()
    section(f"Hasil Konversi ({len(uris)} Valid, {len(gagal)} Gagal)")
    for i, u in enumerate(uris, 1):
        print(f"  {C.DIM}[{i}]{C.RESET} {C.CYAN}{u}{C.RESET}\n")
    if gagal:
        warn("Dilewati (tipe tidak didukung): " + ", ".join(truncate(g, 24) for g in gagal))
    print(sep(50))
    if ask_yn("  Simpan ke file? (y/N) ❯ "):
        os.makedirs(BASE_DIR, exist_ok=True)
        out_path = os.path.join(BASE_DIR, f"URI_{time.strftime('%d%m%Y_%H%M%S')}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(uris) + "\n")
        ok(f"Tersimpan di: {out_path}")
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: Status
# =====================================================================
def feature_check_status():
    clear_screen(); banner(); section("Status Sistem & Konfigurasi")
    tpl = find_template()
    print(f"  {C.DIM}Template & Ruleset:{C.RESET}")
    if tpl:
        ok(f"template      : {C.GREEN}{os.path.relpath(tpl, SCRIPT_DIR)}{C.RESET} {C.DIM}(versi {template_version(tpl) or 'tidak diketahui'}){C.RESET}")
        masters = list_master_templates()
        if masters and os.path.abspath(tpl) == os.path.abspath(TEMPLATE_PATH):
            latest = template_version(masters[-1])
            if latest and template_version(tpl) != latest:
                warn(f"template.yaml (salinan kerja) belum sama dengan master terbaru v{latest} — pakai Edit Configuration → Ganti File Template kalau mau memperbarui")
        try:
            cfg = load_template_cfg(tpl)
            print(f"    - Mixed port : {C.CYAN}{cfg.get('mixed-port', '-')}{C.RESET}")
            print(f"    - Secret     : {C.CYAN}{cfg.get('secret') or '(kosong)'}{C.RESET}")
            print(f"    - DNS        : {C.CYAN}{', '.join(map(str, (cfg.get('dns') or {}).get('nameserver', [])))}{C.RESET}")
        except Exception as e:
            err(f"template tidak bisa dibaca: {e}")
    else:
        err("template      : tidak ada")
    ecfg = load_emoji_cfg()
    ok(f"profil ISP    : {C.GREEN}{ISP_PROFILES[load_settings()['isp']]['label']}{C.RESET}")
    ok(f"emoji node    : {C.GREEN}{'ON' if ecfg['enabled'] else 'OFF'}{C.RESET} ({len(ecfg['emojis'])} emoji)")
    if EMOJI_WARNING:
        warn(EMOJI_WARNING)
    n_rs = len(os.listdir(RULESET_SOURCE)) if os.path.isdir(RULESET_SOURCE) else 0
    (ok(f"folder ruleset: {C.GREEN}{n_rs} file{C.RESET}") if n_rs else err("folder ruleset: tidak ada"))

    print(f"\n  {C.DIM}Provider Node:{C.RESET}")
    files = provider_files()
    if not files:
        warn("Belum ada file provider.")
    for label, fp in files:
        try:
            data = yaml.safe_load(read_text(fp))
            count = len(data.get("proxies") or []) if isinstance(data, dict) else 0
            print(f"  {C.GREEN}✓{C.RESET} {label:<24}: {C.BOLD}{count}{C.RESET} node")
        except Exception:
            print(f"  {C.RED}✗{C.RESET} {label:<24}: {C.RED}Format Error{C.RESET}")

    print(f"\n  {C.DIM}Status Full Config:{C.RESET}")
    for pid, P in PLATFORMS.items():
        files = [os.path.basename(f) for f in generated_config_files(pid)]
        (print(f"  {C.GREEN}✓{C.RESET} {P['label']:<24}: {C.GREEN}Siap{C.RESET} {C.DIM}({', '.join(files)}){C.RESET}") if files
         else print(f"  {C.GRAY}-{C.RESET} {P['label']:<24}: {C.DIM}Belum ada{C.RESET}"))
    print(f"\n  {C.DIM}Path Output:{C.RESET}\n  {C.CYAN}{BASE_DIR}{C.RESET}")
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: Validasi
# =====================================================================
def feature_validate():
    clear_screen(); banner(); section("Validasi / Audit Config")
    tpl = find_template()
    if not tpl:
        err("Template tidak ditemukan."); pause(); return
    print(f"  {C.DIM}Template: {os.path.basename(tpl)}{C.RESET}\n")
    text = read_text(tpl)
    for pid, P in PLATFORMS.items():
        print(f"{C.BOLD}{P['label']}{C.RESET}")
        try:
            cfg, _ = build_config(text, pid)
            out_dir = os.path.join(BASE_DIR, P["out"])
            issues = validate_config(cfg, pid, out_dir if os.path.isdir(out_dir) else None)
            print_issues(issues)
        except Exception as e:
            err(f"gagal build: {e}")
        print()
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: DNS & Nameserver
# =====================================================================
# Tiap preset: protokol terenkripsi untuk nameserver/fallback + IP polos untuk field yang butuh IP
# (default-nameserver WAJIB IP; proxy/direct-nameserver sebaiknya IP polos).
DNS_PRESETS = {
    # Sumber: https://github.com/bebasid/bebasdns (MIT). Hanya DoH & DoT; tidak ada DoQ.
    "1": {"label": "BebasDNS (BebasID, Indonesia) — default",
          "fallback_secure": {"doh": ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
                              "dot": ["tls://1.1.1.1", "tls://dns.google"]},
          "variants": {
              "1": ("Bawaan",                       {"doh": ["https://dns.bebasid.com/dns-query"],
                                                     "dot": ["tls://dns.bebasid.com"]}),
              "2": ("Security (anti-malware)",      {"doh": ["https://security.dns.bebasid.com/dns-query"],
                                                     "dot": ["tls://security.dns.bebasid.com"]}),
              "3": ("Unfiltered (tanpa disaring)",  {"doh": ["https://unfiltered.dns.bebasid.com/dns-query"],
                                                     "dot": ["tls://unfiltered.dns.bebasid.com"]}),
              "4": ("Family (internet sehat)",      {"doh": ["https://family.dns.bebasid.com/dns-query"],
                                                     "dot": ["tls://family.dns.bebasid.com"]}),
          },
          # BebasDNS tidak punya IP polos publik (plain DNS hanya untuk range IP terdaftar) -> IP bootstrap provider lain
          "plain": ["1.1.1.1", "8.8.8.8"],
          "plain_note": "BebasDNS tidak menyediakan IP polos publik → field IP (default/proxy-server/direct-nameserver) diisi 1.1.1.1 & 8.8.8.8. "
                        "Kalau ISP-mu memblokir domain DoH/DoT BebasDNS, minta domain alternatif ke dukungan@bebasid.com."},
    "2": {"label": "Cloudflare + Google",
          "doh": ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
          "dot": ["tls://1.1.1.1", "tls://dns.google"],
          "plain": ["1.1.1.1", "8.8.8.8"]},
    "3": {"label": "Quad9 Unsecured (tanpa filter)",
          "doh": ["https://dns10.quad9.net/dns-query"],
          "dot": ["tls://dns10.quad9.net"],
          "plain": ["9.9.9.10", "149.112.112.10"]},
    "4": {"label": "NextDNS (pakai ID sendiri)", "nextdns": True,
          "plain": ["1.1.1.1", "8.8.8.8"]},
    "5": {"label": "AdGuard DNS (filter iklan)",
          "doh": ["https://dns.adguard-dns.com/dns-query"],
          "dot": ["tls://dns.adguard-dns.com"],
          "doq": ["quic://dns.adguard-dns.com"],
          "plain": ["94.140.14.14", "94.140.15.15"]},
}
PROTO_LABEL = {"doh": "DoH  (https://)", "dot": "DoT  (tls://)", "doq": "DoQ  (quic://)"}

DNS_FIELDS = [
    ("nameserver", "DNS utama (domain non-direct)", "enkripsi (DoH/DoT/DoQ) disarankan"),
    ("proxy-server-nameserver", "resolve domain SERVER proxy", "IP polos disarankan (DoH sering di-reset ISP)"),
    ("default-nameserver", "bootstrap untuk host DoH/DoT/DoQ", "WAJIB berupa IP"),
    ("direct-nameserver", "DNS trafik DIRECT", "bebas"),
    ("fallback", "DNS cadangan", "dibuat + fallback-filter geoip:false kalau belum ada"),
]
SECURE_KINDS = {"DoH", "DoH3", "DoT", "DoQ"}
DNS_FORMAT_HELP = [
    ("1.1.1.1  /  8.8.8.8:53  /  2606:4700:4700::1111", "UDP polos (IP, port opsional)"),
    ("https://dns.google/dns-query", "DoH   (juga h3:// untuk DoH over HTTP/3)"),
    ("tls://1.1.1.1  /  tls://dns.google:853", "DoT"),
    ("quic://dns.adguard-dns.com", "DoQ"),
    ("udp://1.1.1.1  /  tcp://1.1.1.1:53", "UDP / TCP eksplisit"),
    ("system  /  dhcp://wlan0", "DNS bawaan sistem / dari DHCP interface"),
    ("https://1.1.1.1/dns-query#🧩 Inject", "akhiran #… = lewat proxy-group / interface / parameter (mis. #h3=true)"),
]

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$")
_SCHEME_KIND = {"https": "DoH", "h3": "DoH3", "tls": "DoT", "quic": "DoQ", "udp": "UDP", "tcp": "TCP"}


def _is_ip_str(x):
    import ipaddress
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def _split_host_port(hp):
    """'host', 'host:port', '[v6]:port', 'v6' -> (host, is_ip, error)."""
    if not hp:
        return "", False, "host kosong"
    host, port = hp, None
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d+))?$", hp)
    if m:
        host, port = m.group(1), m.group(2)
    elif hp.count(":") == 1:
        host, _, port = hp.partition(":")
    elif hp.count(":") > 1 and not _is_ip_str(hp):
        return "", False, "IPv6 tidak valid"
    if port is not None and not (port.isdigit() and 1 <= int(port) <= 65535):
        return "", False, f"port '{port}' tidak valid (1-65535)"
    if _is_ip_str(host):
        return host, True, None
    if not _HOST_RE.match(host):
        return "", False, f"host '{host}' tidak valid"
    return host, False, None


def parse_dns_entry(raw):
    """Validasi satu entri nameserver Mihomo. Return (nilai_siap_pakai, jenis, host_adalah_ip, error|None)."""
    s = str(raw).strip().strip("'\"")
    if not s:
        return None, None, False, "kosong"
    base, hashmark, params = s.partition("#")
    if re.search(r"\s", base):          # spasi hanya boleh di akhiran #… (mis. nama group "🧩 Inject")
        return None, None, False, "tidak boleh ada spasi (pisahkan entri dengan koma atau baris baru)"
    if hashmark and not params:
        return None, None, False, "setelah '#' kosong"
    suffix = hashmark + params
    if base.lower() == "system":
        return "system" + suffix, "system", False, None
    m = re.match(r"^([A-Za-z0-9]+)://(.*)$", base)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        if scheme == "dhcp":
            return (f"dhcp://{rest}{suffix}", "DHCP", False, None) if rest else \
                (None, None, False, "dhcp:// butuh nama interface atau 'system'")
        if scheme not in _SCHEME_KIND:
            return None, None, False, f"skema '{scheme}://' tidak dikenal (https, h3, tls, quic, udp, tcp, dhcp, system)"
        hostport, slash, path = rest.partition("/")
        host, is_ip, e = _split_host_port(hostport)
        if e:
            return None, None, False, e
        if slash and scheme not in ("https", "h3"):
            return None, None, False, f"path hanya untuk https:// / h3:// (bukan {scheme}://)"
        return f"{scheme}://{hostport}{slash}{path}{suffix}", _SCHEME_KIND[scheme], is_ip, None
    if "/" in base:
        return None, None, False, "ada path tapi tanpa skema — maksudnya https://" + base + " ?"
    host, is_ip, e = _split_host_port(base)
    if e:
        return None, None, False, e
    return base + suffix, "UDP" if is_ip else "UDP (domain)", is_ip, None


def check_dns_field(field, parsed):
    """parsed: [(nilai, jenis, is_ip)] -> list[(level, pesan)] untuk field `field`."""
    out = []
    kinds = {k for _, k, _ in parsed}
    if field == "default-nameserver":
        for v, _, is_ip in parsed:
            if not is_ip:
                out.append(("ERR", f"default-nameserver harus IP, bukan '{v}'"))
    elif field in ("nameserver", "fallback"):
        plain = [v for v, k, _ in parsed if k not in SECURE_KINDS]
        if plain:
            out.append(("WARN", f"{field}: DNS tidak terenkripsi ({', '.join(plain)}) → bisa bocor ke ISP"))
    elif field == "proxy-server-nameserver":
        if parsed and kinds <= SECURE_KINDS:
            out.append(("WARN", "proxy-server-nameserver terenkripsi semua (sengaja di Mode Anti-Blokir / v0.7): kalau ISP me-reset DoH/DoT, "
                                "domain server proxy gagal resolve (semua node timeout) → balikkan ke IP polos lewat Custom manual"))
    return out


def block_ensure_key_block(content, block, key, child_lines):
    """Pastikan sub-blok `key:` ada di dalam blok level-atas `block`; kalau belum, tambahkan di akhir blok."""
    lines = content.split("\n")
    b = _block_bounds(lines, block)
    if not b:
        return content, False
    s, e = b
    if any(re.match(rf"^\s+{re.escape(key)}:", lines[i]) for i in range(s + 1, e)):
        return content, True
    last = e
    while last > s + 1 and not lines[last - 1].strip():
        last -= 1
    ci = next((re.match(r"^(\s+)\S", l).group(1) for l in lines[s + 1:e] if l.strip() and not l.strip().startswith("#")), "  ")
    lines[last:last] = [f"{ci}{key}:"] + [f"{ci}  {l}" for l in child_lines]
    return "\n".join(lines), True


def _yaml_item(x):
    """Quote item kalau YAML akan menafsirkannya bukan sebagai string yang sama (mis. '[::1]:53', '#', ': ')."""
    try:
        if yaml.safe_load(x) == x:
            return x
    except yaml.YAMLError:
        pass
    return yaml_quote(x)


def _dns_kind_tag(entry):
    v, kind, is_ip, e = parse_dns_entry(entry)
    return kind or "?"


def _show_dns_state(dns):
    print(f"  {C.DIM}DNS aktif di template:{C.RESET}")
    for key, desc, _ in DNS_FIELDS:
        vals = dns.get(key)
        if vals is None and key == "fallback":
            continue
        print(f"  {C.CYAN}{key}{C.RESET} {C.DIM}— {desc}{C.RESET}")
        if not vals:
            print(f"      {C.DIM}(kosong){C.RESET}")
        for v in vals or []:
            print(f"      {v}  {C.DIM}[{_dns_kind_tag(v)}]{C.RESET}")


def _pick_dns_fields(dns, default):
    """Pilih field target (boleh banyak, mis. 1,3). Return list nama field / None."""
    fields = list(DNS_FIELDS)
    print(); section("Terapkan ke field mana?")
    for i, (key, desc, hint) in enumerate(fields, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {key:<24} {C.DIM}{desc} · {hint}{C.RESET}")
    dflt = ",".join(str(i) for i, f in enumerate(fields, 1) if f[0] in default)
    raw = ask(f"{C.YELLOW}Nomor, pisah koma (Enter={dflt or '-'}, 0=batal) ❯{C.RESET} ").strip() or dflt
    if raw == "0":
        return None
    try:
        idx = sorted({int(x) for x in raw.replace(" ", "").split(",") if x})
        return [fields[i - 1][0] for i in idx if 1 <= i <= len(fields)] or None
    except ValueError:
        err("Input tidak valid."); time.sleep(1.2)
        return None


def _collect_custom_entries(field):
    """Baca entri bebas format. Return list nilai valid (urut, unik) / None kalau batal."""
    print(); section(f"Entri untuk {field}")
    for ex, desc in DNS_FORMAT_HELP:
        print(f"  {C.CYAN}{ex}{C.RESET}\n      {C.DIM}{desc}{C.RESET}")
    print(f"  {C.DIM}Satu per baris atau pisah koma/spasi. Enter kosong = selesai, 'batal' = keluar.{C.RESET}")
    got = []
    while True:
        line = ask(f"  {C.CYAN}❯{C.RESET} ").strip()
        if not line:
            break
        if line.lower() == "batal":
            return None
        toks = []
        for part in line.split(","):
            part = part.strip()
            toks += [part] if "#" in part else part.split()      # spasi memisahkan entri, kecuali di akhiran #…
        for tok in toks:
            v, kind, _, e = parse_dns_entry(tok)
            if e:
                err(f"{tok} → {e}")
            elif v in got:
                warn(f"{v} sudah ada, dilewati")
            else:
                got.append(v)
                ok(f"{v}  {C.DIM}[{kind}]{C.RESET}")
    return got


def _apply_dns_changes(path, content, dns, changes):
    """changes: {field: [entri]}. Preview → validasi → konfirmasi → tulis. Return True kalau tersimpan."""
    print(); section("Ringkasan Perubahan")
    blocking = False
    for field, new in changes.items():
        print(f"  {C.CYAN}{field}{C.RESET}")
        for v in dns.get(field) or []:
            print(f"    {C.RED}- {v}{C.RESET}")
        for v in new:
            print(f"    {C.GREEN}+ {v}{C.RESET}")
        parsed = []
        for v in new:
            pv, kind, is_ip, e = parse_dns_entry(v)
            parsed.append((pv, kind, is_ip))
        for lvl, msg in check_dns_field(field, parsed):
            (err if lvl == "ERR" else warn)(msg)
            blocking |= lvl == "ERR"
        if field == "fallback" and not dns.get("fallback-filter"):
            print(f"    {C.GREEN}+ fallback-filter: geoip: false{C.RESET}")
    if blocking:
        err("Ada kesalahan di atas — perubahan dibatalkan."); pause(); return False
    if not ask_yn(f"\n  Terapkan? (y/N) ❯ "):
        return False
    new_text = content
    for field, new in changes.items():
        new_text, found = block_set_list(new_text, "dns", field, new)
        if not found:
            err("Blok dns tidak ditemukan di template."); pause(); return False
    if "fallback" in changes and not dns.get("fallback-filter"):
        new_text, _ = block_ensure_key_block(new_text, "dns", "fallback-filter", ["geoip: false"])
    try:
        back = (yaml.safe_load(new_text) or {}).get("dns") or {}
    except yaml.YAMLError as e:
        err(f"Hasil edit tidak valid, dibatalkan: {e}"); pause(); return False
    for field, new in changes.items():
        if [str(x) for x in back.get(field) or []] != new:
            err(f"Verifikasi gagal untuk {field} (hasil baca ulang tidak sama), dibatalkan."); pause(); return False
    backup_file(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
    ok(f"DNS diterapkan ke {os.path.relpath(path, SCRIPT_DIR)} (backup: {os.path.basename(path)}.bak)")
    print(f"  {C.DIM}Aktif saat generate Full Config berikutnya.{C.RESET}")
    pause()
    return True


def _dns_preset_flow(path, content, dns):
    print(); section("Preset Provider DNS")
    for k, p in DNS_PRESETS.items():
        print(f"  {C.CYAN}[{k}]{C.RESET} {p['label']}")
    print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
    k = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
    if k not in DNS_PRESETS:
        if k not in ("", "0"):
            err("Pilihan tidak valid."); time.sleep(1.0)
        return
    p = DNS_PRESETS[k]
    if p.get("variants"):
        print(); section(f"Varian {p['label'].split(' (')[0]}")
        for vk, (vlabel, _) in p["variants"].items():
            print(f"  {C.CYAN}[{vk}]{C.RESET} {vlabel}")
        vk = ask(f"{C.YELLOW}Pilih (Enter=1) ❯{C.RESET} ").strip() or "1"
        if vk not in p["variants"]:
            err("Pilihan tidak valid."); time.sleep(1.0); return
        p = dict(p, **p["variants"][vk][1])
    if p.get("nextdns"):
        nid = ask("  NextDNS ID (kosong = tanpa ID) ❯ ").strip().strip("/")
        if nid and not re.fullmatch(r"[A-Za-z0-9]+", nid):
            err("ID NextDNS hanya huruf/angka."); time.sleep(1.2); return
        suf = f"/{nid}" if nid else ""
        p = dict(p, doh=[f"https://dns.nextdns.io{suf}"], dot=[f"tls://{nid + '.' if nid else ''}dns.nextdns.io"],
                 doq=[f"quic://dns.nextdns.io{suf}"])
    protos = [x for x in ("doh", "dot", "doq") if p.get(x)]
    print(); section("Protokol (untuk nameserver / fallback)")
    for i, x in enumerate(protos, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {PROTO_LABEL[x]}")
    pr = ask(f"{C.YELLOW}Pilih (Enter=1) ❯{C.RESET} ").strip() or "1"
    if not (pr.isdigit() and 1 <= int(pr) <= len(protos)):
        err("Pilihan tidak valid."); time.sleep(1.0); return
    secure, plain = p[protos[int(pr) - 1]], p["plain"]
    print(f"\n  {C.DIM}Isi per field: nameserver/fallback ← {', '.join(secure)}")
    print(f"  default/proxy-server/direct-nameserver ← IP polos {', '.join(plain)}{C.RESET}")
    if p.get("plain_note"):
        warn(p["plain_note"])
    fb_secure = (p.get("fallback_secure") or {}).get(protos[int(pr) - 1], secure)
    if p.get("fallback_secure") and "fallback" in dns:
        print(f"  {C.DIM}fallback ← {', '.join(fb_secure)}  (jika DNS utama gagal){C.RESET}")
    fields = _pick_dns_fields(dns, default={"nameserver", "fallback"} if p.get("fallback_secure") else {"nameserver"})
    if not fields:
        return
    changes = {f: (secure if f == "nameserver" else fb_secure if f == "fallback" else plain) for f in fields}
    _apply_dns_changes(path, content, dns, changes)


def _dns_custom_flow(path, content, dns):
    fields = _pick_dns_fields(dns, default={"nameserver"})
    if not fields:
        return
    changes = {}
    for field in fields:
        entries = _collect_custom_entries(field)
        if entries is None:
            return
        if not entries:
            warn(f"{field}: tidak ada entri, dilewati."); continue
        if dns.get(field):
            print(f"  {C.CYAN}[1]{C.RESET} Ganti semua   {C.CYAN}[2]{C.RESET} Tambahkan ke yang lama  {C.DIM}({len(dns[field])} entri sekarang){C.RESET}")
            if ask_choice(f"{C.YELLOW}{field} (Enter=1) ❯{C.RESET} ", ("1", "2"), default="1") == "2":
                entries = list(dict.fromkeys([str(x) for x in dns[field]] + entries))
        changes[field] = entries
    if changes:
        _apply_dns_changes(path, content, dns, changes)


def _dns_isp_flow():
    st = load_settings()
    print(); section("Profil ISP")
    print(f"  {C.DIM}Sekarang: {ISP_PROFILES[st['isp']]['label']}"
          + (f" → {', '.join(st['isp_fields'] or ISP_PROFILES[st['isp']]['fields'])}" if st["isp"] != "none" else "") + C.RESET)
    print(f"  {C.CYAN}[1]{C.RESET} Umum {C.DIM}(tanpa DNS ISP — paling aman untuk dnsleak){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} XL Axiata {C.DIM}(+{', '.join(ISP_PROFILES['xl']['ips'])}){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
    pick = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
    if pick not in ("1", "2"):
        return
    if pick == "1":
        save_settings({"isp": "none", "isp_fields": []})
        ok("Profil ISP: Umum."); time.sleep(1.0); return
    prof = ISP_PROFILES["xl"]
    cur = st["isp_fields"] if st["isp"] == "xl" and st["isp_fields"] else prof["fields"]
    print(); section("IP XL ditambahkan ke field mana?")
    for i, f in enumerate(ISP_FIELD_CHOICES, 1):
        mark = "✓" if f in cur else " "
        print(f"  {C.CYAN}[{i}]{C.RESET} [{mark}] {f}")
    print(f"  {C.DIM}Default: default-nameserver + proxy-server-nameserver (hanya resolve host DoH & domain server proxy,")
    print(f"  tidak melihat domain yang kamu buka → dnsleak tetap bersih). Template v0.2 dulu juga memakai fallback;")
    print(f"  kalau tunneling masih gagal, tambahkan fallback — konsekuensinya DNS XL ikut terlihat di dnsleak.{C.RESET}")
    raw = ask(f"{C.YELLOW}Nomor, pisah koma (Enter = default) ❯{C.RESET} ").strip()
    fields = list(prof["fields"])
    if raw:
        try:
            idx = sorted({int(x) for x in raw.replace(" ", "").split(",") if x})
            fields = [ISP_FIELD_CHOICES[i - 1] for i in idx if 1 <= i <= len(ISP_FIELD_CHOICES)]
        except ValueError:
            err("Input tidak valid."); time.sleep(1.2); return
    if not fields:
        err("Pilih minimal satu field."); time.sleep(1.2); return
    if "fallback" in fields:
        warn("fallback berisi DNS XL (tidak terenkripsi): DNS ISP bisa muncul di dnsleak test.")
    save_settings({"isp": "xl", "isp_fields": fields})
    ok(f"Profil ISP: XL Axiata → {', '.join(fields)}")
    print(f"  {C.DIM}Berlaku saat generate untuk Nikki & OpenClash (Box tidak diubah). Tersimpan di settings.json.{C.RESET}")
    pause()


ANTIBLOKIR_DNS = {
    # Semua DoH berbasis IP: tidak butuh bootstrap DNS dan tidak memakai port 53 yang bisa dibelokkan ISP.
    "nameserver":              ["https://1.1.1.1/dns-query"],
    "fallback":                ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
    "proxy-server-nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
    "direct-nameserver":       ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
}


def antiblokir_changes(dns, keep_proxy_server_plain=False):
    """Perubahan DNS untuk Mode Anti-Blokir: hanya field yang memang berbeda dari target."""
    target = dict(ANTIBLOKIR_DNS)
    if keep_proxy_server_plain:
        target.pop("proxy-server-nameserver")
    return {k: v for k, v in target.items() if [str(x) for x in dns.get(k) or []] != v}


def _dns_antiblokir_flow(path, content, dns):
    print(); section("Mode Anti-Blokir (Internet Positif)")
    print(f"  {C.DIM}Semua resolver jadi DoH berbasis IP (Cloudflare/Google) — tidak ada query DNS polos port 53.")
    print(f"  Alasan: ISP bisa membelokkan DNS polos di jalur DIRECT ke resolver sensor. Domain yang lewat proxy")
    print(f"  sudah aman lewat fake-ip (nama domain dikirim ke node, bukan di-resolve ISP).")
    print(f"  Tidak mengubah rule/rute, dan tidak bisa memperbaiki node yang server-nya sendiri diblokir.{C.RESET}")
    print(f"\n  {C.CYAN}[1]{C.RESET} Semua DoH {C.DIM}(disarankan){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Semua DoH, kecuali proxy-server-nameserver tetap apa adanya {C.DIM}(pilih ini kalau node timeout){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
    k = ask_choice(f"{C.YELLOW}Pilih (Enter=1) ❯{C.RESET} ", ("1", "2"), default="1", cancel=("0",))
    if k not in ("1", "2"):
        return
    changes = antiblokir_changes(dns, keep_proxy_server_plain=(k == "2"))
    if not changes:
        ok("DNS sudah mode Anti-Blokir."); time.sleep(1.2); return
    if load_settings()["isp"] == "xl":
        print(f"  {C.DIM}Profil XL aktif: IP XL tetap disuntik saat generate (Nikki/OpenClash), terpisah dari template.{C.RESET}")
    _apply_dns_changes(path, content, dns, changes)


def _dns_reset_flow(path, content, dns):
    masters = list_master_templates()
    if not masters:
        err("Tidak ada template master."); time.sleep(1.2); return
    try:
        mdns = load_template_cfg(masters[-1]).get("dns") or {}
    except Exception as e:
        err(f"Master tidak terbaca: {e}"); time.sleep(1.2); return
    changes = {k: [str(x) for x in mdns[k]] for k, _, _ in DNS_FIELDS
               if mdns.get(k) and [str(x) for x in mdns[k]] != [str(x) for x in dns.get(k) or []]}
    if not changes:
        ok("DNS sudah sama dengan master."); time.sleep(1.2); return
    print(f"  {C.DIM}Mengembalikan ke {os.path.basename(masters[-1])}{C.RESET}")
    _apply_dns_changes(path, content, dns, changes)


def feature_config_dns():
    while True:
        path = ensure_working_template()
        if not path:
            err("Template tidak ditemukan!"); time.sleep(1.5); return
        content = read_text(path)
        clear_screen(); banner(); section("DNS & Nameserver")
        try:
            dns = (yaml.safe_load(content) or {}).get("dns") or {}
        except yaml.YAMLError as e:
            err(f"Template rusak: {e}"); pause(); return
        _show_dns_state(dns)
        for key in ("nameserver", "fallback"):
            if any("://" not in str(x) for x in dns.get(key) or []):
                warn(f"Ada DNS polos (tanpa enkripsi) di {key} → rawan bocor ke ISP.")
        print(); section("Menu")
        print(f"  {C.CYAN}[1]{C.RESET} Preset provider   {C.DIM}(BebasDNS [default], Cloudflare/Google, Quad9, NextDNS, AdGuard · DoH/DoT/DoQ){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Custom manual     {C.DIM}(IP, DoH, DoT, DoQ, UDP/TCP, system, dhcp — per field){C.RESET}")
        print(f"  {C.CYAN}[3]{C.RESET} Kembalikan ke master")
        print(f"  {C.CYAN}[4]{C.RESET} Profil ISP         {C.DIM}(sekarang: {ISP_PROFILES[load_settings()['isp']]['label']}; XL Axiata → +112.215.203.254){C.RESET}")
        print(f"  {C.CYAN}[5]{C.RESET} Mode Anti-Blokir   {C.DIM}(semua resolver DoH berbasis IP — tanpa DNS polos port 53){C.RESET}")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        elif pilih == "5": _dns_antiblokir_flow(path, content, dns)
        elif pilih == "1": _dns_preset_flow(path, content, dns)
        elif pilih == "2": _dns_custom_flow(path, content, dns)
        elif pilih == "3": _dns_reset_flow(path, content, dns)
        elif pilih == "4": _dns_isp_flow()
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


# =====================================================================
#  Feature: Emoji Node
# =====================================================================
def _is_emoji_token(tok):
    return len(tok) <= 12 and any(ord(ch) > 127 for ch in tok)


def feature_edit_emoji():
    cfg = load_emoji_cfg()
    keys = list(DEFAULT_EMOJI_MAP)
    while True:
        clear_screen(); banner(); section("Emoji Node")
        state = f"{C.GREEN}ON{C.RESET}" if cfg["enabled"] else f"{C.RED}OFF{C.RESET}"
        print(f"  Status : {state}   {C.DIM}(emoji mengikuti metode node, bukan acak){C.RESET}\n")
        for i, k in enumerate(keys, 1):
            print(f"  {C.CYAN}[{i:>2}]{C.RESET} {cfg['methods'][k]:<3} {k:<13} {C.DIM}{EMOJI_METHOD_LABEL[k]}{C.RESET}")
        print(); print(sep(50))
        print(f"  {C.CYAN}[E]{C.RESET} Ubah emoji satu metode   {C.DIM}(nomor, lalu emoji baru){C.RESET}")
        print(f"  {C.CYAN}[T]{C.RESET} Nyala / Matikan fitur emoji")
        print(f"  {C.CYAN}[R]{C.RESET} Reset ke bawaan")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask_choice(f"{C.YELLOW}Pilih ❯{C.RESET} ", ("e", "t", "r", "0"))
        changed = True
        if pilih == "0":
            return
        elif pilih == "e":
            num = ask(f"  Nomor metode (1-{len(keys)}) ❯ ").strip()
            if not (num.isdigit() and 1 <= int(num) <= len(keys)):
                err("Nomor di luar daftar."); time.sleep(1.2); continue
            k = keys[int(num) - 1]
            new = ask(f"  Emoji baru untuk {k} ❯ ").strip()
            if not _is_emoji_token(new):
                err("Itu bukan emoji."); time.sleep(1.2); continue
            cfg["methods"][k] = new
        elif pilih == "t":
            cfg["enabled"] = not cfg["enabled"]
        elif pilih == "r":
            cfg = {"enabled": cfg["enabled"], "methods": dict(DEFAULT_EMOJI_MAP)}
        if changed:
            try:
                save_emoji_cfg(cfg)
            except OSError as e:
                err(f"Gagal menyimpan emoji.json: {e}"); time.sleep(1.5)


# =====================================================================
#  Feature: Edit Configuration
# =====================================================================
def feature_edit_config():
    while True:
        clear_screen(); banner(); section("Edit Configuration")
        print(f"  {C.CYAN}[1]{C.RESET} Edit Port & Secret")
        print(f"  {C.CYAN}[2]{C.RESET} Ganti File Template")
        print(f"  {C.CYAN}[3]{C.RESET} DNS & Nameserver")
        print(f"  {C.CYAN}[4]{C.RESET} Emoji Node (daftar emoji nama)")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilih == "0":
            break
        elif pilih == "1":
            path = ensure_working_template()
            if not path:
                err("Template belum ada!"); time.sleep(1.5); continue
            content = read_text(path)
            try:
                cfg = yaml.safe_load(content) or {}
            except yaml.YAMLError as e:
                err(f"Template rusak: {e}"); time.sleep(1.5); continue
            print(); section("Edit Port & Secret")
            print(f"  {C.DIM}Enter = tidak diubah. Ketik 'acak' di Secret untuk generate otomatis.{C.RESET}")
            new_port = ask(f"  Mixed Port baru (sekarang: {cfg.get('mixed-port', '-')}): ").strip()
            new_secret = ask(f"  Secret baru (sekarang: {cfg.get('secret') or 'kosong'}): ").strip()
            if new_port and not (new_port.isdigit() and 1 <= int(new_port) <= 65535):
                err("Port harus angka 1-65535."); time.sleep(1.5); continue
            if new_secret.lower() == "acak":
                new_secret = secrets.token_urlsafe(9); print(f"  Secret baru: {C.BOLD}{new_secret}{C.RESET}")
            if not (new_port or new_secret):
                warn("Tidak ada perubahan."); time.sleep(1.2); continue
            new = content
            if new_port:
                new, f = set_top_scalar(new, "mixed-port", new_port)
                if not f:
                    err("Key mixed-port tidak ada di template."); time.sleep(1.5); continue
            if new_secret:
                new, f = set_top_scalar(new, "secret", yaml_quote(new_secret))
                if not f:
                    err("Key secret tidak ada di template."); time.sleep(1.5); continue
            backup_file(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new)
            ok("Template berhasil diupdate!"); time.sleep(1.2)
        elif pilih == "2":
            print(); section("Ganti Template")
            masters = list_master_templates()
            for i, m in enumerate(masters, 1):
                print(f"  {C.CYAN}[{i}]{C.RESET} {os.path.basename(m)}")
            print(f"  {C.DIM}Pilih nomor, atau ketik path lengkap file template. Enter = batal.{C.RESET}")
            src = ask(f"  {C.CYAN}❯{C.RESET} ").strip()
            if src.isdigit() and 1 <= int(src) <= len(masters):
                src = masters[int(src) - 1]
            if not src:
                continue
            src = os.path.expanduser(src)
            if not os.path.isfile(src):
                err("File tidak ditemukan."); time.sleep(1.5); continue
            try:
                text = read_text(src)
                if not isinstance(yaml.safe_load(text), dict):
                    raise ValueError("bukan YAML mapping")
                if os.path.isfile(TEMPLATE_PATH):
                    backup_file(TEMPLATE_PATH)
                with open(TEMPLATE_PATH, "w", encoding="utf-8") as f:
                    f.write(text)
                ok("Template berhasil diganti!")
            except Exception as e:
                err(f"Gagal: {e}")
            time.sleep(1.5)
        elif pilih == "3":
            feature_config_dns()
        elif pilih == "4":
            feature_edit_emoji()


# =====================================================================
#  Feature: Miscellaneous (menu 5)
# =====================================================================
RULES_OUT_DIR = os.path.join(BASE_DIR, "rules")
RULE_EXTS = (".mrs", ".yaml", ".yml", ".txt")


def _import_tool(name):
    try:
        return __import__(name)
    except Exception as e:
        err(f"Modul {name}.py tidak bisa dimuat: {e}")
        return None


def _human_size(n):
    return f"{n / 1024:.1f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.2f} MB"


def _unique_dst(path):
    """Jangan menimpa diam-diam: kalau sudah ada, tanya timpa atau pakai nama baru."""
    if not os.path.exists(path):
        return path
    if ask_yn(f"  {os.path.basename(path)} sudah ada. Timpa? (y/N) ❯ "):
        return path
    stem, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{stem}_{i}{ext}"):
        i += 1
    return f"{stem}_{i}{ext}"


def _pick_file(files, prompt="Pilih nomor, atau ketik path file"):
    """files: [(label, path)]. Return path / None (batal)."""
    for i, (label, _) in enumerate(files, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {label}")
    print(f"  {C.DIM}{prompt}. Enter = batal.{C.RESET}")
    raw = ask(f"  {C.CYAN}❯{C.RESET} ").strip()
    if not raw:
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(files):
        return files[int(raw) - 1][1]
    path = os.path.expanduser(raw.strip("'\""))
    if os.path.isfile(path):
        return path
    err("File tidak ditemukan."); time.sleep(1.2)
    return None


def _ruleset_files():
    if not os.path.isdir(RULESET_SOURCE):
        return []
    out = []
    for fn in sorted(os.listdir(RULESET_SOURCE)):
        if fn.lower().endswith(RULE_EXTS):
            fp = os.path.join(RULESET_SOURCE, fn)
            out.append((f"{fn:<22} {C.DIM}{_human_size(os.path.getsize(fp))}{C.RESET}", fp))
    return out


def _print_convert_result(res):
    arrow = ".mrs ➜ teks" if res["direction"] == "mrs->text" else "teks ➜ .mrs"
    ok(f"{arrow}  |  behavior: {C.BOLD}{res['behavior']}{C.RESET}  |  {res['entries']:,} entri")
    print(f"  {C.DIM}{res['dst']}  ({_human_size(os.path.getsize(res['dst']))}){C.RESET}")
    for w in res["warnings"][:6]:
        warn(w)
    if len(res["warnings"]) > 6:
        print(f"  {C.DIM}... +{len(res['warnings']) - 6} peringatan lain{C.RESET}")


def _convert_one_rule(mrs):
    print(); section("Pilih File Sumber")
    src = _pick_file(_ruleset_files(), "Pilih nomor, atau ketik path .mrs / .yaml / .txt")
    if not src:
        return
    os.makedirs(RULES_OUT_DIR, exist_ok=True)
    stem = os.path.splitext(os.path.basename(src))[0]
    try:
        if src.lower().endswith(".mrs"):
            print(f"  {C.CYAN}[1]{C.RESET} YAML (payload:)   {C.CYAN}[2]{C.RESET} TXT (satu entri per baris)")
            as_text = ask_choice(f"{C.YELLOW}Format keluaran (1/2, Enter=1) ❯{C.RESET} ", ("1", "2"), default="1") == "2"
            dst = _unique_dst(os.path.join(RULES_OUT_DIR, stem + (".txt" if as_text else ".yaml")))
            res = mrs.convert_file(src, dst, text_out=as_text)
        else:
            with open(src, "r", encoding="utf-8") as f:
                raw = mrs.parse_rule_text(f.read())
            if not raw:
                err("Tidak ada entri di file itu."); return
            auto = mrs.detect_behavior(raw)
            print(f"  {C.DIM}{len(raw):,} baris terbaca, terdeteksi behavior: {auto}{C.RESET}")
            pick = ask(f"{C.YELLOW}Behavior (d=domain, i=ipcidr, Enter={auto}) ❯{C.RESET} ").strip().lower()
            behavior = {"d": "domain", "i": "ipcidr"}.get(pick, auto)
            dst = _unique_dst(os.path.join(RULES_OUT_DIR, stem + ".mrs"))
            spinner("Membangun .mrs", 0.4)
            res = mrs.convert_file(src, dst, behavior=behavior)
            back = mrs.read_mrs_bytes(open(dst, "rb").read())      # baca ulang = cek file tidak rusak
            if len(back["entries"]) != res["entries"]:
                res["warnings"].append(f"cek baca-ulang: {len(back['entries']):,} entri terbaca vs {res['entries']:,} ditulis")
        print(); _print_convert_result(res)
    except mrs.ZstdUnavailable as e:
        err(str(e))
    except (mrs.MrsError, OSError, ValueError, yaml.YAMLError) as e:
        err(f"Gagal: {e}")


def _convert_all_mrs(mrs):
    files = [(l, p) for l, p in _ruleset_files() if p.lower().endswith(".mrs")]
    if not files:
        warn("Tidak ada .mrs di ruleset/."); return
    os.makedirs(RULES_OUT_DIR, exist_ok=True)
    print(f"  {C.DIM}{len(files)} file .mrs → YAML di {RULES_OUT_DIR}{C.RESET}\n")
    for _, p in files:
        dst = os.path.join(RULES_OUT_DIR, os.path.splitext(os.path.basename(p))[0] + ".yaml")
        try:
            res = mrs.convert_file(p, dst)
            ok(f"{os.path.basename(p):<20} → {res['entries']:,} entri ({res['behavior']})")
        except mrs.ZstdUnavailable as e:
            err(str(e)); return
        except (mrs.MrsError, OSError, ValueError) as e:
            err(f"{os.path.basename(p)}: {e}")


def _info_mrs(mrs):
    print(); section("Pilih File .mrs")
    src = _pick_file([(l, p) for l, p in _ruleset_files() if p.lower().endswith(".mrs")],
                     "Pilih nomor, atau ketik path .mrs")
    if not src:
        return
    try:
        i = mrs.mrs_info(src)
        ok(f"behavior: {C.BOLD}{i['behavior']}{C.RESET}  |  entri: {i['entries']:,}  |  ukuran: {_human_size(i['size'])}")
    except mrs.ZstdUnavailable as e:
        err(str(e))
    except (mrs.MrsError, OSError) as e:
        err(f"Gagal: {e}")


def feature_misc_rules():
    mrs = _import_tool("mrs_codec")
    if not mrs:
        pause(); return
    while True:
        clear_screen(); banner("MISC"); section("Rule-Provider Converter")
        be = mrs.backend_name()
        print(f"  {C.DIM}zstd backend: {be or 'TIDAK ADA'}   |   output: {RULES_OUT_DIR}{C.RESET}")
        if not be:
            warn("Backend zstd belum ada, konversi .mrs tidak bisa jalan:\n" + mrs.INSTALL_HINT)
        print(f"\n  {C.CYAN}[1]{C.RESET} Konversi satu file  {C.DIM}(.mrs ⇄ .yaml / .txt, arah otomatis dari ekstensi){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Semua .mrs di ruleset/ ➜ YAML")
        print(f"  {C.CYAN}[3]{C.RESET} Info file .mrs  {C.DIM}(behavior, jumlah entri){C.RESET}")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        if pilih == "1":
            _convert_one_rule(mrs)
        elif pilih == "2":
            print(); _convert_all_mrs(mrs)
        elif pilih == "3":
            _info_mrs(mrs)
        else:
            err("Pilihan tidak valid."); time.sleep(0.8); continue
        pause()


# ---------- Config tester ----------
def generated_config_files(pid):
    """Semua config hasil generate satu platform (hasil/full_config_*/<operator>.yaml atau config.yaml)."""
    return sorted(glob.glob(os.path.join(BASE_DIR, PLATFORMS[pid]["out"], "*.y*ml")))


def _generated_configs():
    return [(pid, cp) for pid in PLATFORMS for cp in generated_config_files(pid)]


def _run_core_test(core, out_dir, cfg_path):
    import subprocess
    try:
        r = subprocess.run([core, "-t", "-d", out_dir, "-f", cfg_path], capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return False, "timeout 90 dtk (kemungkinan core mencoba download provider / jaringan lambat)"
    except OSError as e:
        return False, str(e)
    text = (r.stdout + r.stderr).strip().splitlines()
    return r.returncode == 0, "\n".join(text[-6:])


def feature_misc_config():
    clear_screen(); banner("MISC"); section("Config Tester")
    items = _generated_configs()
    if not items:
        err("Belum ada config hasil generate. Jalankan Convert dulu (menu 1)."); pause(); return
    mrs = _import_tool("mrs_codec")
    core = mrs.find_mihomo() if mrs else None
    print(f"  {C.DIM}Core Mihomo: {core or 'tidak ditemukan (hanya validator internal; set HIKARI_MIHOMO=/path/core untuk mengaktifkan tes core)'}{C.RESET}\n")
    for pid, cp in items:
        P = PLATFORMS[pid]
        print(f"{C.BOLD}{P['label']}{C.RESET}  {C.DIM}{os.path.relpath(cp, SCRIPT_DIR)}{C.RESET}")
        try:
            cfg = yaml.safe_load(read_text(cp))
            if not isinstance(cfg, dict):
                raise ValueError("bukan YAML mapping")
        except (OSError, ValueError, yaml.YAMLError) as e:
            err(f"YAML tidak terbaca: {e}\n"); continue
        print_issues(validate_config(cfg, pid, os.path.dirname(cp)))
        leaks = dns_leak_audit(cfg, pid)
        print(f"  {C.DIM}Audit DNS leak (statis):{C.RESET}")
        shown = False
        for lvl, msg in leaks:
            if lvl == "LEAK":
                err(msg)
            elif lvl == "WARN":
                warn(msg)
            else:
                print(f"  {C.DIM}· {msg}{C.RESET}")
            shown |= lvl in ("LEAK", "WARN")
        if not shown:
            ok("Tidak ada sumber bocor terdeteksi di config. Konfirmasi tetap di dnsleaktest.com / bash.ws dari perangkat.")
        if not core:
            print()
        elif pid == "nikki" and not os.path.isdir(NIKKI_RUN_DIR):
            print(f"  {C.DIM}tes core dilewati: path Nikki absolut ({NIKKI_RUN_DIR}) baru ada di perangkat Nikki-nya.{C.RESET}\n")
        else:
            spinner("mihomo -t", 0.3)
            good, out = _run_core_test(core, os.path.dirname(cp), cp)
            (ok if good else err)("mihomo -t: " + ("config diterima core" if good else "core menolak config"))
            if out:
                for ln in out.splitlines():
                    print(f"    {C.DIM}{truncate(ln, 100)}{C.RESET}")
            print()
    pause()


# ---------- Node tester ----------
def _fmt_ms(v):
    return f"{v}ms" if v is not None else "-"


def _node_source():
    """Return list node (dict) atau None kalau batal."""
    print(f"  {C.CYAN}[1]{C.RESET} File provider hasil generate")
    print(f"  {C.CYAN}[2]{C.RESET} Paste link URI {C.DIM}(vless:// vmess:// trojan://){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
    pilih = ask(f"{C.YELLOW}Sumber node ❯{C.RESET} ").strip()
    if pilih == "1":
        files = provider_files()
        if not files:
            err("Belum ada file provider hasil generate."); return None
        path = _pick_file([(lbl, p) for lbl, p in files], "Pilih nomor file")
        return load_provider_nodes(path) if path else None
    if pilih == "2":
        lines = _collect_lines(["Paste link, satu per baris. Enter kosong = selesai.", "Ketik 'batal' untuk kembali."])
        if not lines:
            return None
        nodes = []
        for i, ln in enumerate(lines, 1):
            try:
                n = convert_line(ln)
                if n:
                    nodes.append(n)
            except Exception as e:
                warn(f"baris {i} dilewati: {e}")
        return nodes
    return None


def _progress(done, total):
    if sys.stdout.isatty():
        sys.stdout.write(f"\r  {C.DIM}menguji {done}/{total}{C.RESET}   "); sys.stdout.flush()
        if done == total:
            sys.stdout.write("\r" + " " * 30 + "\r")


def _node_test_offline(nt):
    nodes = _node_source()
    if nodes is None:
        return
    if not nodes:
        warn("Tidak ada node untuk diuji."); return
    raw = ask(f"{C.YELLOW}Timeout per tahap, detik (Enter=5) ❯{C.RESET} ").strip()
    timeout = float(raw) if raw.replace(".", "", 1).isdigit() and float(raw) > 0 else 5.0
    print(f"\n  {C.DIM}Menguji {len(nodes)} node (DNS → TCP → TLS)...{C.RESET}")
    results = nt.run_batch(nodes, timeout=timeout, progress=_progress)
    order = sorted(range(len(results)), key=lambda i: nt.sort_key(results[i]))
    print(f"\n  {C.BOLD}{'No':<3} {'Nama':<22} {'Tipe':<6} {'DNS':>7} {'TCP':>7} {'TLS':>7}  Status{C.RESET}")
    for n, i in enumerate(order, 1):
        r = results[i]
        col = C.GREEN if r["ok"] else (C.YELLOW if r["status"].startswith("dilewati") else C.RED)
        print(f"  {n:<3} {truncate(r['name'], 22):<22} {r['type'][:6]:<6} {_fmt_ms(r['dns_ms']):>7} "
              f"{_fmt_ms(r['tcp_ms']):>7} {_fmt_ms(r['tls_ms']):>7}  {col}{r['status']}{C.RESET}")
    s = nt.summarize(results)
    print(f"\n  {C.GREEN}{s['ok']} hidup{C.RESET} · {C.RED}{s['fail']} gagal{C.RESET} · {C.YELLOW}{s['skipped']} dilewati{C.RESET} · total {s['total']}")
    print(f"  {C.DIM}Ini tes jangkauan server dari jaringan ini (DNS/TCP/TLS), bukan jaminan proxy-nya tembus ke internet.{C.RESET}")
    good = [nodes[i] for i in range(len(nodes)) if results[i]["ok"]]
    if good and ask_yn(f"\n  Simpan {len(good)} node yang hidup ke file provider? (y/N) ❯ "):
        os.makedirs(BASE_DIR, exist_ok=True)
        path = os.path.join(BASE_DIR, f"nodes_ok_{time.strftime('%d%m%Y_%H%M%S')}.yaml")
        save_proxy_yaml(good, path)
        ok(f"Tersimpan: {path}")


def _node_test_api(nt):
    default_secret = _template_secret()
    base = ask(f"{C.YELLOW}Alamat controller (Enter=127.0.0.1:9090) ❯{C.RESET} ").strip() or "127.0.0.1:9090"
    secret = ask(f"{C.YELLOW}Secret (Enter={default_secret or 'kosong'}) ❯{C.RESET} ").strip() or default_secret
    url = ask(f"{C.YELLOW}URL tes (Enter=gstatic generate_204) ❯{C.RESET} ").strip() or "http://www.gstatic.com/generate_204"
    try:
        base = nt.normalize_base(base)
        names = nt.api_list_nodes(base, secret)
    except (OSError, ValueError) as e:
        err(str(e)); return
    if not names:
        warn("Core hidup tapi belum ada node (provider kosong?)."); return
    print(f"\n  {C.DIM}Mengukur delay {len(names)} node lewat core ({base})...{C.RESET}")
    results = nt.run_api_delay(base, secret, names, url, progress=_progress)
    results.sort(key=lambda r: (not r["ok"], r["delay"] or 0, r["name"]))
    print(f"\n  {C.BOLD}{'No':<3} {'Nama':<34} {'Delay':>8}  Status{C.RESET}")
    for n, r in enumerate(results, 1):
        col = C.GREEN if r["ok"] else C.RED
        print(f"  {n:<3} {truncate(r['name'], 34):<34} {_fmt_ms(r['delay']):>8}  {col}{r['status']}{C.RESET}")
    good = sum(1 for r in results if r["ok"])
    print(f"\n  {C.GREEN}{good} lolos{C.RESET} · {C.RED}{len(results) - good} gagal{C.RESET} · total {len(results)}")


def feature_misc_nodes():
    nt = _import_tool("nodetest")
    if not nt:
        pause(); return
    while True:
        clear_screen(); banner("MISC"); section("Proxy Node Tester")
        print(f"  {C.CYAN}[1]{C.RESET} Offline  {C.DIM}(DNS → TCP → TLS ke server node, tanpa core){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Via core {C.DIM}(delay sungguhan lewat external-controller Mihomo yang sedang jalan){C.RESET}")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        if pilih == "1":
            print(); _node_test_offline(nt)
        elif pilih == "2":
            print(); _node_test_api(nt)
        else:
            err("Pilihan tidak valid."); time.sleep(0.8); continue
        pause()


# ---------- Route tester ----------
def feature_misc_route():
    rt = _import_tool("routetest")
    if not rt:
        pause(); return
    clear_screen(); banner("MISC"); section("Route Tester")
    tpl = find_template()
    if not tpl:
        err("Template tidak ditemukan."); pause(); return
    print(f"  {C.CYAN}[B]{C.RESET} Box   {C.CYAN}[N]{C.RESET} Nikki   {C.CYAN}[O]{C.RESET} OpenClash   {C.DIM}(rule beda: WIFI hanya ada di Box){C.RESET}")
    plat = {"b": "box", "n": "nikki", "o": "openclash"}[ask_choice(f"{C.YELLOW}Platform (Enter=B) ❯{C.RESET} ", ("b", "n", "o"), default="b")]
    try:
        cfg, _ = build_config(read_text(tpl), plat)
    except Exception as e:
        err(f"Gagal build config: {e}"); pause(); return
    print(f"\n  {C.DIM}Template: {os.path.basename(tpl)} · ruleset: ruleset/ · tanpa DNS lookup (offline).")
    print(f"  Contoh: youtube.com   chatgpt.com:443   1.1.1.1   udp://example.com:443{C.RESET}")
    seen_skips = set()                       # peringatan "tidak bisa dievaluasi" cukup sekali per sesi
    while True:
        target = ask(f"\n{C.YELLOW}Domain/IP (Enter = selesai) ❯{C.RESET} ").strip()
        if not target:
            return
        res = rt.route(cfg, RULESET_SOURCE, target)
        port = f":{res['port']}" if res["port"] else ""
        print(f"  {C.DIM}{res['proto']}://{res['host']}{port}{C.RESET}")
        f = res["final"]
        if f:
            ok(f"group {C.BOLD}{f['group']}{C.RESET}   ← {f['rule']}")
            print(f"    {C.DIM}cocok: {f['detail']}{C.RESET}")
        else:
            warn("tidak ada rule yang cocok (jatuh ke DIRECT)")
        for sh in res["shadowed"]:
            print(f"    {C.DIM}tertimpa: {sh['rule']}  → {sh['group']}{C.RESET}")
        for sk in res["skipped"]:
            if sk not in seen_skips:
                seen_skips.add(sk)
                warn(f"tidak bisa dievaluasi (dicatat sekali): {truncate(sk, 90)}")
        for name, why in res["load_errors"].items():
            warn(f"provider {name}: {why}")


# ---------- Sniffer Only ----------
# Domain aplikasi provider (MyXL, MyTelkomsel, by.U, myIM3, Tri, AXIS). Dipakai untuk dns.nameserver-policy opsional:
# banyak aplikasi ini memeriksa nama host yang hanya di-resolve benar oleh DNS operator. Saat Box aktif, SEMUA DNS
# dibelokkan ke core (DoH 1.1.1.1 / dns.google), jadi nama itu gagal/beda hasil dan aplikasi macet. Hipotesis, belum
# diuji di perangkat: kalau tidak membantu, lihat bagian "Aplikasi provider tidak mau terbuka" di docs/sniffer.md.
OPERATOR_DOMAINS = (
    "xl.co.id", "xl.id", "xlaxiata.co.id", "xlaxiata.id", "xlsmart.co.id", "axis.co.id",
    "telkomsel.com", "tsel.me", "tsel.id", "byu.id",
    "indosatooredoo.com", "ioh.co.id", "tri.co.id",
)


def parse_operator_dns(text):
    """'112.215.203.254, 118.98.44.10' -> (['112.215.203.254', '118.98.44.10'], ['salah']). Hanya IP polos yang diterima."""
    good, bad = [], []
    for tok in re.split(r"[\s,;]+", str(text or "").strip()):
        if not tok:
            continue
        try:
            ip = str(ipaddress.ip_address(tok))
        except ValueError:
            bad.append(tok)
            continue
        if ip not in good:
            good.append(ip)
    return good, bad


# Preset DNS operator. Hanya XL yang terverifikasi (dipakai di profil ISP repo dan terbukti membuat paket Spotify
# jalan: host CDN-nya di-resolve ke IP milik XL, AS24203). IP operator lain SENGAJA tidak ditebak: salah satu IP
# membuat semua koneksi gagal resolve, dan DNS operator berbeda per wilayah. Pakai deteksi dari perangkat.
OPERATOR_DNS_PRESETS = (
    ("xl", "XL / AXIS", ISP_PROFILES["xl"]["ips"], True),
    ("telkomsel", "Telkomsel / by.U", [], False),
    ("indosat", "Indosat / IM3 / Tri", [], False),
    ("smartfren", "Smartfren / XL Smart", [], False),
)
_MOBILE_IFACE = ("rmnet", "ccmni", "seth", "v4-rmnet", "pdp", "usb")


def parse_dns_addresses(text):
    """Keluaran `dumpsys connectivity` -> [(interface, [ipv4,...])] dari baris LinkProperties (DnsAddresses).
    Antarmuka seluler (rmnet/ccmni/...) mempertahankan IP privat (DNS internal operator); WiFi dan lainnya hanya
    IP publik, karena DNS WiFi biasanya router rumah (192.168.x) dan bukan DNS operator."""
    found, seen = [], set()
    for m in re.finditer(r"InterfaceName:\s*(\S+).*?DnsAddresses:\s*\[([^\]]*)\]", str(text or "")):
        iface, ips = m.group(1), []
        mobile = iface.lower().startswith(_MOBILE_IFACE)
        for tok in re.split(r"[\s,]+", m.group(2)):
            try:
                ip = ipaddress.ip_address(tok.strip().lstrip("/"))
            except ValueError:
                continue
            if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
            if ip.is_private and not mobile:
                continue
            if str(ip) not in ips:
                ips.append(str(ip))
        if ips and (iface, tuple(ips)) not in seen:
            seen.add((iface, tuple(ips)))
            found.append((iface, ips))
    return found


def detect_system_dns(run=None):
    """DNS yang diberikan operator ke perangkat, lewat `su -c dumpsys connectivity` (butuh root) lalu `dumpsys`
    biasa. Return [(interface, [ip,...])]; kosong kalau tidak bisa dibaca. Seluler diurutkan lebih dulu."""
    run = run or subprocess.run
    for cmd in (["su", "-c", "dumpsys connectivity"], ["dumpsys", "connectivity"]):
        try:
            r = run(cmd, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            continue
        if getattr(r, "returncode", 1) == 0 and "DnsAddresses" in (getattr(r, "stdout", "") or ""):
            res = parse_dns_addresses(r.stdout)
            return sorted(res, key=lambda x: not x[0].lower().startswith(_MOBILE_IFACE))
    return []


CATCHER_PORT = 7893                                     # httpcatch.py: proxy penangkap path HTTP polos
CATCHER_HTTP_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)
CATCHER_PROXY = "🪤 Catcher"
CATCHER_GROUP = "🪤 HTTP Catcher"


def add_catcher(cfg, host="127.0.0.1", port=CATCHER_PORT, enabled=True):
    """Selipkan penangkap path ke config sniffer: proxy http -> host:port, group pilihan, dan rule port HTTP polos
    (setelah rule LAN/DNS, SEBELUM rule CDN supaya trafik Cloudflare/CloudFront ikut tertangkap). enabled=False:
    DIRECT jadi pilihan awal group (aman kalau penangkap belum jalan). Return catatan."""
    cfg.setdefault("proxies", [])
    cfg["proxies"] = [x for x in cfg["proxies"] if not (isinstance(x, dict) and x.get("name") == CATCHER_PROXY)]
    cfg["proxies"].append({"name": CATCHER_PROXY, "type": "http", "server": host, "port": int(port)})
    groups = cfg.setdefault("proxy-groups", [])
    groups[:] = [g for g in groups if g.get("name") != CATCHER_GROUP]
    groups.append({"name": CATCHER_GROUP, "type": "select",
                   "proxies": [CATCHER_PROXY, "DIRECT"] if enabled else ["DIRECT", CATCHER_PROXY]})
    rules = cfg.setdefault("rules", [])
    rules[:] = [r for r in rules if CATCHER_GROUP not in str(r)]
    idx = 0
    for i, r in enumerate(rules):
        if str(r).startswith(("GEOIP,", "DST-PORT,53", "DST-PORT,853")):
            idx = i + 1
    for j, pt in enumerate(CATCHER_HTTP_PORTS):
        rules.insert(idx + j, f"DST-PORT,{pt},{CATCHER_GROUP}")
    return [f"Penangkap path: port HTTP polos ({', '.join(map(str, CATCHER_HTTP_PORTS))}) → proxy http {host}:{port} "
            f"(jalankan penangkap di Sniffer Only > Inspector atau menu Penangkap Path; Termux harus dikecualikan dari Box)"]


def build_sniffer_config(platform, with_asn=False, secret_mode="template", template_path=None, operator_dns=None,
                         operator_scope="provider", catcher=None):
    """Config pengintai dari template/sniffer_only.yaml, disesuaikan per platform. Return (cfg, notes).
    Tanpa profil ISP (kuota reguler) dan tanpa provider. geodata-mode dipaksa false: GeoIP di /connections
    hanya terisi di mode mmdb. operator_dns (list IP, opsional): domain aplikasi provider di-resolve lewat
    DNS operator itu (dns.nameserver-policy); domain lain tetap lewat DoH template. operator_scope="all":
    SEMUA domain lewat DNS operator saja (dns.nameserver = IP itu, tanpa DoH). Untuk menguji dugaan bahwa paket
    aplikasi (Spotify, Instagram, dsb) hanya gratis di IP yang dijawab DNS operator, bukan IP jawaban DoH publik."""
    cfg, notes = build_config(read_text(template_path or SNIFFER_TEMPLATE), platform,
                              secret_mode=secret_mode, isp="none")
    cfg["geodata-mode"] = False
    if operator_dns:
        ips, _ = parse_operator_dns(" ".join(operator_dns) if isinstance(operator_dns, (list, tuple)) else operator_dns)
        if ips:
            dns = cfg.setdefault("dns", {})
            if operator_scope == "all":
                dns["nameserver"] = list(ips)
                dns.pop("nameserver-policy", None)
                notes.append(f"SEMUA domain di-resolve lewat DNS operator {', '.join(ips)} (tanpa DoH). "
                             "Kalau DNS itu tidak terjangkau (mis. pindah jaringan), semua koneksi akan gagal resolve")
            else:
                policy = dns.setdefault("nameserver-policy", {})
                for d in OPERATOR_DOMAINS:
                    policy["+." + d] = list(ips)
                notes.append(f"DNS operator {', '.join(ips)} dipakai untuk {len(OPERATOR_DOMAINS)} domain aplikasi provider (nameserver-policy)")
    if with_asn:
        cfg.setdefault("geox-url", {})["asn"] = SNIFFER_ASN_URL
        rules = cfg.setdefault("rules", [])
        rules.insert(1 if rules and str(rules[0]).startswith("GEOIP,ZZ") else 0, "IP-ASN,0,DIRECT")
        notes.append("ASN aktif: core akan mengunduh GeoLite2-ASN.mmdb (kuota reguler) saat start")
    if catcher:
        chost, cport = catcher if isinstance(catcher, (tuple, list)) else (catcher, CATCHER_PORT)
        notes += add_catcher(cfg, chost, cport)
    return cfg, notes


def sniffer_config_filename(name=None):
    name = safe_name(name)
    return f"sniffer-{name}.yaml" if name else "config.yaml"


def write_sniffer_config(platform, with_asn=False, secret_mode="template", out_root=None, operator_dns=None,
                         operator_scope="provider", catcher=None, name=None):
    """Tulis hasil/sniffer/<platform>/sniffer-<name>.yaml (tanpa name: config.yaml). Return (path, issues, notes)."""
    cfg, notes = build_sniffer_config(platform, with_asn, secret_mode, operator_dns=operator_dns,
                                      operator_scope=operator_scope, catcher=catcher)
    out_dir = os.path.join(out_root or SNIFFER_OUT_DIR, platform)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, sniffer_config_filename(name))
    issues = validate_config(cfg, platform, out_dir)
    if os.path.exists(path):
        backup_file(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_config(cfg, platform, "(sniffer only)"))
    return path, issues, notes


SNIFFER_INSTALL_HINT = {
    "box": "salin {f} ke /data/adb/box/clash/  (cadangkan config lama dulu; kalau Box membaca config.yaml, ganti namanya)",
    "nikki": "salin {f} ke /etc/nikki/profiles/  (tanpa folder proxy/ruleset)",
    "openclash": "salin {f} ke /etc/openclash/config/  (tanpa folder provider)",
}


def _ask_name(prompt, default_hint):
    """Minta nama (untuk nama file). Enter = kosong (pakai bawaan). Nama diubah ke bentuk aman; yang tak menyisakan
    karakter valid ditolak dan ditanya ulang."""
    while True:
        raw = ask(prompt).strip()
        if not raw:
            return ""
        name = safe_name(raw)
        if name:
            if name != raw:
                print(f"  {C.DIM}dipakai: {name}{C.RESET}")
            return name
        err(f"Nama '{truncate(raw, 20)}' tidak valid (pakai huruf/angka). Enter = {default_hint}.")


def _pick_platform(default="b"):
    print(f"  {C.CYAN}[B]{C.RESET} Box   {C.CYAN}[N]{C.RESET} Nikki   {C.CYAN}[O]{C.RESET} OpenClash")
    key = ask_choice(f"{C.YELLOW}Platform (Enter={default.upper()}) ❯{C.RESET} ", ("b", "n", "o"), default=default)
    return {"b": "box", "n": "nikki", "o": "openclash"}[key]


def _pick_operator_dns(context="sniffer"):
    """Menu DNS operator (config sniffer atau Uji Bug). Return list IP (kosong = lewati)."""
    if context == "bugtest":
        print(f"\n  {C.DIM}Address node dan kandidat di-resolve lewat resolver sistem. Di jaringan operator, IP gratis (cache milik{C.RESET}")
        print(f"  {C.DIM}operator) hanya dijawab DNS operator; DNS publik/DoH memberi IP lain sehingga uji bisa salah gagal.{C.RESET}")
        print(f"  {C.DIM}Matikan Box saat uji: Box membelokkan semua DNS ke DoH publik.{C.RESET}\n")
    else:
        print(f"\n  {C.DIM}Aplikasi provider dan paket aplikasi (MyXL, by.U, Spotify, Instagram, dsb) bisa mati saat Box aktif: DNS-nya{C.RESET}")
        print(f"  {C.DIM}dibelokkan ke DoH publik, padahal IP gratisnya (cache milik operator) hanya dijawab DNS operator.{C.RESET}\n")
    print(f"  {C.BOLD}DNS operator{C.RESET}")
    print(f"    [D] Deteksi dari perangkat (butuh root)")
    for i, (_, label, ips, verified) in enumerate(OPERATOR_DNS_PRESETS, 1):
        if ips:
            print(f"    [{i}] {label:<22} {', '.join(ips)}  {C.DIM}(terverifikasi){C.RESET}")
        else:
            print(f"    [{i}] {label:<22} {C.DIM}IP belum terverifikasi → pakai [D] atau [M]{C.RESET}")
    print(f"    [M] Isi manual    {C.DIM}Enter = lewati{C.RESET}")
    while True:
        ch = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip().lower()
        if not ch:
            return []
        if ch == "d":
            spinner("Membaca DNS perangkat", 0.4)
            found = detect_system_dns()
            if not found:
                warn("Tidak terbaca (butuh root / izin su untuk Termux). Pakai [M] atau pilih preset."); continue
            for i, (iface, ips) in enumerate(found, 1):
                kind = "seluler" if iface.lower().startswith(_MOBILE_IFACE) else "lainnya"
                print(f"    {i}) {iface:<14} {', '.join(ips)}  {C.DIM}({kind}){C.RESET}")
            pick = ask(f"{C.YELLOW}Nomor (Enter = 1, 0 = batal) ❯{C.RESET} ").strip()
            if pick == "0":
                continue
            idx = int(pick) - 1 if pick.isdigit() and 1 <= int(pick) <= len(found) else 0
            return found[idx][1]
        if ch == "m":
            raw = ask(f"{C.YELLOW}IP DNS (spasi/koma) ❯{C.RESET} ").strip()
            ips, bad = parse_operator_dns(raw)
            if bad or not ips:
                err(f"Bukan IP yang valid: {', '.join(bad) or raw}"); continue
            return ips
        if ch.isdigit() and 1 <= int(ch) <= len(OPERATOR_DNS_PRESETS):
            ips = OPERATOR_DNS_PRESETS[int(ch) - 1][2]
            if ips:
                return list(ips)
            warn("Preset ini belum punya IP terverifikasi. Pakai [D] atau [M]."); continue
        err("Pilihan tidak dikenal.")


def _sniffer_generate():
    clear_screen(); banner("MISC"); section("Sniffer Only — Generate Config")
    if not os.path.isfile(SNIFFER_TEMPLATE):
        err(f"Template tidak ditemukan: {os.path.relpath(SNIFFER_TEMPLATE, SCRIPT_DIR)}"); pause(); return
    print(f"  {C.DIM}Tanpa node, semua trafik DIRECT lewat kuota reguler. Hanya mengintip koneksi.{C.RESET}\n")
    plat = _pick_platform()
    print(f"\n  {C.DIM}Nama file: 'three' → sniffer-three.yaml. Kosong = config.yaml (bisa menimpa config sniffer lama).{C.RESET}")
    sname = _ask_name(f"{C.YELLOW}Nama config (Enter = config.yaml) ❯{C.RESET} ", "config.yaml")
    print(f"\n  {C.DIM}ASN = nama pemilik IP (mis. AS13335 Cloudflare). Butuh GeoLite2-ASN.mmdb yang diunduh core saat start.{C.RESET}")
    with_asn = ask_yn(f"{C.YELLOW}Aktifkan ASN? (y/N) ❯{C.RESET} ")
    rnd = ask_yn(f"{C.YELLOW}Secret acak? (y/N, N = 'hikari') ❯{C.RESET} ")
    op_ips = _pick_operator_dns()
    scope = "provider"
    if op_ips:
        print(f"\n  {C.DIM}Cakupan DNS operator: [1] hanya domain provider   [2] SEMUA domain, tanpa DoH{C.RESET}")
        print(f"  {C.DIM}[2] dibutuhkan untuk paket aplikasi (Spotify, Instagram, dsb): CDN-nya hanya dijawab DNS operator.{C.RESET}")
        print(f"  {C.DIM}Risiko [2]: kalau DNS itu tidak terjangkau (pindah jaringan), semua koneksi gagal resolve.{C.RESET}")
        scope = "provider" if ask_choice(f"{C.YELLOW}Cakupan (1/2, Enter = 2) ❯{C.RESET} ", ("1", "2"), default="2") == "1" else "all"
    catcher = None
    print(f"\n  {C.DIM}Penangkap path: proxy lokal (httpcatch.py) yang mencatat URL PATH, redirect (Location) dan status")
    print(f"  untuk HTTP polos (port 80/8080/...). Path HTTPS tidak terlihat. Berjalan di perangkat yang sama dengan Box.{C.RESET}")
    if ask_yn(f"{C.YELLOW}Aktifkan penangkap path? (y/N) ❯{C.RESET} "):
        chost = ask(f"  Alamat penangkap (Enter = 127.0.0.1) ❯ ").strip() or "127.0.0.1"
        craw = ask(f"  Port penangkap   (Enter = {CATCHER_PORT}) ❯ ").strip()
        catcher = (chost, int(craw) if craw.isdigit() and 1 <= int(craw) <= 65535 else CATCHER_PORT)
    spinner("Membangun config", 0.4)
    try:
        path, issues, notes = write_sniffer_config(plat, with_asn, "random" if rnd else "template",
                                                   operator_dns=op_ips or None, operator_scope=scope, catcher=catcher, name=sname)
    except Exception as e:
        err(f"Gagal membuat config: {type(e).__name__}: {e}"); pause(); return
    ok(f"Config {PLATFORMS[plat]['label']} → {os.path.relpath(path, SCRIPT_DIR)}")
    for n in notes:
        print(f"  {C.DIM}· {n}{C.RESET}")
    print_issues(issues)
    print(f"\n  {C.BOLD}Pasang:{C.RESET} {SNIFFER_INSTALL_HINT[plat].format(f=os.path.basename(path))}")
    print(f"  {C.DIM}Lalu jalankan core, buka aplikasi yang mau diintip, dan pakai menu [2] Inspector.{C.RESET}")
    print(f"  {C.DIM}Nikki/OpenClash menimpa port/dns/controller dari LuCI; GeoIP butuh mode mmdb (bukan geoip.dat).{C.RESET}")
    pause()


def sniffer_result_path(name, stamp, ext, kind="koneksi"):
    """hasil/sniffer/<nama>_<tanggal>_<jam>.<ext>. kind='path' (log penangkap path): <nama>_path_<tanggal>_<jam>.<ext>.
    Tanpa nama: 'koneksi' / 'path'."""
    name = safe_name(name)
    base = (f"{name}_path" if name else "path") if kind == "path" else (name or "koneksi")
    return os.path.join(SNIFFER_OUT_DIR, f"{base}_{stamp}.{ext}")


def _sniffer_rename_pathlog(stamp, name):
    """Log penangkap path ditulis langsung selama sesi (path_<stamp>.jsonl); ganti ke nama pilihan pengguna."""
    old = os.path.join(SNIFFER_OUT_DIR, f"path_{stamp}.jsonl")
    new = sniffer_result_path(name, stamp, "jsonl", "path")
    if os.path.isfile(old) and old != new:
        try:
            os.replace(old, new)
            return new
        except OSError:
            return old
    return new if os.path.isfile(new) else old


def _sniffer_controller_defaults():
    """Alamat & secret dari config sniffer yang pernah digenerate; kalau tidak ada, default template."""
    for pid in PLATFORMS:
        found = sorted(glob.glob(os.path.join(SNIFFER_OUT_DIR, pid, "*.yaml")), key=os.path.getmtime, reverse=True)
        for cp in found[:1]:
            try:
                cfg = yaml.safe_load(read_text(cp)) or {}
                return str(cfg.get("external-controller") or "127.0.0.1:9090"), str(cfg.get("secret") or "")
            except (OSError, yaml.YAMLError):
                break
    return "127.0.0.1:9090", "hikari"


def _catcher_start(hc, stamp):
    """Tanya alamat/port lalu jalankan penangkap path di thread latar. Return CatchServer atau None."""
    host = ask(f"  Listen penangkap (Enter = 127.0.0.1; 0.0.0.0 bila Box di perangkat lain) ❯ ").strip() or "127.0.0.1"
    raw = ask(f"  Port penangkap    (Enter = {CATCHER_PORT}) ❯ ").strip()
    port = int(raw) if raw.isdigit() and 1 <= int(raw) <= 65535 else CATCHER_PORT

    def show(e, phase):
        if phase == "done":
            print(f"  {C.MAGENTA}⇢{C.RESET} {hc.fmt_event(e)}")

    try:
        srv = hc.CatchServer(host, port, os.path.join(SNIFFER_OUT_DIR, f"path_{stamp}.jsonl"), show).start()
    except OSError as e:
        err(str(e)); return None
    ok(f"Penangkap path aktif di {host}:{srv.port} {C.DIM}(HTTP polos saja; HTTPS hanya SNI){C.RESET}")
    return srv


def _sniffer_inspect():
    sn = _import_tool("sniffer")
    if not sn:
        pause(); return
    clear_screen(); banner("MISC"); section("Sniffer Only — Inspector Live")
    addr, secret = _sniffer_controller_defaults()
    print(f"  {C.DIM}Membaca /connections dari core yang SEDANG jalan dengan config sniffer.{C.RESET}\n")
    a = ask(f"  Controller (Enter = {addr}) ❯ ").strip() or addr
    sec = ask(f"  Secret     (Enter = {secret or 'kosong'}) ❯ ").strip() or secret
    detail = ask_choice(f"  Tampilan   [1] ringkas  [2] detail (Enter=2) ❯ ", ("1", "2"), default="2") != "1"
    stamp = time.strftime("%Y%m%d_%H%M%S")
    catch = None
    hc = _import_tool("httpcatch")
    if hc and ask_yn(f"  Tangkap URL path HTTP juga? (y/N) ❯ "):
        print(f"  {C.DIM}Config sniffer harus dibuat dengan 'penangkap path' aktif (Generate Config) agar trafik lewat sini.{C.RESET}")
        catch = _catcher_start(hc, stamp)
    base = sn.controller_url(a)
    ranges = sn.CdnRanges(SNIFFER_OUT_DIR)
    if not ranges.cloudfront:
        warn("Daftar CIDR CloudFront belum ada → CloudFront hanya dikenali dari nama *.cloudfront.net (menu [3] untuk mengunduh).")
    try:
        first = sn.fetch_connections(base, sec)      # snapshot pertama ikut diproses, tidak dibuang
    except sn.SnifferError as e:
        if catch:
            catch.stop()
        err(str(e)); pause(); return
    tracker = sn.Tracker(ranges)
    print(f"\n  {C.GREEN}Terhubung{C.RESET} ke {base}. Buka aplikasi/situs yang mau diintip. {C.DIM}Ctrl+C untuk berhenti.{C.RESET}\n{sep(50)}")
    try:
        while True:
            try:
                conns, first = (first, None) if first is not None else (sn.fetch_connections(base, sec), None)
                new = tracker.update(conns)
            except sn.SnifferError as e:
                warn(f"{e} — mencoba lagi...")
                time.sleep(3); continue
            for row in new:
                if detail:
                    for ln in sn.fmt_detail(row):
                        print(ln)
                    print(f"  {C.DIM}{'·' * 30}{C.RESET}")
                else:
                    print(sn.fmt_compact(row))
            time.sleep(2)
    except KeyboardInterrupt:
        print()
    rows = tracker.all()
    path_events = []
    if catch:
        path_events = catch.log.snapshot()
        catch.stop()
    print(f"{sep(50)}\n{C.BOLD}Ringkasan sesi{C.RESET}")
    for ln in sn.summary_lines(rows):
        print(f"  {ln}")
    if path_events:
        plain = [e for e in path_events if not e.get("tls")]
        print(f"  Path HTTP tertangkap: {len(plain)} permintaan")
        for c in hc.bug_candidates(path_events)[:8]:
            print(f"    {C.GREEN}•{C.RESET} {c}  {C.DIM}(kandidat bug berpath){C.RESET}")
    if not rows and not path_events:
        pause(); return
    if ask_yn(f"\n{C.YELLOW}Simpan ke hasil/sniffer/? (y/N) ❯{C.RESET} "):
        print(f"  {C.DIM}Nama hasil: 'instagram' → instagram_{stamp}.csv/.json/.md. Kosong = koneksi.{C.RESET}")
        rname = _ask_name(f"{C.YELLOW}Nama hasil (Enter = koneksi) ❯{C.RESET} ", "koneksi")
        try:
            p1 = sn.export_csv(rows, sniffer_result_path(rname, stamp, "csv"))
            p2 = sn.export_json(rows, sniffer_result_path(rname, stamp, "json"))
            p3 = sn.export_markdown(rows, sniffer_result_path(rname, stamp, "md"), source=f"sesi {stamp}",
                                    path_events=path_events)
            if path_events:
                pl = _sniffer_rename_pathlog(stamp, rname)
                ok(f"{os.path.relpath(pl, SCRIPT_DIR)}")
            ok(f"{os.path.relpath(p1, SCRIPT_DIR)}"); ok(f"{os.path.relpath(p2, SCRIPT_DIR)}")
            ok(f"{os.path.relpath(p3, SCRIPT_DIR)}  {C.DIM}(hanya yang menerima data, digabung){C.RESET}")
        except OSError as e:
            err(f"Gagal menyimpan: {e}")
    pause()


def _sniffer_update_cidr():
    sn = _import_tool("sniffer")
    if not sn:
        pause(); return
    clear_screen(); banner("MISC"); section("Sniffer Only — Update CIDR CDN")
    print(f"  {C.DIM}Mengunduh daftar resmi Cloudflare (cloudflare.com/ips-v4, ips-v6) dan CloudFront (AWS ip-ranges.json).")
    print(f"  Memakai kuota reguler: ip-ranges.json berukuran beberapa MB. Hasil di-cache di hasil/sniffer/.{C.RESET}\n")
    if not ask_yn(f"{C.YELLOW}Lanjut? (y/N) ❯{C.RESET} "):
        return
    spinner("Mengunduh", 0.4)
    for name, n, e in sn.update_cdn_ranges(SNIFFER_OUT_DIR):
        (err if e else ok)(f"{name}: {e}" if e else f"{name}: {n} CIDR")
    pause()


def _sniffer_catcher():
    hc = _import_tool("httpcatch")
    if not hc:
        pause(); return
    clear_screen(); banner("MISC"); section("Sniffer Only — Penangkap Path")
    print(f"  {C.DIM}Proxy lokal yang mencatat URL PATH, redirect (Location) dan status dari HTTP polos.")
    print(f"  Masuk lewat config sniffer (Generate Config > penangkap path) atau atur proxy HTTP aplikasi ke alamat ini.")
    print(f"  Path HTTPS tidak terlihat (tanpa MITM); untuk HTTPS hanya SNI.{C.RESET}\n")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    srv = _catcher_start(hc, stamp)
    if not srv:
        pause(); return
    print(f"  {C.DIM}Buka situs/aplikasi yang mau diintip. Ctrl+C untuk berhenti.{C.RESET}\n{sep(50)}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
    events = srv.log.snapshot()
    srv.stop()
    print(f"{sep(50)}\n  {len([e for e in events if not e.get('tls')])} permintaan HTTP · {len([e for e in events if e.get('tls')])} TLS")
    for c in hc.bug_candidates(events)[:10]:
        print(f"    {C.GREEN}•{C.RESET} {c}  {C.DIM}(kandidat bug berpath){C.RESET}")
    if events:
        print(f"  {C.DIM}Nama hasil: 'instagram' → instagram_path_{stamp}.md/.jsonl. Kosong = path.{C.RESET}")
        rname = _ask_name(f"{C.YELLOW}Nama hasil (Enter = path) ❯{C.RESET} ", "path")
        try:
            mdp = sniffer_result_path(rname, stamp, "md", "path")
            with open(mdp, "w", encoding="utf-8") as f:
                f.write(hc.render_markdown(events, f"sesi {stamp}"))
            pl = _sniffer_rename_pathlog(stamp, rname)
            ok(f"{os.path.relpath(mdp, SCRIPT_DIR)}  {C.DIM}(+ {os.path.basename(pl)}){C.RESET}")
        except OSError as e:
            err(f"Gagal menyimpan: {e}")
    pause()


def feature_misc_sniffer():
    while True:
        clear_screen(); banner("MISC"); section("Sniffer Only")
        print(f"  {C.CYAN}[1]{C.RESET} Generate Config          {C.DIM}(tanpa node, semua DIRECT){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Inspector Live           {C.DIM}(detail tiap koneksi dari /connections){C.RESET}")
        print(f"  {C.CYAN}[3]{C.RESET} Update CIDR CDN          {C.DIM}(Cloudflare + CloudFront, resmi){C.RESET}")
        print(f"  {C.CYAN}[4]{C.RESET} Penangkap Path           {C.DIM}(URL path + redirect HTTP polos){C.RESET}")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        elif pilih == "1": _sniffer_generate()
        elif pilih == "2": _sniffer_inspect()
        elif pilih == "3": _sniffer_update_cidr()
        elif pilih == "4": _sniffer_catcher()
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


# ---------- Info ----------
def feature_misc_info():
    clear_screen(); banner("MISC"); section("Info Lingkungan")
    mrs = _import_tool("mrs_codec")
    print(f"  Python        : {sys.version.split()[0]}")
    print(f"  PyYAML        : {getattr(yaml, '__version__', '?')}")
    be = mrs.backend_name() if mrs else None
    print(f"  zstd (.mrs)   : {be or 'tidak ada — ' + (mrs.INSTALL_HINT.splitlines()[0] if mrs else '')}")
    core = mrs.find_mihomo() if mrs else None
    print(f"  Core Mihomo   : {core or 'tidak ditemukan (opsional; env HIKARI_MIHOMO untuk path manual)'}")
    tpl = find_template()
    print(f"  Template aktif: {os.path.relpath(tpl, SCRIPT_DIR) if tpl else '-'}  (versi {template_version(tpl) or '?'})")
    ecfg = load_emoji_cfg()
    print(f"  Emoji node    : {'ON' if ecfg['enabled'] else 'OFF'} ({len(ecfg['emojis'])} emoji)")
    print(f"  Folder script : {SCRIPT_DIR}")
    print(f"  Folder hasil  : {BASE_DIR}")
    pause()


def feature_info_banner():
    """Pengaturan info di bawah banner (disimpan di settings.json, kunci "info")."""
    import sysinfo
    onoff = lambda v: f"{C.GREEN}ON{C.RESET}" if v else f"{C.GRAY}OFF{C.RESET}"
    while True:
        clear_screen(); banner("MISC", info=None); section("Info Banner")
        pr = sysinfo.load_prefs()
        print(f"  {C.CYAN}[1]{C.RESET} Tampilan          : {C.BOLD}{pr['mode']}{C.RESET} {C.DIM}(full / compact / off){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Sensor IP         : {onoff(pr['mask'])} {C.DIM}(36.71.x.x, lokasi hanya negara — aman untuk screenshot){C.RESET}")
        print(f"  {C.CYAN}[3]{C.RESET} IP publik+lokasi  : {onoff(pr['lookup'])} {C.DIM}(menghubungi ipwho.is / ipinfo.io){C.RESET}")
        print(f"  {C.CYAN}[4]{C.RESET} Platform          : {C.BOLD}{pr['platform']}{C.RESET} {C.DIM}(auto / box / nikki / openclash){C.RESET}")
        print(f"  {C.CYAN}[5]{C.RESET} Alamat controller : {C.BOLD}{pr['api'] or '(otomatis)'}{C.RESET} {C.DIM}(mis. 192.168.1.1:9090 untuk router){C.RESET}")
        print(f"  {C.CYAN}[6]{C.RESET} Secret controller : {C.BOLD}{'(diisi)' if pr['secret'] else '(otomatis dari template)'}{C.RESET}")
        print(f"  {C.CYAN}[7]{C.RESET} Operator          : {C.BOLD}{pr['operator'] or '(otomatis dari SIM)'}{C.RESET} {C.DIM}(isi bila HP dual SIM, mis. by.U){C.RESET}")
        print(f"  {C.CYAN}[8]{C.RESET} Pratinjau sekarang")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        saved = sysinfo.load_prefs(use_env=False)       # simpan nilai file, bukan hasil timpaan env
        if pilih == "1":
            v = ask("  Tampilan (full/compact/off) ❯ ").strip().lower()
            if v not in sysinfo.MODES:
                err("Pilih full, compact, atau off."); time.sleep(0.8); continue
            saved["mode"] = v
        elif pilih == "2":
            saved["mask"] = not saved["mask"]
        elif pilih == "3":
            saved["lookup"] = not saved["lookup"]
        elif pilih == "4":
            v = ask("  Platform (auto/box/nikki/openclash) ❯ ").strip().lower()
            if v not in ("auto",) + tuple(sysinfo.PLATFORM_NAMES):
                err("Pilih auto, box, nikki, atau openclash."); time.sleep(0.8); continue
            saved["platform"] = v
        elif pilih == "5":
            v = ask("  host:port (kosong = otomatis) ❯ ").strip()
            if v and not re.fullmatch(r"[\w.\-]+:\d{1,5}", v):
                err("Format host:port, mis. 192.168.1.1:9090"); time.sleep(0.8); continue
            saved["api"] = v
        elif pilih == "6":
            saved["secret"] = ask("  Secret (kosong = otomatis) ❯ ").strip()
        elif pilih == "7":
            saved["operator"] = ask("  Nama operator (kosong = otomatis) ❯ ").strip()[:40]
        elif pilih == "8":
            sysinfo.clear_cache()
            rows = sysinfo.lines("full", None, sys.stdout.isatty(), force=True)
            print("\n".join(rows) if rows else f"  {C.DIM}(info dimatikan){C.RESET}")
            pause(); continue
        else:
            err("Pilihan tidak valid."); time.sleep(0.8); continue
        try:
            sysinfo.save_prefs(saved)
            sysinfo.clear_cache()
        except OSError as e:
            err(f"Tidak bisa menyimpan settings.json: {e}"); time.sleep(1.2)


def feature_misc_menu():
    while True:
        clear_screen(); banner("MISC"); section("Miscellaneous")
        print(f"  {C.CYAN}[1]{C.RESET} Rule-Provider Converter  {C.DIM}(.mrs ⇄ .yaml / .txt){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Config Tester            {C.DIM}(validator + mihomo -t bila core ada){C.RESET}")
        print(f"  {C.CYAN}[3]{C.RESET} Proxy Node Tester        {C.DIM}(offline atau via core){C.RESET}")
        print(f"  {C.CYAN}[4]{C.RESET} Route Tester             {C.DIM}(domain/IP ➜ rule & group){C.RESET}")
        print(f"  {C.CYAN}[5]{C.RESET} Sniffer Only             {C.DIM}(config pengintai koneksi + inspector){C.RESET}")
        print(f"  {C.CYAN}[6]{C.RESET} Info Lingkungan")
        print(f"  {C.CYAN}[7]{C.RESET} Info Banner              {C.DIM}(IP, lokasi, jaringan, status core, usage){C.RESET}")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        elif pilih == "1": feature_misc_rules()
        elif pilih == "2": feature_misc_config()
        elif pilih == "3": feature_misc_nodes()
        elif pilih == "4": feature_misc_route()
        elif pilih == "5": feature_misc_sniffer()
        elif pilih == "6": feature_misc_info()
        elif pilih == "7": feature_info_banner()
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


# =====================================================================
#  Menu
# =====================================================================
# =====================================================================
#  Free node (sub2yaml → proxy/free.yaml, group ☘️ FREE NODE)
# =====================================================================
# Kontrak dengan sub2yaml: keluarannya YAML Clash `proxies: [...]` (sama dengan subscription.yaml).
# Hikari hanya memvalidasi lalu menulis ke <platform>/<proxy_dir>/free.yaml; config.yaml tidak perlu di-generate ulang
# karena provider "📄 Free" sudah menunjuk ke file itu (core membaca ulang saat restart / update provider).
FREE_REQUIRED_KEYS = ("name", "type", "server", "port")


def free_node_path(platform, base_dir=None):
    P = PLATFORMS[platform]
    return os.path.join(base_dir or BASE_DIR, P["out"], P["proxy_dir"], FREE_NODE_FILE)


def load_sub2yaml_output(path):
    """Baca keluaran sub2yaml. Return (nodes, error). Menerima `proxies: [...]` atau list polos."""
    try:
        data = yaml.safe_load(read_text(path))
    except (OSError, yaml.YAMLError) as e:
        return [], f"tidak bisa membaca {path}: {e}"
    items = data.get("proxies") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return [], "format tidak dikenal: butuh `proxies: [...]` (YAML Clash)"
    return [x for x in items if isinstance(x, dict)], None


def clean_free_nodes(nodes, taken=()):
    """Buang node tak lengkap, nama bentrok dengan group/proxy template → dedupe. Return (nodes, notes)."""
    notes, good = [], []
    for n in nodes:
        miss = [k for k in FREE_REQUIRED_KEYS if n.get(k) in (None, "")]
        if miss:
            notes.append(f"dibuang: '{n.get('name', '?')}' tanpa {', '.join(miss)}")
            continue
        good.append(dict(n, name=str(n["name"])))
    before = [n["name"] for n in good]
    dedupe_names(good, set(taken) | reserved_names())
    renamed = sum(1 for a, n in zip(before, good) if a != n["name"])
    if renamed:
        notes.append(f"{renamed} nama node diubah agar unik")
    return good, notes


def import_free_nodes(source_path, platforms=None, write_mode="replace", base_dir=None):
    """Tulis node dari sub2yaml ke free.yaml tiap platform. write_mode: 'replace' | 'append'.
    Return list[(platform, jumlah_node, notes, error)]."""
    nodes, error = load_sub2yaml_output(source_path)
    if error:
        return [(None, 0, [], error)]
    if not nodes:
        return [(None, 0, [], "tidak ada node di file sumber")]
    results = []
    for plat in platforms or list(PLATFORMS):
        dest = free_node_path(plat, base_dir)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            taken = set()
            # nama node di Active/Trial juga dihindari supaya tidak dobel di group yang memakai banyak provider
            for fn in USER_NODE_FILES:
                taken |= {x.get("name") for x in load_provider_nodes(os.path.join(os.path.dirname(dest), fn))}
            existing = load_provider_nodes(dest) if write_mode == "append" else []
            taken |= {x.get("name") for x in existing}
            cleaned, notes = clean_free_nodes(nodes, taken)
            if not cleaned:
                results.append((plat, 0, notes, "semua node tidak valid"))
                continue
            if write_mode == "replace" and os.path.exists(dest):
                backup_file(dest)
            save_proxy_yaml(existing + cleaned, dest)
            results.append((plat, len(cleaned), notes, None))
        except OSError as e:
            results.append((plat, 0, [], f"{type(e).__name__}: {e}"))
    return results


def sub2yaml_free_path(out_dir=None):
    return os.path.join(out_dir or SUB2YAML_OUT_DIR, FREE_NODE_FILE)


def run_sub2yaml(script=None, out_dir=None):
    """Jalankan sub2yaml.py secara interaktif (menu & spinner-nya tampil langsung di terminal ini).
    Return (ok, pesan). ok=True hanya kalau <out_dir>/free.yaml baru dibuat/diperbarui oleh proses tadi."""
    script = script or SUB2YAML_SCRIPT
    out_dir = out_dir or SUB2YAML_OUT_DIR
    if not os.path.isfile(script):
        return False, f"sub2yaml.py tidak ditemukan di {script}"
    target = sub2yaml_free_path(out_dir)
    before = os.path.getmtime(target) if os.path.isfile(target) else None
    try:
        proc = subprocess.Popen([sys.executable, script, "-o", out_dir], env=dict(os.environ, HIKARI_PARENT="1"))
    except OSError as e:
        return False, f"gagal menjalankan sub2yaml: {e}"
    while True:                      # Ctrl+C ditangani sub2yaml sendiri; Hikari tidak ikut berhenti
        try:
            code = proc.wait()
            break
        except KeyboardInterrupt:
            continue
    if code != 0:
        return False, f"sub2yaml berhenti dengan kode {code} (tidak ada node yang berhasil?)"
    if not os.path.isfile(target) or (before is not None and os.path.getmtime(target) <= before):
        return False, "free.yaml tidak dibuat/diperbarui (sub2yaml dibatalkan, atau folder output diubah di menu [5])"
    return True, "ok"


def feature_import_free_nodes():
    clear_screen(); banner(); section("Free Node ➜ ☘️ FREE NODE (sub2yaml)")
    print(f"  {C.DIM}Isi proxy/free.yaml dari keluaran sub2yaml (YAML Clash `proxies:`). Node divalidasi dan dijaga unik.{C.RESET}\n")
    src = None
    if os.path.isfile(SUB2YAML_SCRIPT):
        print(f"  {C.CYAN}[1]{C.RESET} Jalankan sub2yaml.py sekarang {C.DIM}(ambil node dari src/*.txt, tes, simpan ke hasil/proxy/free.yaml){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Pilih / ketik path file YAML {C.DIM}(mis. hasil/proxy/free.yaml dari proses sebelumnya){C.RESET}")
        if ask_choice(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ", ("1", "2")) == "1":
            good, msg = run_sub2yaml()
            print()
            if not good:
                err(msg); pause(); return
            src = sub2yaml_free_path()
            ok(f"Keluaran sub2yaml: {os.path.relpath(src, SCRIPT_DIR)}")
    if src is None:
        cands = [("subscription.yaml (repo)", SUBSCRIPTION_SOURCE)] if os.path.isfile(SUBSCRIPTION_SOURCE) else []
        cands += [(os.path.relpath(f, SCRIPT_DIR), f) for f in sorted(glob.glob(os.path.join(SUB2YAML_OUT_DIR, "*.y*ml")))]
        cands += [(os.path.relpath(f, SCRIPT_DIR), f) for f in sorted(glob.glob(os.path.join(BASE_DIR, "*.y*ml")))]
        src = _pick_file(cands, "Pilih nomor, atau ketik path file")
        if not src:
            return
    print(f"\n  {C.CYAN}[B]{C.RESET} Box  {C.CYAN}[N]{C.RESET} Nikki  {C.CYAN}[O]{C.RESET} OpenClash  {C.CYAN}[A]{C.RESET} Semua")
    pl = ask_choice(f"{C.YELLOW}Platform (B/N/O/A, Enter=A) ❯{C.RESET} ", ("b", "n", "o", "a"), default="a")
    plats = {"b": ["box"], "n": ["nikki"], "o": ["openclash"], "a": list(PLATFORMS)}[pl]
    mode = ask_choice(f"{C.YELLOW}Mode: [1] Ganti isi free.yaml  [2] Tambahkan (Enter=1) ❯{C.RESET} ", ("1", "2"), default="1")
    for plat, n, notes, error in import_free_nodes(src, plats, "append" if mode == "2" else "replace"):
        if error:
            err(f"{plat or 'sumber'}: {error}"); continue
        ok(f"{PLATFORMS[plat]['label']}: {n} node → {os.path.relpath(free_node_path(plat), SCRIPT_DIR)}")
        for note in notes:
            print(f"  {C.DIM}• {note}{C.RESET}")
    pause("Tekan Enter untuk kembali ke menu...")


def feature_convert_menu():
    clear_screen(); banner(); section("Menu Convert")
    print(f"  {C.CYAN}[1]{C.RESET} URI (VLESS/VMess/Trojan)  ➜  Clash (YAML)")
    print(f"  {C.CYAN}[2]{C.RESET} Clash (YAML)              ➜  URI (VLESS/VMess/Trojan)")
    print(f"  {C.CYAN}[3]{C.RESET} Regenerate config dari node tersimpan {C.DIM}(tanpa paste URI lagi){C.RESET}")
    print(f"  {C.CYAN}[4]{C.RESET} Free node (sub2yaml)  ➜  🐦 Free {C.DIM}(proxy/free.yaml){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
    pilihan = ask(f"{C.YELLOW}Pilih (1/2/3/4) ❯{C.RESET} ").strip()
    if pilihan == "1":
        clear_screen(); banner(); feature_convert_to_clash()
    elif pilihan == "2":
        feature_convert_to_uri()
    elif pilihan == "3":
        feature_regenerate()
    elif pilihan == "4":
        feature_import_free_nodes()


def ensure_emoji_file():
    """Pastikan emoji.json ada (isi bawaan) supaya gampang diedit manual maupun lewat menu."""
    if not os.path.isfile(EMOJI_PATH):
        try:
            save_emoji_cfg({"enabled": True, "emojis": list(DEFAULT_EMOJIS)})
        except OSError:
            pass


# =====================================================================
#  Box Utilities (root: start/stop/restart, pasang & ganti config, dashboard) — logika di boxutil.py
# =====================================================================
def _box_ctx():
    """(boxutil, info) atau (None, None) bila tidak bisa dipakai (bukan Android/root, settings.ini tak terbaca)."""
    bx = _import_tool("boxutil")
    if not bx:
        return None, None
    if not bx.can_use_root():
        err("Box Utilities butuh Android yang sudah root (Termux + su) dengan Box for Root terpasang.")
        pause(); return None, None
    info = bx.box_info()
    if info.get("error"):
        err(info["error"])
        print(f"  {C.DIM}Pastikan Box for Root terpasang dan akses root diizinkan untuk Termux.{C.RESET}")
        pause(); return None, None
    return bx, info


def _box_run(bx, title, cmds, timeout=90, confirm=True):
    """Tampilkan perintah root, minta persetujuan (default tidak), jalankan berurutan. Return True bila semua sukses."""
    print(f"\n  {C.BOLD}{title}{C.RESET} {C.DIM}(dijalankan sebagai root){C.RESET}")
    for c in cmds:
        print(f"    {C.DIM}# su -c{C.RESET} {truncate(c, 110)}")
    if confirm and not ask_yn(f"{C.YELLOW}Setuju? (y/N) ❯{C.RESET} "):
        warn("Dibatalkan."); return False
    good, log = bx.run_steps(cmds, timeout)
    for c, rc, out in log:
        if rc != 0:
            err(f"Gagal (rc={rc}): {truncate(c, 70)}")
            if out:
                print(f"    {C.DIM}{truncate(out, 300)}{C.RESET}")
    if good:
        ok("Selesai.")
    return good


def _box_restart(bx, info):
    return _box_run(bx, "Restart Box", bx.stop_cmds(info) + bx.start_cmds(info), 120)


def _box_status_line(bx, info):
    running, pid = bx.is_running(info)
    state = f"{C.GREEN}Berjalan (pid {pid}){C.RESET}" if running else f"{C.RED}Berhenti{C.RESET}"
    print(f"  Status : {state}")
    print(f"  Core   : {info['bin_name']}{('/' + info['xclash']) if info['bin_name'] == 'clash' and info['xclash'] else ''}"
          f"   Mode: {info['network_mode'] or '-'}   tproxy {info['tproxy_port'] or '-'} · redir {info['redir_port'] or '-'}")
    print(f"  Config : {C.BOLD}{info['config_name']}{C.RESET}  {C.DIM}({info['clash_dir']}){C.RESET}")
    if info["bin_name"] != "clash":
        warn("bin_name bukan clash — pasang/ganti config di sini hanya untuk core Clash/Mihomo.")
    return running


def _box_pick_config(bx, info, title, only_other=False):
    cfgs = bx.list_configs(info)
    if only_other:
        cfgs = [c for c in cfgs if not c["active"]]
    if not cfgs:
        warn(f"Tidak ada file .yaml di {info['clash_dir']}."); return None
    print(f"\n  {C.BOLD}{title}{C.RESET}")
    for i, c in enumerate(cfgs, 1):
        mark = f"{C.GREEN}● aktif{C.RESET}" if c["active"] else "       "
        print(f"  {C.CYAN}[{i}]{C.RESET} {c['name']:<28} {C.DIM}{_human_size(c['size']):>10}{C.RESET}  {mark}")
    pick = ask_choice(f"{C.YELLOW}Pilih (0 = batal) ❯{C.RESET} ", [str(i) for i in range(1, len(cfgs) + 1)], cancel=("0",))
    return None if pick == "0" else cfgs[int(pick) - 1]["name"]


def box_activate(bx, info, name, restart_hint=True):
    """Ganti name_clash_config di settings.ini (dengan cadangan + verifikasi). Tawarkan restart bila Box berjalan."""
    try:
        cmds = bx.plan_activate(name, info)
    except ValueError as e:
        err(str(e)); return False
    if not _box_run(bx, f"Aktifkan {name} (ubah name_clash_config di settings.ini)", cmds):
        return False
    if not bx.verify_active(name, info):
        err("settings.ini tidak berubah seperti yang diharapkan — cek manual (cadangan: settings.ini.hikari.bak).")
        return False
    ok(f"name_clash_config = {name}")
    info["config_name"] = name
    if restart_hint and bx.is_running(info)[0] and ask_yn(f"{C.YELLOW}Box sedang berjalan. Restart agar config baru dipakai? (y/N) ❯{C.RESET} "):
        _box_restart(bx, info)
    return True


def box_install_flow(src_dir=None, operator=None, bx=None, info=None):
    """Pasang hasil generate Box ke perangkat (dengan persetujuan), opsional aktifkan + restart."""
    if bx is None:
        bx, info = _box_ctx()
        if not bx:
            return
    src_dir = src_dir or os.path.join(BASE_DIR, PLATFORMS["box"]["out"])
    if operator is None:
        files = [os.path.basename(f) for f in generated_config_files("box")]
        if not files:
            warn("Belum ada config Box hasil generate (menu 1 → Convert → Box)."); pause(); return
        print(f"\n  {C.BOLD}Config Box hasil generate{C.RESET} {C.DIM}({src_dir}){C.RESET}")
        for i, f in enumerate(files, 1):
            print(f"  {C.CYAN}[{i}]{C.RESET} {f}")
        pick = ask_choice(f"{C.YELLOW}Pilih (0 = batal) ❯{C.RESET} ", [str(i) for i in range(1, len(files) + 1)], cancel=("0",))
        if pick == "0":
            return
        operator = os.path.splitext(files[int(pick) - 1])[0]
    cfg_local = os.path.join(src_dir, f"{operator}.yaml")
    if not os.path.isfile(cfg_local) or not os.path.isdir(os.path.join(src_dir, PLATFORMS["box"]["proxy_dir"], operator)):
        err(f"Hasil '{operator}' tidak lengkap (butuh {operator}.yaml dan proxy/{operator}/). Generate ulang dengan operator.")
        pause(); return
    try:
        warns = bx.port_warnings(bx.config_summary(read_text(cfg_local)), info)
    except (ValueError, OSError, yaml.YAMLError) as e:
        err(f"Config lokal tidak terbaca: {e}"); pause(); return
    for w in warns:
        warn(w)
    # pasang sebagai bukan-aktif dulu; nama operator dijadikan nama file di perangkat
    running = bx.is_running(info)[0]
    if running:
        warn("Box sedang berjalan. Dokumentasi BFR menyarankan mengubah config saat Box berhenti.")
    plan = bx.plan_install(src_dir, operator, info)
    print(f"\n  Tujuan: {C.BOLD}{info['clash_dir']}/{operator}.yaml{C.RESET}, {info['provide_path']}/{operator}/, {info['clash_dir']}/ruleset/")
    if not _box_run(bx, f"Pasang '{operator}' ke Box", plan):
        pause(); return
    activated = False
    if info["config_name"] != f"{operator}.yaml":
        if ask_yn(f"\n{C.YELLOW}Jadikan {operator}.yaml config aktif Box (ubah settings.ini)? (Y/n) ❯{C.RESET} ", default=True):
            activated = box_activate(bx, info, f"{operator}.yaml", restart_hint=False)
    else:
        activated = True
    if running:
        if ask_yn(f"{C.YELLOW}Restart Box agar perubahan dipakai? (Y/n) ❯{C.RESET} ", default=True):
            _box_restart(bx, info)
    elif activated and ask_yn(f"{C.YELLOW}Start Box sekarang? (y/N) ❯{C.RESET} "):
        _box_run(bx, "Start Box", bx.start_cmds(info), 120, confirm=False)
    pause()


def _box_view_config(bx, info):
    name = _box_pick_config(bx, info, "Lihat config")
    if not name:
        return
    path = f"{info['clash_dir']}/{name}"
    text = bx.read_remote(path)
    if text is None:
        err("Tidak terbaca."); pause(); return
    try:
        s = bx.config_summary(text)
    except (ValueError, yaml.YAMLError) as e:
        err(f"Bukan config Clash yang valid: {e}"); s = None
    if s:
        print(f"\n  {C.BOLD}{name}{C.RESET}  {C.DIM}{len(text.splitlines())} baris{C.RESET}")
        for k in ("mixed-port", "redir-port", "tproxy-port", "external-controller", "secret", "external-ui", "dns", "mode"):
            print(f"  {k:<20}: {s[k] if s[k] not in (None, '') else '-'}")
        print(f"  {'proxy-groups / rules':<20}: {s['groups']} / {s['rules']}")
        for k, v in s["providers"].items():
            print(f"  {C.DIM}provider {k:<14} → {v}{C.RESET}")
    if ask_yn(f"\n{C.YELLOW}Tampilkan teks penuh? (y/N) ❯{C.RESET} "):
        lines = text.splitlines()
        for i in range(0, len(lines), 40):
            print("\n".join(lines[i:i + 40]))
            if i + 40 < len(lines) and not ask_yn(f"{C.DIM}-- lanjut? ({min(i + 40, len(lines))}/{len(lines)}) (Y/n) --{C.RESET} ", default=True):
                break
    pause()


def _box_dashboard(bx, info):
    text = bx.read_remote(info["config_path"])
    if text is None:
        err(f"Config aktif tidak terbaca: {info['config_path']}"); pause(); return
    try:
        s = bx.config_summary(text)
    except (ValueError, yaml.YAMLError) as e:
        err(f"Config aktif tidak valid: {e}"); pause(); return
    url = bx.dashboard_url(s)
    ui = s.get("external-ui")
    print(f"\n  URL     : {C.BOLD}{C.CYAN}{url}{C.RESET}")
    print(f"  Secret  : {C.BOLD}{s['secret'] if s['secret'] else '(kosong)'}{C.RESET}")
    if ui:
        ui_path = ui if str(ui).startswith("/") else f"{info['clash_dir']}/{str(ui).lstrip('./')}"
        rc, _ = bx.run_root(f"[ -d {bx.q(ui_path)} ] && [ -n \"$(ls -A {bx.q(ui_path)} 2>/dev/null)\" ]", 15)
        if rc != 0:
            warn(f"Folder dashboard {ui_path} kosong/tidak ada.")
            if ask_yn(f"{C.YELLOW}Pasang dashboard UI lewat box.tool upxui? (y/N) ❯{C.RESET} "):
                _box_run(bx, "Pasang dashboard UI", [f"{info['box_dir']}/scripts/box.tool upxui"], 300, confirm=False)
    if not bx.is_running(info)[0]:
        warn("Box tidak berjalan — dashboard baru bisa dibuka setelah Start.")
    cmd = bx.open_url_cmd(url)
    if cmd and ask_yn(f"{C.YELLOW}Buka di browser? (Y/n) ❯{C.RESET} ", default=True):
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ok("Perintah buka dikirim (belum diuji di semua perangkat).")
        except OSError as e:
            err(f"Gagal membuka: {e}")
    elif not cmd:
        print(f"  {C.DIM}Buka URL di atas di browser (tidak ada termux-open-url / am).{C.RESET}")
    pause()


def _box_logs(bx, info):
    print(f"\n  {C.CYAN}[1]{C.RESET} Log layanan  {C.DIM}({info['log']}){C.RESET}\n  {C.CYAN}[2]{C.RESET} Log core     {C.DIM}({info['bin_log']}){C.RESET}")
    pick = ask_choice(f"{C.YELLOW}Pilih (0 = batal) ❯{C.RESET} ", ("1", "2"), cancel=("0",))
    if pick == "0":
        return
    rc, out = bx.run_root(bx.tail_cmd(info["log"] if pick == "1" else info["bin_log"]), 20)
    print(f"\n{out if out else '(kosong / tidak terbaca)'}")
    pause()


def _box_tools(bx, info):
    keys = list(bx.TOOL_CMDS)
    print()
    for i, k in enumerate(keys, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET} {bx.TOOL_CMDS[k]}")
    pick = ask_choice(f"{C.YELLOW}Pilih (0 = batal) ❯{C.RESET} ", [str(i) for i in range(1, len(keys) + 1)], cancel=("0",))
    if pick == "0":
        return
    k = keys[int(pick) - 1]
    _box_run(bx, bx.TOOL_CMDS[k], [f"{info['box_dir']}/scripts/box.tool {k}"], 600)
    pause()


def feature_box_menu():
    clear_screen(); banner("BOX"); section("Box Utilities")
    print(f"  {C.DIM}Memakai akses root (su) untuk mengendalikan Box for Root. Tiap perubahan menampilkan perintahnya\n"
          f"  dan meminta persetujuanmu dulu. Popup izin root dari Magisk/KernelSU/APatch bisa muncul.{C.RESET}")
    bx, info = _box_ctx()
    if not bx:
        return
    while True:
        clear_screen(); banner("BOX"); section("Box Utilities")
        info = bx.box_info()
        if info.get("error"):
            err(info["error"]); pause(); return
        running = _box_status_line(bx, info)
        print(sep(50))
        print(f"  {C.CYAN}[1]{C.RESET} Start   {C.CYAN}[2]{C.RESET} Stop   {C.CYAN}[3]{C.RESET} Restart   {C.CYAN}[4]{C.RESET} Status rinci")
        print(f"  {C.CYAN}[5]{C.RESET} Pasang config hasil generate  {C.DIM}(→ {info['clash_dir']}/){C.RESET}")
        print(f"  {C.CYAN}[6]{C.RESET} Ganti config aktif")
        print(f"  {C.CYAN}[7]{C.RESET} Lihat / daftar config")
        print(f"  {C.CYAN}[8]{C.RESET} Buka dashboard")
        print(f"  {C.CYAN}[9]{C.RESET} Log")
        print(f"  {C.CYAN}[A]{C.RESET} Update  {C.DIM}(geox · subs · kernel · dashboard UI){C.RESET}")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask_choice(f"{C.YELLOW}Pilih menu ❯{C.RESET} ", ("1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "0"))
        if pilih == "0":
            return
        elif pilih == "1":
            if running:
                warn("Box sudah berjalan."); pause()
            else:
                _box_run(bx, "Start Box", bx.start_cmds(info), 120); pause()
        elif pilih == "2":
            if not running:
                warn("Box sudah berhenti."); pause()
            else:
                _box_run(bx, "Stop Box", bx.stop_cmds(info), 120); pause()
        elif pilih == "3":
            _box_restart(bx, info); pause()
        elif pilih == "4":
            rc, out = bx.service_status_text(info)
            print(f"\n{out if out else '(tanpa keluaran)'}\n  {C.DIM}rc={rc}{C.RESET}"); pause()
        elif pilih == "5":
            box_install_flow(bx=bx, info=info)
        elif pilih == "6":
            name = _box_pick_config(bx, info, "Ganti config aktif", only_other=True)
            if name:
                box_activate(bx, info, name); pause()
        elif pilih == "7":
            _box_view_config(bx, info)
        elif pilih == "8":
            _box_dashboard(bx, info)
        elif pilih == "9":
            _box_logs(bx, info)
        elif pilih == "a":
            _box_tools(bx, info)


def main():
    ensure_emoji_file()
    startup_notes = migrate_legacy_layout()
    load_emoji_cfg()
    if EMOJI_WARNING:
        startup_notes.append(EMOJI_WARNING)
    try:
        prepare_dirs()
    except OSError as e:
        err(f"Tidak bisa membuat folder hasil/: {e}")
        print("  Pindahkan folder script ke /storage/emulated/0/ (jalankan `termux-setup-storage` dulu).")
        sys.exit(1)
    while True:
        clear_screen(); banner(info="full"); section("MENU UTAMA")
        for n in startup_notes:
            warn(n)
        print(f"  {C.CYAN}[1]{C.RESET} Convert")
        print(f"  {C.CYAN}[2]{C.RESET} Edit Configuration")
        print(f"  {C.CYAN}[3]{C.RESET} Check Status")
        print(f"  {C.CYAN}[4]{C.RESET} Validasi / Audit Config")
        print(f"  {C.CYAN}[5]{C.RESET} Miscellaneous")
        print(f"  {C.CYAN}[6]{C.RESET} Box Utilities {C.DIM}(root: start/stop, pasang config, dashboard){C.RESET}")
        print(sep(50))
        print(f"  {C.RED}[Q]{C.RESET} Exit")
        print(sep(50))
        pilihan = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip().lower()
        if pilihan == "1":   feature_convert_menu()
        elif pilihan == "2": feature_edit_config()
        elif pilihan == "3": feature_check_status()
        elif pilihan == "4": feature_validate()
        elif pilihan == "5": feature_misc_menu()
        elif pilihan == "6": feature_box_menu()
        elif pilihan == "q":
            clear_screen(); print(f"\n  {C.GREEN}Terima kasih sudah pakai Hikari /.CLASH!{C.RESET}\n"); sys.exit(0)
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.RED}Program dihentikan.{C.RESET}\n")
        sys.exit(0)
