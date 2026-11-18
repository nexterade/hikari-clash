#!/usr/bin/env python3
"""
HIKARI /.CLASH — CONVERTER  v3
URI <-> Clash (Mihomo) converter + generator config untuk Box / Nikki / OpenClash.
(sebelumnya "Hikari Subclash" / Hikari-SC)
"""

import base64
import copy
import glob
import json
import os
import random
import re
import secrets
import shutil
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
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "template")
TEMPLATE_PATH = os.path.join(TEMPLATE_DIR, "template.yaml")  # working copy (boleh diedit lewat menu)
TEMPLATE_GLOB = "config_v*.yaml"                             # master di template/; dipakai kalau template.yaml belum ada

# node dari link biasanya pakai bug-host/SNI custom -> cert tidak cocok.
# Kalau link eksplisit bilang allowInsecure=0 maka dihormati.
DEFAULT_SKIP_CERT_VERIFY = True

EMOJI_PATH = os.path.join(SCRIPT_DIR, "emoji.json")        # daftar emoji nama node (bisa diedit lewat menu)
# Daftar bawaan = isi emoji.json bawaan repo (dipakai kalau file hilang / rusak / di-Reset lewat menu).
# Sengaja tanpa emoji yang dipakai nama group di template (🧩 🛸 👒 🌳 💤 💕 🍪 🪼 🎮 ✂️ 🐬).
DEFAULT_EMOJIS = ["🦊", "🎿", "💟", "🩻", "💭", "🔮", "🐠", "🍂", "🐣", "🧢", "🪭",
                  "🍞", "☕", "🧊", "🍕", "🍟", "🛋️", "🏙️", "🌃", "🌠", "🌌", "⛱️"]

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


def load_settings():
    """{'isp': id, 'isp_fields': [...]} dari settings.json; nilai tidak valid -> default."""
    cfg = {"isp": "none", "isp_fields": []}
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
    return cfg


def save_settings(cfg):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
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


def banner(mode="CONVERTER"):
    """Banner Hikari /.CLASH (definisi visual ada di banner.py)."""
    _show_banner(mode=mode)
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
    """{'enabled': bool, 'emojis': [str]} dari emoji.json.
    File tidak ada -> default. JSON rusak -> coba perbaiki koma berlebih (trailing comma), kalau tetap gagal
    pakai default; keduanya meninggalkan pesan di EMOJI_WARNING (tidak lagi diam-diam)."""
    global EMOJI_WARNING
    EMOJI_WARNING = ""
    cfg = {"enabled": True, "emojis": list(DEFAULT_EMOJIS)}
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
            EMOJI_WARNING = f"emoji.json rusak ({e}); memakai daftar bawaan"
            return cfg
    if not isinstance(data, dict):
        EMOJI_WARNING = "emoji.json harus berupa objek {\"enabled\": ..., \"emojis\": [...]}; memakai daftar bawaan"
        return cfg
    if isinstance(data.get("enabled"), bool):
        cfg["enabled"] = data["enabled"]
    emojis = data.get("emojis", [])
    items = [e.strip() for e in emojis if isinstance(e, str) and e.strip()] if isinstance(emojis, list) else []
    if items:
        cfg["emojis"] = list(dict.fromkeys(items))
    else:
        EMOJI_WARNING = EMOJI_WARNING or "emoji.json: daftar 'emojis' kosong/tidak valid; memakai daftar bawaan"
    return cfg


def save_emoji_cfg(cfg):
    with open(EMOJI_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")


def starts_with_emoji(name):
    """True kalau nama sudah diawali emoji/simbol (🪟, 🇸🇬, ⭐, ✅, ...), apa pun emojinya."""
    name = str(name).lstrip()
    if not name:
        return False
    ch = name[0]
    return 0x1F000 <= ord(ch) <= 0x1FAFF or unicodedata.category(ch) in ("So", "Sk")


def apply_emoji(nodes, cfg=None):
    """Awali nama node dengan emoji acak: 'Singapore' -> '🦊 Singapore'.
    Emoji tidak berulang dalam satu batch selama daftar cukup. Nama yang SUDAH diawali emoji
    (apa pun, mis. '🪟 Rekayasa' atau '🇸🇬 Singapore') dibiarkan, tidak jadi dobel."""
    cfg = cfg or load_emoji_cfg()
    emojis = cfg["emojis"]
    if not cfg["enabled"] or not emojis:
        return 0
    pool, count = [], 0
    for node in nodes:
        name = str(node["name"])
        if starts_with_emoji(name) or any(name.startswith(e) for e in emojis):
            continue
        if not pool:
            pool = random.sample(emojis, len(emojis))
        node["name"] = f"{pool.pop()} {name}"
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


def _remap_path(path, platform):
    P = PLATFORMS[platform]
    if not isinstance(path, str):
        return path
    for old, folder in (("./proxy/", P["proxy_dir"]), ("./ruleset/", P["rule_dir"])):
        if path.startswith(old):
            return f'{P["prefix"]}{folder}/{path[len(old):]}'
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


def build_config(tpl_text, platform, provider_mode="template", secret_mode="template", isp=None):
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
        cfg["external-controller"] = "0.0.0.0:9090"
        if _drop_wifi(cfg):
            notes.append("rule/group/provider WIFI dibuang (SRC-IP 192.168/16 menangkap semua client LAN di OpenWrt)")

    for sect in ("proxy-providers", "rule-providers"):
        for prov in (cfg.get(sect) or {}).values():
            if isinstance(prov, dict) and "path" in prov:
                prov["path"] = _remap_path(prov["path"], platform)

    if provider_mode == "offline":
        n = 0
        for prov in (cfg.get("rule-providers") or {}).values():
            if prov.get("type") == "http":
                prov["type"] = "file"
                for k in ("url", "interval", "proxy"):
                    prov.pop(k, None)
                n += 1
        notes.append(f"mode offline: {n} rule-provider http -> file (tanpa update otomatis)")

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

    for g in cfg.get("proxy-groups") or []:
        for x in g.get("proxies") or []:
            if x not in valid_targets:
                E(f"group '{g['name']}' mengacu ke '{x}' yang tidak ada")
        for u in g.get("use") or []:
            if u not in pproviders:
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
    psn = dns.get("proxy-server-nameserver") or []
    if psn and all("://" in str(x) for x in psn):
        W("proxy-server-nameserver DoH semua: kalau ISP me-reset DoH, domain server proxy tidak bisa di-resolve (semua node timeout)")
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
                    W(f"{os.path.basename(fn)} besar ({os.path.getsize(fn)//1024} KB) — pertimbangkan menu Tools > Padatkan port")
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
    direct_plain = [x for x in dns.get("direct-nameserver") or [] if "://" not in str(x)]
    if direct_plain:
        out.append(("INFO", f"direct-nameserver polos ({', '.join(map(str, direct_plain))}) — hanya untuk domain DIRECT, bukan domain yang lewat proxy"))
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
    return [x for x in (data or {}).get("proxies", []) or [] if isinstance(x, dict)] if isinstance(data, dict) else []


def save_proxy_yaml(proxies, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(dump_yaml({"proxies": proxies}))


def setup_full_config(proxies, target_name, platform, provider_mode="template", write_mode="replace", secret_mode="template", isp=None):
    """Return (out_dir, notes, issues, error)."""
    tpl = find_template()
    if not tpl:
        return None, [], [], "template tidak ditemukan (template/template.yaml / template/config_v*.yaml)"
    if not os.path.isdir(RULESET_SOURCE):
        return None, [], [], f"folder 'ruleset' tidak ditemukan di samping script ({RULESET_SOURCE})"

    P = PLATFORMS[platform]
    out_dir = os.path.join(BASE_DIR, P["out"])
    proxy_dir = os.path.join(out_dir, P["proxy_dir"])
    try:
        os.makedirs(proxy_dir, exist_ok=True)
        cfg, notes = build_config(read_text(tpl), platform, provider_mode, secret_mode, isp)

        # node: dedupe terhadap nama bawaan template (+ node lama kalau mode append)
        target_path = os.path.join(proxy_dir, target_name)
        existing = load_provider_nodes(target_path) if write_mode == "append" else []
        nodes = dedupe_names([dict(n) for n in proxies], reserved_names() | {x["name"] for x in existing})
        save_proxy_yaml(existing + nodes, target_path)

        other = os.path.join(proxy_dir, "trial.yaml" if target_name == "active.yaml" else "active.yaml")
        if not os.path.exists(other):
            with open(other, "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

        target_rules = os.path.join(out_dir, P["rule_dir"])
        if os.path.exists(target_rules):
            shutil.rmtree(target_rules)
        shutil.copytree(RULESET_SOURCE, target_rules)

        with open(os.path.join(out_dir, "config.yaml"), "w", encoding="utf-8") as f:
            f.write(render_config(cfg, platform, "v3"))
    except PermissionError as e:
        return None, [], [], f"PermissionError: {e}. Taruh folder script di /storage/emulated/0/ (bukan ~ Termux)."
    except (OSError, ValueError, yaml.YAMLError) as e:
        return None, [], [], str(e)

    issues = validate_config(cfg, platform, out_dir)
    return out_dir, notes, issues, None


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
        section(f"Preview Input ({len(valid)} Valid, {len(invalid)} Gagal)")
        if valid:
            print(f"  {C.BOLD}{'No':<4} | {'Tipe':<7} | {'Nama Node':<20} | {'Server'}{C.RESET}")
            print(f"  {C.GRAY}{'-'*4}-+-{'-'*7}-+-{'-'*20}-+-{'-'*15}{C.RESET}")
            for idx, p in enumerate(valid, 1):
                print(f"  {C.CYAN}{idx:<4}{C.RESET} | {p['type'].upper():<7} | "
                      f"{truncate(str(p['name']), 20):<20} | {C.DIM}{truncate(str(p['server']), 15)}{C.RESET}")
        for i, ln, reason in invalid:
            print(f"  {C.RED}✗ baris {i+1}{C.RESET} {C.DIM}{truncate(ln, 28)}{C.RESET} → {reason}")

        print()
        section("Aksi")
        print(f"  {C.YELLOW}[T]{C.RESET} Tambah node lain")
        print(f"  {C.YELLOW}[H]{C.RESET} Hapus node (nomor, mis: 1 atau 1,3)")
        print(f"  {C.GREEN}[L]{C.RESET} Lanjut Proses")
        print(f"  {C.RED}[B]{C.RESET} Batal / Kembali ke Menu")
        print(sep(50))
        aksi = ask(f"{C.YELLOW}Pilih Aksi ❯{C.RESET} ").strip().lower()

        if aksi == "l":
            if valid:
                break
            warn("Belum ada node valid."); time.sleep(1.2)
        elif aksi == "b":
            return
        elif aksi == "t":
            print(); section("Tambah Node Lagi")
            extra = _collect_lines(["Paste tautan baru (satu per baris).", "Enter kosong = selesai.",
                                    "Ketik 'batalkan' untuk batal nambah."])
            if extra:
                lines += extra
        elif aksi == "h":
            raw = ask("  Nomor yang mau dihapus ❯ ").strip()
            try:
                nums = [int(x) for x in raw.split(",") if x.strip()]
            except ValueError:
                err("Input tidak valid."); time.sleep(1.2); continue
            gone = {valid[n - 1]["_orig_idx"] for n in nums if 1 <= n <= len(valid)}
            lines = [ln for i, ln in enumerate(lines) if i not in gone]
            if not any(ln.strip() for ln in lines):
                err("Semua tautan dihapus. Kembali ke menu."); time.sleep(1.2); return
        else:
            err("Aksi tidak dikenal."); time.sleep(0.8)

    proxies = [{k: v for k, v in p.items() if k != "_orig_idx"} for p in valid]
    n_emoji = apply_emoji(proxies)

    print(); section("Pilih Output Config")
    print(f"  {C.CYAN}[B]{C.RESET} Config for Box (Android)")
    print(f"  {C.CYAN}[N]{C.RESET} Config for Nikki (OpenWrt)")
    print(f"  {C.CYAN}[O]{C.RESET} Config for OpenClash (OpenWrt)")
    print(sep(50))
    platform = {"b": "box", "n": "nikki", "o": "openclash"}
    while True:
        plat = platform.get(ask(f"{C.YELLOW}Pilih (B/N/O) ❯{C.RESET} ").strip().lower())
        if plat:
            break
        err("Pilihan tidak valid.")

    print(); section("Pilih Target Provider")
    print(f"  {C.CYAN}[1]{C.RESET} active.yaml\n  {C.CYAN}[2]{C.RESET} trial.yaml")
    print(sep(50))
    while True:
        c = ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
        if c in ("1", "2"):
            target_name = "active.yaml" if c == "1" else "trial.yaml"; break
        err("Pilihan tidak valid.")

    P = PLATFORMS[plat]
    existing = load_provider_nodes(os.path.join(BASE_DIR, P["out"], P["proxy_dir"], target_name))
    write_mode = "replace"
    if existing:
        print()
        warn(f"{target_name} sudah berisi {len(existing)} node.")
        print(f"  {C.CYAN}[1]{C.RESET} Ganti (timpa)   {C.CYAN}[2]{C.RESET} Tambahkan ke yang lama")
        write_mode = "append" if ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip() == "2" else "replace"

    print(); section("Mode Rule-Provider")
    print(f"  {C.CYAN}[1]{C.RESET} Ikuti template {C.DIM}(http: auto-update dari GitHub){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Offline        {C.DIM}(file lokal saja, tanpa update){C.RESET}")
    provider_mode = "offline" if ask(f"{C.YELLOW}Pilih (1/2, Enter=1) ❯{C.RESET} ").strip() == "2" else "template"

    print(); section("Secret Dashboard")
    tpl_secret = _template_secret()
    print(f"  {C.CYAN}[1]{C.RESET} Ikuti template {C.DIM}(sekarang: {tpl_secret or 'kosong'}){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Acak           {C.DIM}(dibuat otomatis, ditampilkan setelah generate){C.RESET}")
    secret_mode = "random" if ask(f"{C.YELLOW}Pilih (1/2, Enter=1) ❯{C.RESET} ").strip() == "2" else "template"

    isp = None
    if plat in ISP_PLATFORMS:
        saved = load_settings()["isp"]
        print(); section("Profil ISP")
        print(f"  {C.CYAN}[1]{C.RESET} Umum {C.DIM}(tanpa DNS ISP){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} XL Axiata {C.DIM}(wajib untuk tunneling di XL: +{', '.join(ISP_PROFILES['xl']['ips'])}){C.RESET}")
        pick = ask(f"{C.YELLOW}Pilih (Enter = pengaturan tersimpan: {ISP_PROFILES[saved]['label']}) ❯{C.RESET} ").strip()
        isp = {"1": "none", "2": "xl"}.get(pick)

    print()
    spinner("Membangun & memvalidasi config", 0.5)
    out_dir, notes, issues, error = setup_full_config(proxies, target_name, plat, provider_mode, write_mode, secret_mode, isp)
    if error:
        err(f"Gagal: {error}\n"); pause(); return

    ok(f"Config {P['label']} siap di:\n  {C.BOLD}{C.CYAN}{out_dir}/{C.RESET}")
    print(f"  {C.DIM}├── config.yaml{C.RESET}")
    print(f"  {C.DIM}├── {P['proxy_dir']}/{target_name} ({len(proxies)} node baru){C.RESET}")
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
        print(f"\n  {C.DIM}Nama node (emoji acak, ubah daftar di Edit Configuration → Emoji Node):{C.RESET}")
        for p in proxies[:10]:
            print(f"    {p['name']}")
        if len(proxies) > 10:
            print(f"    {C.DIM}... +{len(proxies) - 10} lainnya{C.RESET}")
    secret = yaml.safe_load(read_text(os.path.join(out_dir, "config.yaml"))).get("secret")
    print(f"\n  Dashboard secret : {C.BOLD}{secret if secret else '(kosong)'}{C.RESET}")

    print()
    if plat == "box":
        print(f"{C.YELLOW}💡 BOX ANDROID:{C.RESET} copy SEMUA isi folder di atas ke {C.BOLD}/data/adb/box/clash/{C.RESET}")
    elif plat == "nikki":
        print(f"{C.YELLOW}💡 NIKKI:{C.RESET}")
        print(f"   1. {C.BOLD}config.yaml{C.RESET} → {C.BOLD}/etc/nikki/profiles/{C.RESET}")
        print(f"   2. folder {C.BOLD}proxy/{C.RESET} & {C.BOLD}ruleset/{C.RESET} → {C.BOLD}{NIKKI_RUN_DIR}/{C.RESET}")
    else:
        print(f"{C.YELLOW}💡 OPENCLASH:{C.RESET}")
        print(f"   1. {C.BOLD}config.yaml{C.RESET} → {C.BOLD}/etc/openclash/config/{C.RESET}")
        print(f"   2. folder {C.BOLD}proxy_provider/{C.RESET} & {C.BOLD}rule_provider/{C.RESET} → {C.BOLD}/etc/openclash/{C.RESET}")
    pause("Tekan Enter untuk kembali ke menu...")


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
    if ask("  Simpan ke file? (y/n) ❯ ").strip().lower() == "y":
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
        cp = os.path.join(BASE_DIR, P["out"], "config.yaml")
        (print(f"  {C.GREEN}✓{C.RESET} {P['label']:<24}: {C.GREEN}Siap{C.RESET}") if os.path.isfile(cp)
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
    ("fallback", "DNS cadangan", "hanya muncul kalau ada di template"),
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
            out.append(("WARN", "proxy-server-nameserver terenkripsi semua: kalau ISP me-reset DoH/DoT, domain server proxy gagal resolve (semua node timeout)"))
    return out


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
    fields = [f for f in DNS_FIELDS if f[0] != "fallback" or "fallback" in dns]
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
    if blocking:
        err("Ada kesalahan di atas — perubahan dibatalkan."); pause(); return False
    if ask(f"\n  Terapkan? (y/N) ❯ ").strip().lower() != "y":
        return False
    new_text = content
    for field, new in changes.items():
        new_text, found = block_set_list(new_text, "dns", field, new)
        if not found:
            err("Blok dns tidak ditemukan di template."); pause(); return False
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
            if ask(f"{C.YELLOW}{field} (Enter=1) ❯{C.RESET} ").strip() == "2":
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
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip()
        if pilih == "0":
            return
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
    while True:
        clear_screen(); banner(); section("Emoji Node")
        state = f"{C.GREEN}ON{C.RESET}" if cfg["enabled"] else f"{C.RED}OFF{C.RESET}"
        print(f"  Status : {state}   {C.DIM}(nama 'Singapore' → '{cfg['emojis'][0] if cfg['emojis'] else '🦊'} Singapore'){C.RESET}")
        print(f"  Daftar : {len(cfg['emojis'])} emoji\n")
        for i in range(0, len(cfg["emojis"]), 6):
            row = cfg["emojis"][i:i + 6]
            print("  " + "   ".join(f"{C.DIM}{i + j + 1:>2}.{C.RESET} {e}" for j, e in enumerate(row)))
        print(); print(sep(50))
        print(f"  {C.CYAN}[A]{C.RESET} Tambah emoji   {C.DIM}(pisahkan dengan spasi/koma){C.RESET}")
        print(f"  {C.CYAN}[H]{C.RESET} Hapus emoji    {C.DIM}(nomor, mis: 1,4,7){C.RESET}")
        print(f"  {C.CYAN}[T]{C.RESET} Nyala / Matikan fitur emoji")
        print(f"  {C.CYAN}[R]{C.RESET} Reset ke daftar bawaan")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip().lower()
        changed = True
        if pilih == "0":
            return
        elif pilih == "a":
            raw = ask("  Emoji baru ❯ ").replace(",", " ").split()
            good = [t for t in raw if _is_emoji_token(t) and t not in cfg["emojis"]]
            bad = [t for t in raw if not _is_emoji_token(t)]
            cfg["emojis"] = list(dict.fromkeys(cfg["emojis"] + good))
            if bad:
                warn("Dilewati (bukan emoji): " + " ".join(bad))
            if not good:
                changed = False; time.sleep(1.2)
        elif pilih == "h":
            raw = ask("  Nomor yang dihapus ❯ ").replace(",", " ").split()
            try:
                gone = {int(x) - 1 for x in raw}
            except ValueError:
                err("Input tidak valid."); time.sleep(1.2); continue
            left = [e for i, e in enumerate(cfg["emojis"]) if i not in gone]
            if not left:
                warn("Daftar tidak boleh kosong (matikan saja lewat [T])."); time.sleep(1.5); continue
            cfg["emojis"] = left
        elif pilih == "t":
            cfg["enabled"] = not cfg["enabled"]
        elif pilih == "r":
            cfg = {"enabled": cfg["enabled"], "emojis": list(DEFAULT_EMOJIS)}
        else:
            changed = False
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
#  Feature: Tools Ruleset (padatkan DST-PORT)
# =====================================================================
def compact_port_payload(payload):
    """Gabung DST-PORT tunggal/berurutan jadi range. Return (payload_baru, jumlah_port_asal)."""
    ports, rest, n_in = set(), [], 0
    for item in payload:
        m = re.fullmatch(r"DST-PORT,\s*(\d+)(?:-(\d+))?", str(item).strip())
        if not m:
            rest.append(item); continue
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        ports.update(range(a, b + 1)); n_in += 1
    ranges, start = [], None
    for p in sorted(ports):
        if start is None:
            start = prev = p
        elif p == prev + 1:
            prev = p
        else:
            ranges.append((start, prev)); start = prev = p
    if start is not None:
        ranges.append((start, prev))
    out = [f"DST-PORT,{a}" if a == b else f"DST-PORT,{a}-{b}" for a, b in ranges]
    return rest + out, n_in


def feature_tools():
    clear_screen(); banner(); section("Tools Ruleset")
    print(f"  {C.CYAN}[1]{C.RESET} Padatkan port-games.yaml {C.DIM}(gabung DST-PORT jadi range){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
    if ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip() != "1":
        return
    fp = os.path.join(RULESET_SOURCE, "port-games.yaml")
    if not os.path.isfile(fp):
        err("ruleset/port-games.yaml tidak ada."); pause(); return
    try:
        data = yaml.safe_load(read_text(fp))
        payload = data["payload"]
    except Exception as e:
        err(f"Gagal baca: {e}"); pause(); return
    new, n_in = compact_port_payload(payload)
    print(f"  {len(payload)} baris → {len(new)} baris (perilaku routing identik)")
    if ask("  Terapkan? Backup disimpan sebagai port-games.yaml.bak (y/N) ❯ ").strip().lower() != "y":
        return
    backup_file(fp)
    with open(fp, "w", encoding="utf-8") as f:
        f.write("# Port game — dipadatkan oleh hikari_converter (range = perilaku sama dengan DST-PORT satuan)\n"
                "# Sintaks range: https://wiki.metacubex.one/en/handbook/syntax (Port Ranges)\npayload:\n")
        for x in new:
            f.write(f"  - {x}\n")
    ok("port-games.yaml dipadatkan.")
    print(f"  {C.DIM}Jangan lupa upload versi baru ini ke repo kalau rule-provider-nya type http.{C.RESET}")
    pause()


# =====================================================================
#  Feature: Miscellaneous (menu 7)
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
    if ask(f"  {os.path.basename(path)} sudah ada. Timpa? (y/N) ❯ ").strip().lower() == "y":
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
            as_text = ask(f"{C.YELLOW}Format keluaran (1/2, Enter=1) ❯{C.RESET} ").strip() == "2"
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
def _generated_configs():
    out = []
    for pid, P in PLATFORMS.items():
        cp = os.path.join(BASE_DIR, P["out"], "config.yaml")
        if os.path.isfile(cp):
            out.append((pid, cp))
    return out


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
    if good and ask(f"\n  Simpan {len(good)} node yang hidup ke file provider? (y/N) ❯ ").strip().lower() == "y":
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
    plat = {"b": "box", "n": "nikki", "o": "openclash"}.get(ask(f"{C.YELLOW}Platform (Enter=B) ❯{C.RESET} ").strip().lower() or "b")
    if not plat:
        err("Pilihan tidak valid."); time.sleep(1); return
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


def feature_misc_menu():
    while True:
        clear_screen(); banner("MISC"); section("Miscellaneous")
        print(f"  {C.CYAN}[1]{C.RESET} Rule-Provider Converter  {C.DIM}(.mrs ⇄ .yaml / .txt){C.RESET}")
        print(f"  {C.CYAN}[2]{C.RESET} Config Tester            {C.DIM}(validator + mihomo -t bila core ada){C.RESET}")
        print(f"  {C.CYAN}[3]{C.RESET} Proxy Node Tester        {C.DIM}(offline atau via core){C.RESET}")
        print(f"  {C.CYAN}[4]{C.RESET} Route Tester             {C.DIM}(domain/IP ➜ rule & group){C.RESET}")
        print(f"  {C.CYAN}[5]{C.RESET} Info Lingkungan")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilih == "0":
            return
        elif pilih == "1": feature_misc_rules()
        elif pilih == "2": feature_misc_config()
        elif pilih == "3": feature_misc_nodes()
        elif pilih == "4": feature_misc_route()
        elif pilih == "5": feature_misc_info()
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


# =====================================================================
#  Menu
# =====================================================================
def feature_convert_menu():
    clear_screen(); banner(); section("Menu Convert")
    print(f"  {C.CYAN}[1]{C.RESET} URI (VLESS/VMess/Trojan)  ➜  Clash (YAML)")
    print(f"  {C.CYAN}[2]{C.RESET} Clash (YAML)              ➜  URI (VLESS/VMess/Trojan)")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
    pilihan = ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
    if pilihan == "1":
        clear_screen(); banner(); feature_convert_to_clash()
    elif pilihan == "2":
        feature_convert_to_uri()


def ensure_emoji_file():
    """Pastikan emoji.json ada (isi bawaan) supaya gampang diedit manual maupun lewat menu."""
    if not os.path.isfile(EMOJI_PATH):
        try:
            save_emoji_cfg({"enabled": True, "emojis": list(DEFAULT_EMOJIS)})
        except OSError:
            pass


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
        clear_screen(); banner(); section("MENU UTAMA")
        for n in startup_notes:
            warn(n)
        print(f"  {C.CYAN}[1]{C.RESET} Convert")
        print(f"  {C.CYAN}[2]{C.RESET} Edit Configuration")
        print(f"  {C.CYAN}[3]{C.RESET} Check Status")
        print(f"  {C.CYAN}[4]{C.RESET} Validasi / Audit Config")
        print(f"  {C.CYAN}[5]{C.RESET} Tools Ruleset")
        print(f"  {C.CYAN}[6]{C.RESET} Exit")
        print(f"  {C.CYAN}[7]{C.RESET} Miscellaneous {C.DIM}(converter .mrs, tester config/node/route){C.RESET}\n{sep(50)}")
        pilihan = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilihan == "1":   feature_convert_menu()
        elif pilihan == "2": feature_edit_config()
        elif pilihan == "3": feature_check_status()
        elif pilihan == "4": feature_validate()
        elif pilihan == "5": feature_tools()
        elif pilihan == "7": feature_misc_menu()
        elif pilihan == "6":
            clear_screen(); print(f"\n  {C.GREEN}Terima kasih sudah pakai Hikari /.CLASH!{C.RESET}\n"); sys.exit(0)
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.RED}Program dihentikan.{C.RESET}\n")
        sys.exit(0)
