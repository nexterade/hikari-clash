#!/usr/bin/env python3
"""Info pengguna di bawah banner Hikari /.CLASH: IP, lokasi, jaringan (WiFi/Data), status core, usage.

Hanya stdlib. Setiap pengambilan data: timeout pendek, jalan paralel di thread daemon, di-cache, dan gagal
dengan tenang (nilai kosong tampil sebagai "-"). Tidak pernah memanggil `su`, jadi tidak memicu popup root.

Otomatis mati kalau stdout bukan terminal (pipe / tes) kecuali HIKARI_INFO diisi eksplisit.
"""

import glob
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener, urlopen

try:
    import fcntl
except ImportError:                      # Windows: nama interface tidak terbaca, IP tetap tampil
    fcntl = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_PATH = os.path.join(SCRIPT_DIR, "settings.json")

PLATFORM_NAMES = {"box": "Box", "nikki": "Nikki", "openclash": "OpenClash"}
PREF_DEFAULTS = {"mode": "full", "mask": False, "lookup": True, "platform": "auto",
                 "api": "", "secret": "", "stats": "", "operator": ""}
MODES = ("full", "compact", "off")

DEFAULT_API = "127.0.0.1:9090"           # external-controller Box (Nikki/OpenClash: 0.0.0.0:9090 di router)
DEFAULT_STATS = "127.0.0.1:9099"         # Hikari NetStat
SKIP_IFACE = ("lo", "tun", "meta", "clash", "dummy", "ifb", "sit", "ip6", "docker", "veth")
WIFI_PREFIX = ("wlan", "wl", "swlan", "wifi", "ath", "ra")
MOBILE_PREFIX = ("rmnet", "ccmni", "v4-rmnet", "seth", "pdp", "ccinet", "wwan", "ppp")
LAN_PREFIX = ("eth", "en", "br-", "br0", "lan", "wan", "rndis", "usb")
CORE_COMM = ("mihomo", "clash")
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")      # fake-ip Mihomo / TUN
PING_URL = "http://cp.cloudflare.com/generate_204"
TTL = {"net": 5, "core": 10, "usage": 10, "public": 120, "ping": 30}
DEADLINE = 3.5                                           # batas tunggu total satu kali render (detik)


# ── Pengaturan ───────────────────────────────────────────────────────────────

def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y")


def load_prefs(path=None, use_env=True):
    """Pengaturan info banner: settings.json (kunci "info") lalu env HIKARI_INFO* menimpa (use_env=False: file saja)."""
    prefs = dict(PREF_DEFAULTS)
    try:
        with open(path or SETTINGS_PATH, encoding="utf-8") as f:
            data = json.load(f).get("info")
    except (OSError, ValueError, AttributeError):
        data = None
    if isinstance(data, dict):
        for k, dv in PREF_DEFAULTS.items():
            if k in data and isinstance(data[k], type(dv)):
                prefs[k] = data[k]
    if prefs["mode"] not in MODES:
        prefs["mode"] = "full"
    if prefs["platform"] not in ("auto",) + tuple(PLATFORM_NAMES):
        prefs["platform"] = "auto"
    if not use_env:
        return prefs
    env = os.environ
    if env.get("HIKARI_INFO", "").strip().lower() in MODES:
        prefs["mode"] = env["HIKARI_INFO"].strip().lower()
    if env.get("HIKARI_INFO_MASK"):
        prefs["mask"] = _truthy(env["HIKARI_INFO_MASK"])
    if env.get("HIKARI_INFO_LOOKUP"):
        prefs["lookup"] = _truthy(env["HIKARI_INFO_LOOKUP"])
    if env.get("HIKARI_PLATFORM", "").strip().lower() in PLATFORM_NAMES:
        prefs["platform"] = env["HIKARI_PLATFORM"].strip().lower()
    for key, name in (("api", "HIKARI_API"), ("secret", "HIKARI_SECRET"), ("stats", "HIKARI_STATS"),
                      ("operator", "HIKARI_OPERATOR")):
        if env.get(name):
            prefs[key] = env[name].strip()
    return prefs


def save_prefs(prefs, path=None):
    """Simpan ke settings.json kunci "info"; kunci lain (profil ISP, dll) dibiarkan."""
    path = path or SETTINGS_PATH
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data["info"] = {k: prefs[k] for k in PREF_DEFAULTS if k in prefs}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


# ── Format ───────────────────────────────────────────────────────────────────

def fmt_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            break
        n /= 1024
    if unit == "B":
        return f"{int(n)} B"
    return f"{n:.0f} {unit}" if n >= 100 else f"{n:.1f} {unit}"


def fmt_duration(sec):
    sec = int(sec or 0)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} hari {h} jam"
    if h:
        return f"{h} jam {m} mnt"
    return f"{m} mnt"


def mask_ip(ip):
    """36.71.12.34 -> 36.71.x.x ; IPv6 -> 2001:x. Untuk screenshot yang mau dibagikan."""
    ip = str(ip or "")
    if ":" in ip:
        return ip.split(":")[0] + ":x"
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else ip


def classify_iface(name):
    """Nama interface -> wifi | data | lan | other."""
    n = str(name or "").lower()
    if n.startswith(MOBILE_PREFIX):
        return "data"
    if n.startswith(WIFI_PREFIX):
        return "wifi"
    if n.startswith(LAN_PREFIX):
        return "lan"
    return "other"


def guess_kind_by_ip(ip):
    """Cadangan kalau nama interface tidak terbaca: sama seperti NetStat, 192.168.0.0/16 dianggap WiFi."""
    try:
        return "wifi" if ipaddress.ip_address(ip) in ipaddress.ip_network("192.168.0.0/16") else "data"
    except ValueError:
        return "other"


KIND_LABEL = {"wifi": "WiFi", "data": "Data", "lan": "LAN", "other": "Jaringan"}


# ── HTTP (satu pintu supaya mudah dites) ─────────────────────────────────────

_DIRECT = build_opener(ProxyHandler({}))                 # controller lokal/LAN: jangan lewat proxy lingkungan


def _http_get(url, timeout=1.0, headers=None, direct=True):
    """(status, body bytes). status None kalau tidak tersambung."""
    req = Request(url, headers=headers or {})
    try:
        r = _DIRECT.open(req, timeout=timeout) if direct else urlopen(req, timeout=timeout)
        with r:
            return r.status, r.read(4_000_000)
    except HTTPError as e:
        return e.code, b""
    except (OSError, ValueError):
        return None, b""


def _get_json(url, timeout=1.0, headers=None, direct=True):
    st, body = _http_get(url, timeout, headers, direct)
    if st == 200:
        try:
            return st, json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return st, None
    return st, None


# ── Jaringan ─────────────────────────────────────────────────────────────────

def _proc_dev_names(path="/proc/net/dev"):
    try:
        with open(path, encoding="utf-8") as f:
            return [ln.split(":")[0].strip() for ln in f.read().splitlines()[2:] if ":" in ln]
    except OSError:
        return []


def _iface_addrs():
    """[(nama, ipv4)] semua interface yang punya IPv4 (ioctl SIOCGIFADDR; tanpa root)."""
    if fcntl is None:
        return []
    try:
        names = [n for _, n in socket.if_nameindex()]
    except (OSError, AttributeError):
        names = _proc_dev_names()
    out = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return out
    try:
        for n in names:
            try:
                r = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", n.encode()[:15]))
                out.append((n, socket.inet_ntoa(r[20:24])))
            except OSError:
                continue
    finally:
        s.close()
    return out


def _primary_ip():
    """IP lokal yang dipakai untuk keluar (UDP connect tidak mengirim paket)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(0.5)
            s.connect(("1.1.1.1", 53))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def parse_route(text, iface=None):
    """Isi /proc/net/route -> IP gateway default (interface `iface` bila ada, kalau tidak yang pertama)."""
    first = None
    for ln in str(text or "").splitlines()[1:]:
        f = ln.split()
        if len(f) < 3 or f[1] != "00000000":
            continue
        try:
            gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
        except (ValueError, struct.error):
            continue
        if gw == "0.0.0.0":
            continue
        if iface and f[0] == iface:
            return gw
        first = first or gw
    return first


def guess_gateway(ip):
    """192.168.1.23 -> 192.168.1.1 (cadangan kalau tabel rute tidak terbaca; umum untuk router rumahan)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4 or not a.is_private:
        return None
    p = str(a).split(".")
    return ".".join(p[:3] + ["1"])


def parse_operators(text):
    """`gsm.operator.alpha` = satu nama per slot SIM ("XL Axiata,Telkomsel") -> daftar unik, urutan slot."""
    out = []
    for tok in str(text or "").split(","):
        tok = tok.strip()
        if tok and tok not in out:
            out.append(tok)
    return out


def _operator_name():
    """Nama operator dari semua slot SIM. Android tanpa root tidak memberi tahu SIM mana yang dipakai untuk data,
    jadi HP dual SIM menampilkan semuanya ("XL Axiata / Telkomsel"); pastikan lewat pengaturan Operator."""
    try:
        r = subprocess.run(["getprop", "gsm.operator.alpha"], capture_output=True, text=True, timeout=1)
    except (OSError, subprocess.SubprocessError):
        return None
    return " / ".join(parse_operators(r.stdout)) or None


def collect_net():
    """Jaringan aktif: {online, iface, ip, kind, operator, gateway}."""
    addrs = []
    for n, ip in _iface_addrs():
        if n.lower().startswith(SKIP_IFACE):
            continue
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or a.is_link_local or a in FAKE_IP_NET:
            continue
        addrs.append((n, ip))
    primary = _primary_ip()
    pick = next((a for a in addrs if a[1] == primary), None)
    if pick is None and addrs:
        rank = {"wifi": 0, "data": 1, "lan": 2, "other": 3}
        pick = sorted(addrs, key=lambda a: rank[classify_iface(a[0])])[0]
    if pick is None and primary:
        pick = ("?", primary)                            # interface tidak terbaca, IP tetap diketahui
    if pick is None:
        return {"online": False}
    name, ip = pick
    kind = classify_iface(name) if name != "?" else guess_kind_by_ip(ip)
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            gw = parse_route(f.read(), name if name != "?" else None)
    except OSError:
        gw = None
    return {"online": True, "iface": name, "ip": ip, "kind": kind,
            "operator": _operator_name() if kind == "data" else None,
            "gateway": gw or (guess_gateway(ip) if kind in ("wifi", "lan") else None)}


# ── IP publik & lokasi ───────────────────────────────────────────────────────

def collect_public():
    """IP publik + lokasi + ISP lewat ipwho.is (cadangan ipinfo.io). Kalau Box aktif, ini IP *keluar* (node)."""
    st, o = _get_json("https://ipwho.is/", 2.5, direct=False)
    if isinstance(o, dict) and o.get("success", True) and o.get("ip"):
        conn = o.get("connection") if isinstance(o.get("connection"), dict) else {}
        return {"ip": o["ip"], "city": o.get("city") or "", "region": o.get("region") or "",
                "cc": o.get("country_code") or "", "isp": conn.get("isp") or conn.get("org") or ""}
    st, o = _get_json("https://ipinfo.io/json", 2.5, direct=False)
    if isinstance(o, dict) and o.get("ip"):
        return {"ip": o["ip"], "city": o.get("city") or "", "region": o.get("region") or "",
                "cc": o.get("country") or "", "isp": re.sub(r"^AS\d+\s+", "", o.get("org") or "")}
    return None


def collect_ping():
    t0 = time.time()
    st, _ = _http_get(PING_URL, 2.5, direct=False)
    return int((time.time() - t0) * 1000) if st in (200, 204) else None


# ── Status core (Box / Nikki / OpenClash) ────────────────────────────────────

def detect_platform(prefs, root="/"):
    """Platform tempat script ini jalan: box | nikki | openclash | None (tidak diketahui)."""
    if prefs.get("platform") in PLATFORM_NAMES:
        return prefs["platform"]
    p = lambda x: os.path.exists(os.path.join(root, x.lstrip("/")))
    if p("/etc/openwrt_release"):
        if p("/etc/init.d/nikki") or p("/etc/nikki"):
            return "nikki"
        if p("/etc/init.d/openclash") or p("/etc/openclash"):
            return "openclash"
        return None
    if p("/system/build.prop") or os.environ.get("ANDROID_ROOT") or "com.termux" in os.environ.get("PREFIX", ""):
        return "box"
    return None


def core_process_running(proc="/proc"):
    """Cari proses mihomo/clash. Di Android tanpa root biasanya tak terlihat (hidepid) -> False."""
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            with open(f"{proc}/{pid}/comm", encoding="utf-8") as f:
                if f.read().strip().lower().startswith(CORE_COMM):
                    return True
        except OSError:
            continue
    return False


def template_secret(root=None):
    """Secret dari template yang dipakai (template.yaml, kalau tidak config_v*.yaml terbaru)."""
    tdir = os.path.join(root or SCRIPT_DIR, "template")
    cand = [os.path.join(tdir, "template.yaml")]
    try:
        cand += sorted((os.path.join(tdir, f) for f in os.listdir(tdir)
                        if re.match(r"config_v[\d.]+\.yaml$", f)),
                       key=lambda x: [int(n) for n in re.findall(r"\d+", os.path.basename(x))], reverse=True)
    except OSError:
        pass
    for fp in cand:
        try:
            with open(fp, encoding="utf-8") as f:
                m = re.search(r"^secret:\s*[\"']?([^\"'#\s]*)", f.read(), re.M)
        except OSError:
            continue
        if m:
            return m.group(1)
    return ""


def probe_controller(hostport, secrets):
    """Tanya external-controller Mihomo. None = tidak ada; {"auth": False} = ada tapi minta secret."""
    base = f"http://{hostport}"
    hdr, ver = {}, None
    for sec in secrets:
        hdr = {"Authorization": f"Bearer {sec}"} if sec else {}
        st, ver = _get_json(base + "/version", 0.8, hdr)
        if st == 200 and isinstance(ver, dict):
            break
        if st != 401:
            return None
    else:
        return {"auth": False, "host": hostport}
    info = {"auth": True, "host": hostport, "version": str(ver.get("version") or ""),
            "meta": bool(ver.get("meta"))}
    st, cfg = _get_json(base + "/configs", 1.0, hdr)
    if isinstance(cfg, dict):
        info["mode"] = cfg.get("mode")
    st, con = _get_json(base + "/connections", 1.5, hdr)
    if isinstance(con, dict):
        info["conns"] = len(con.get("connections") or [])
        info["down"] = int(con.get("downloadTotal") or 0)
        info["up"] = int(con.get("uploadTotal") or 0)
    return info


def remote_label(ip, prefs):
    """Nama platform router (Nikki/OpenClash). Heuristik LuCI: halaman plugin yang ada beda status dengan
    halaman palsu (403 vs 404). Tidak yakin -> "Mihomo"; pasti -> isi pengaturan Platform."""
    if prefs.get("platform") in PLATFORM_NAMES:
        return PLATFORM_NAMES[prefs["platform"]]
    ctrl, _ = _http_get(f"http://{ip}/cgi-bin/luci/admin/services/hikari-tidak-ada", 0.8)
    if ctrl is None:
        return "Mihomo"
    for slug, name in (("nikki", "Nikki"), ("openclash", "OpenClash")):
        st, _ = _http_get(f"http://{ip}/cgi-bin/luci/admin/services/{slug}", 0.8)
        if st is not None and st != ctrl and st in (200, 301, 302, 403):
            return name
    return "Mihomo"


_REMEMBERED = []          # [(host:port, secret)] controller yang terbukti hidup di sesi ini (mis. dari Inspector Live)


def _norm_hostport(raw):
    """'http://0.0.0.0:9090/ui' -> '127.0.0.1:9090'; ':9090' -> '127.0.0.1:9090'; tanpa port -> :9090. Kosong -> ''."""
    s = re.sub(r"^[a-z]+://", "", str(raw or "").strip().strip("\"'"), flags=re.I).split("/")[0]
    if not s:
        return ""
    host, sep_, port = s.rpartition(":") if not s.endswith("]") else (s, "", "")
    if not sep_ or not port.isdigit():
        host, port = s, "9090"
    host = host.strip("[]")
    if host in ("", "0.0.0.0", "::", "*"):
        host = "127.0.0.1"
    return f"{host}:{port}"


def remember_controller(hostport, secret=""):
    """Ingat controller yang baru terbukti hidup supaya banner tidak salah menyatakan core mati."""
    hp = _norm_hostport(hostport)
    if hp:
        _REMEMBERED[:] = [(h, s) for h, s in _REMEMBERED if h != hp]
        _REMEMBERED.insert(0, (hp, secret or ""))


def generated_controllers(root=None, limit=6):
    """[(host:port, secret)] dari config hasil generate terbaru (hasil/**/*.yaml): external-controller & secret-nya
    bisa beda dari template (mis. config sniffer)."""
    base = os.path.join(root or SCRIPT_DIR, "hasil")
    try:
        files = sorted(glob.glob(os.path.join(base, "**", "*.yaml"), recursive=True), key=os.path.getmtime, reverse=True)
    except OSError:
        return []
    out = []
    for fp in files[:40]:
        try:
            with open(fp, encoding="utf-8") as f:
                head = f.read(20000)
        except OSError:
            continue
        m = re.search(r"^external-controller:\s*[\"']?([^\"'#\s]+)", head, re.M)
        if not m:
            continue
        s = re.search(r"^secret:\s*[\"']?([^\"'#\s]*)", head, re.M)
        item = (_norm_hostport(m.group(1)), s.group(1) if s else "")
        if item[0] and item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def collect_core(net, prefs):
    """{alive, label, where, ...}. Urutan: controller diset -> lokal 127.0.0.1 -> proses lokal -> router (gateway)."""
    plat = detect_platform(prefs)
    local_label = PLATFORM_NAMES.get(plat, "Mihomo")
    remembered, generated = list(_REMEMBERED), generated_controllers()
    secrets = []
    for s in ("", prefs.get("secret") or "", *(s for _, s in remembered), template_secret(), "hikari",
              *(s for _, s in generated)):
        if s not in secrets:
            secrets.append(s)
    cands = []
    if prefs.get("api"):
        cands.append(prefs["api"])
    cands += [h for h, _ in remembered]
    cands.append(DEFAULT_API)
    cands += [h for h, _ in generated]
    gw = (net or {}).get("gateway")
    if gw and (net or {}).get("kind") in ("wifi", "lan", "other"):
        cands.append(f"{gw}:9090")
    seen = set()
    for hp in cands:
        if hp in seen:
            continue
        seen.add(hp)
        r = probe_controller(hp, secrets)
        if r:
            host = hp.rsplit(":", 1)[0]
            local = host in ("127.0.0.1", "localhost", "::1")
            r.update(alive=True, local=local,
                     label=local_label if local else remote_label(host, prefs),
                     where="" if local else f"router {host}")
            return r
    if core_process_running():
        return {"alive": True, "local": True, "label": local_label, "where": "", "auth": None}
    return {"alive": False, "label": local_label}


# ── Usage ────────────────────────────────────────────────────────────────────

def _iface_counters(iface, path="/proc/net/dev"):
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f.read().splitlines()[2:]:
                name, _, rest = ln.partition(":")
                if name.strip() == iface:
                    v = rest.split()
                    return int(v[0]), int(v[8])           # rx, tx
    except (OSError, ValueError, IndexError):
        pass
    return None


def collect_usage(net, core, prefs):
    """Pemakaian data. Sumber terbaik dulu: NetStat (hari ini) > sesi core (/connections) > counter interface."""
    st, data = _get_json(f"http://{prefs.get('stats') or DEFAULT_STATS}/api/summary", 1.2)
    if isinstance(data, dict):
        today = next((e for e in reversed(data.get("daily") or []) if isinstance(e, dict) and e.get("active")), None)
        if today:
            nets = today.get("nets") or {}
            tot = {"up": 0, "down": 0}
            per = {}
            for k in ("wifi", "data"):
                c = nets.get(k) or {}
                up, down = int(c.get("up") or 0), int(c.get("down") or 0)
                per[k] = up + down
                tot["up"] += up
                tot["down"] += down
            lim = ((data.get("overview") or {}).get("limit") or {})
            return {"source": "hari ini", "up": tot["up"], "down": tot["down"], "wifi": per["wifi"],
                    "data": per["data"], "remaining": lim.get("remaining") if lim.get("bytes") else None}
    if core and core.get("down") is not None:
        return {"source": "sesi core", "up": core["up"], "down": core["down"]}
    rt = _iface_counters((net or {}).get("iface"))
    if rt:
        return {"source": "sejak boot", "down": rt[0], "up": rt[1]}
    return None


def read_uptime(path="/proc/uptime"):
    try:
        with open(path, encoding="utf-8") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


# ── Cache + eksekusi paralel ─────────────────────────────────────────────────

_LOCK = threading.Lock()
_CACHE = {}
_INFLIGHT = {}


def _start(key, ttl, fn):
    """Mulai fn di thread daemon bila cache `key` kedaluwarsa dan belum ada yang berjalan. Return thread / None."""
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and time.time() - hit[0] < ttl:
            return None
        th = _INFLIGHT.get(key)
        if th is not None and th.is_alive():
            return th

        def run():
            try:
                val = fn()
            except Exception:                            # info banner tidak boleh menjatuhkan menu
                val = None
            with _LOCK:
                _CACHE[key] = (time.time(), val)

        th = threading.Thread(target=run, daemon=True)
        _INFLIGHT[key] = th
        th.start()
        return th


def _value(key):
    with _LOCK:
        hit = _CACHE.get(key)
    return hit[1] if hit else None


def _join(threads, deadline):
    for th in threads:
        if th is not None:
            th.join(max(0.0, deadline - time.time()))


def clear_cache():
    with _LOCK:
        _CACHE.clear()
        _INFLIGHT.clear()


def collect(level="full", prefs=None):
    """Kumpulkan info. level 'compact' = jaringan + status core; 'full' = semuanya."""
    prefs = prefs or load_prefs()
    deadline = time.time() + DEADLINE
    _join([_start("net", TTL["net"], collect_net)], deadline)
    net = _value("net") or {"online": False}
    out = {"net": net, "core": None, "public": None, "usage": None, "ping": None, "uptime": None}
    jobs = [_start("core", TTL["core"], lambda: collect_core(net, prefs))]
    if level == "full" and net.get("online"):
        if prefs.get("lookup"):
            jobs.append(_start(("public", net.get("ip"), net.get("iface")), TTL["public"], collect_public))
        jobs.append(_start("ping", TTL["ping"], collect_ping))
    _join(jobs[:1], deadline)
    out["core"] = _value("core")
    if level == "full":
        _join([_start("usage", TTL["usage"], lambda: collect_usage(net, out["core"], prefs))] + jobs[1:], deadline)
        out["usage"] = _value("usage")
        out["ping"] = _value("ping")
        out["uptime"] = read_uptime()
        if prefs.get("lookup"):
            out["public"] = _value(("public", net.get("ip"), net.get("iface")))
    return out


# ── Tampilan ─────────────────────────────────────────────────────────────────

def _styles():
    try:
        import banner as b
        return {"label": b.GRAY, "val": b.WHITE, "ip": b.OCEAN_BLUE, "ok": b.GREEN, "bad": b.RED,
                "dim": b.GRAY, "reset": b.RESET}
    except ImportError:
        return {k: "" for k in ("label", "val", "ip", "ok", "bad", "dim", "reset")}


def status_text(core):
    if not core:
        return "-", "dim"
    if core.get("alive"):
        return f"{core['label']} Aktif", "ok"
    return f"{core['label']} Tidak Aktif", "bad"


def _location(pub, mask):
    if not pub:
        return None
    place = pub["cc"] if mask else ", ".join(x for x in (pub["city"], pub["cc"]) if x)
    return " · ".join(x for x in (place, pub["isp"]) if x) or None


def _wrap(bits, budget, sep="  ·  "):
    """Gabung potongan teks dengan pemisah, pindah baris bila melewati `budget` karakter."""
    rows, cur = [], ""
    for b in bits:
        if cur and len(cur) + len(sep) + len(b) > budget:
            rows.append(cur)
            cur = b
        else:
            cur = cur + sep + b if cur else b
    if cur:
        rows.append(cur)
    return rows


def build_rows(info, prefs, level="full", width=80):
    """[(label, [(teks, gaya), ...])]; label "" = baris lanjutan. Baris panjang dibungkus sesuai `width`."""
    budget = max(16, width - 14)                         # lebar isi: setelah indent 2 + label 8 + " : "
    net, core = info["net"], info["core"]
    mask = bool(prefs.get("mask"))
    st_txt, st_style = status_text(core)
    st_seg = [(st_txt, st_style)]
    if core and core.get("alive") and core.get("where"):
        st_seg.append((f"  ({core['where']})", "dim"))
    if level == "compact":
        segs = list(st_seg)
        if net.get("online"):
            ip = mask_ip(net["ip"]) if mask else net["ip"]
            segs += [("  ·  ", "dim"), (KIND_LABEL[net["kind"]], "val"), ("  ·  ", "dim"), (ip, "ip")]
        else:
            segs += [("  ·  ", "dim"), ("Offline", "bad")]
        return [("", segs)]
    rows = []
    # IP
    if net.get("online"):
        loc_ip = net["ip"]
        segs = [(loc_ip, "ip"), (" lokal", "dim")]
        pub = info.get("public")
        if pub:
            segs += [("  ·  ", "dim"), (mask_ip(pub["ip"]) if mask else pub["ip"], "ip"), (" publik", "dim")]
        elif prefs.get("lookup"):
            segs += [("  ·  ", "dim"), ("publik: -", "dim")]
        rows.append(("IP", segs))
    else:
        rows.append(("IP", [("-", "dim")]))
    rows.append(("Lokasi", [(_location(info.get("public"), mask) or "-", "val")]))
    # Jaringan
    if net.get("online"):
        extra = (prefs.get("operator") or net.get("operator")) if net["kind"] == "data" else None
        iface = "" if net["iface"] == "?" else net["iface"]
        det = " · ".join(x for x in (iface, extra) if x)
        segs = [(KIND_LABEL[net["kind"]], "val")] + ([(f"  ({det})", "dim")] if det else [])
    else:
        segs = [("Offline", "bad")]
    rows.append(("Jaringan", segs))
    rows.append(("Status", st_seg))
    # Usage
    u = info.get("usage")
    if u:
        rows.append(("Usage", [("↓ ", "dim"), (fmt_bytes(u["down"]), "val"), ("  ↑ ", "dim"),
                               (fmt_bytes(u["up"]), "val"), (f"  ({u['source']})", "dim")]))
        if "wifi" in u:
            det = [f"Data {fmt_bytes(u['data'])}", f"WiFi {fmt_bytes(u['wifi'])}"]
            if u.get("remaining") is not None:
                det.append(f"sisa {fmt_bytes(max(0, u['remaining']))}")
            rows += [("", [(t, "dim")]) for t in _wrap(det, budget)]
    else:
        rows.append(("Usage", [("-", "dim")]))
    # Etc
    bits = []
    if core and core.get("alive"):
        if core.get("version"):
            bits.append(("clash" if core.get("meta") is False else "mihomo") + " " + core["version"])
        if core.get("mode"):
            bits.append(f"mode {core['mode']}")
        if core.get("conns") is not None:
            bits.append(f"{core['conns']} koneksi")
        if core.get("auth") is False:
            bits.append("controller minta secret")
    if info.get("uptime"):
        bits.append(f"uptime {fmt_duration(info['uptime'])}")
    if info.get("ping") is not None:
        bits.append(f"ping {info['ping']} ms")
    for i, t in enumerate(_wrap(bits, budget)):
        rows.append(("Etc" if i == 0 else "", [(t, "val")]))
    return rows


def render(rows, width=None, color=True):
    """Baris-baris -> list string (diberi warna ANSI bila color)."""
    width = max(30, (width or 80) - 1)
    st = _styles() if color else {k: "" for k in ("label", "val", "ip", "ok", "bad", "dim", "reset")}
    lw = max([len(l) for l, _ in rows] + [0])
    out = []
    for label, segs in rows:
        head = f"{label:<{lw}} : " if label else (" " * (lw + 3) if lw else "")
        budget = width - 2 - len(head)
        parts, used = [], 0
        for text, style in segs:
            if used + len(text) > budget:
                text = text[:max(0, budget - used - 1)] + "…" if budget - used > 1 else ""
            if text:
                parts.append(f"{st[style]}{text}{st['reset']}")
                used += len(text)
            if used >= budget:
                break
        out.append("  " + f"{st['label']}{head}{st['reset']}" + "".join(parts))
    return out


def enabled(force=False):
    """Info banner hanya tampil di terminal, kecuali HIKARI_INFO diisi eksplisit."""
    if os.environ.get("HIKARI_INFO", "").strip().lower() in MODES:
        return True
    return force or sys.stdout.isatty()


def lines(level="full", width=None, color=True, force=False):
    """Baris info siap cetak ([] bila dimatikan). level diminta pemanggil; pengaturan pengguna jadi batas atas."""
    prefs = load_prefs()
    if prefs["mode"] == "off" or level not in ("full", "compact") or not enabled(force):
        return []
    if prefs["mode"] == "compact":
        level = "compact"
    try:
        info = collect(level, prefs)
        return render(build_rows(info, prefs, level, width or 80), width, color)
    except Exception:
        return []


if __name__ == "__main__":
    import shutil
    for ln in lines("full", shutil.get_terminal_size((80, 24)).columns, sys.stdout.isatty(), force=True):
        print(ln)
