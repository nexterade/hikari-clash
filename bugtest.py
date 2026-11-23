#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hikari /.CLASH — Bug Tester (tanpa UI; dipakai menu Convert).

Mengambil node (URI hasil paste / YAML tersimpan) + daftar kandidat SNI / Host / Address (server) / Port /
Path / ALPN / Fingerprint, membuat "varian" node (satu field diganti per varian), lalu menguji tiap varian
apakah masih bisa konek. Varian yang lolos dikeluarkan sebagai node Clash siap pakai.

Mode tes (bisa dipilih lebih dari satu; varian harus lolos SEMUA mode yang dipilih, dijalankan berurutan
dari yang termurah sehingga yang sudah gagal tidak ikut ke mode berikutnya):
  tcp     DNS -> TCP connect -> TLS handshake (dengan SNI varian) -> untuk node WebSocket juga HTTP Upgrade
          (Host + path varian; lolos hanya jika server menjawab 101). Cepat, tanpa core. Tidak membuktikan
          proxy tembus ke internet; node grpc/h2/reality hanya sampai TCP/TLS.
  mihomo  URL-test sungguhan lewat core Mihomo (memakai mesin sub2yaml.mihomo_delays).
  v2ray   URL-test sungguhan lewat core Xray / V2Ray (>=5): satu proses, satu inbound SOCKS per varian,
          lalu HTTP GET lewat SOCKS5.

Modul ini tidak mengimpor hikari_converter (supaya tidak melingkar); penulisan YAML dipasok pemanggil.
"""

import base64
import copy
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MODES = ("tcp", "mihomo", "v2ray")
MODE_LABEL = {"tcp": "TCP/TLS", "mihomo": "Mihomo", "v2ray": "V2Ray/Xray"}

FIELDS = ("sni", "host", "server", "port", "path", "alpn", "fp")        # urutan tampil & urutan apply gabungan
FIELD_LABEL = {"sni": "SNI", "host": "Host", "server": "Address", "port": "Port",
               "path": "Path", "alpn": "ALPN", "fp": "Fingerprint"}
FIELD_TAG = {"sni": "sni", "host": "host", "server": "addr", "port": "port",
             "path": "path", "alpn": "alpn", "fp": "fp"}
FIELD_FILE = {"sni": "custom-sni.yaml", "host": "custom-host.yaml", "server": "custom-address.yaml",
              "port": "custom-port.yaml", "path": "custom-path.yaml", "alpn": "custom-alpn.yaml",
              "fp": "custom-fp.yaml", "combo": "custom-combined.yaml"}
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")

DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
UDP_ONLY_TYPES = {"hysteria", "hysteria2", "tuic", "wireguard"}

SAME, NA = "same", "na"          # alasan apply_variant gagal: nilai sama dengan asli / field tidak berlaku untuk node


# =====================================================================
#  Kandidat: parsing input pengguna
# =====================================================================
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)*{_LABEL}$")


def is_ip(host):
    try:
        ipaddress.ip_address(str(host).strip("[]"))
        return True
    except ValueError:
        return False


def clean_host(token):
    """Rapikan satu token jadi hostname / IP valid, atau None. Menerima 'https://a.b.com/x', 'A.B.COM:443', '[::1]'."""
    t = str(token).strip().strip("'\"")
    t = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", t)
    t = re.split(r"[/?#]", t, maxsplit=1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):
        end = t.find("]")
        t = t[1:end] if end > 0 else t
    elif t.count(":") == 1:
        h, _, p = t.partition(":")
        if p.isdigit():
            t = h
    t = t.strip().rstrip(".").lower()
    if not t:
        return None
    if is_ip(t):
        return t
    if not _HOST_RE.match(t) or ("." not in t and t != "localhost"):    # satu kata tanpa titik = salah ketik, bukan domain
        return None
    return t


def read_candidate_lines(lines, max_bytes=1_000_000):
    """Gabungkan baris input jadi satu teks. Baris '@path' dimuat dari file (UTF-8). Return (teks, [pesan_error])."""
    out, problems = [], []
    for ln in lines:
        s = ln.strip()
        if s.startswith("@") and len(s) > 1:
            p = os.path.expanduser(s[1:].strip().strip("'\""))
            if not os.path.isabs(p):
                p = os.path.join(SCRIPT_DIR, p) if not os.path.isfile(p) else p
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    out.append(f.read(max_bytes))
            except OSError as e:
                problems.append(f"{s}: {e.strerror or e}")
        else:
            out.append(ln)
    return "\n".join(out), problems


def parse_candidates(field, text):
    """Teks bebas -> (nilai_valid_unik_berurutan, [token_ditolak]). Komentar '# ...' diabaikan.
    host-like (sni/host/server): pisah spasi/koma/titik-koma. alpn/path: pisah spasi/baris saja (koma bagian dari nilai)."""
    text = re.sub(r"(?m)#.*$", "", text or "")
    if field in ("path", "alpn"):
        tokens = [t for t in re.split(r"[\s;]+", text) if t]
    else:
        tokens = [t for t in re.split(r"[\s,;]+", text) if t]
    good, bad, seen = [], [], set()
    for tok in tokens:
        val = None
        if field in ("sni", "host", "server"):
            val = clean_host(tok)
        elif field == "port":
            val = int(tok) if tok.isdigit() and 1 <= int(tok) <= 65535 else None
        elif field == "path":
            val = tok if tok.startswith("/") or re.fullmatch(r"[A-Za-z0-9_.\-]+", tok) else None
        elif field == "alpn":
            parts = [p.strip() for p in tok.split(",") if p.strip()]
            val = parts if parts and all(re.fullmatch(r"[A-Za-z0-9./-]+", p) for p in parts) else None
        elif field == "fp":
            val = tok.lower() if tok.lower() in FINGERPRINTS else None
        key = json.dumps(val)
        if val is None:
            bad.append(tok)
        elif key not in seen:
            seen.add(key)
            good.append(val)
    return good, bad


# =====================================================================
#  Varian node
# =====================================================================
def _net(n):
    return str(n.get("network") or "tcp").lower()


def _is_tls(n):
    return bool(n.get("tls")) or str(n.get("type", "")).lower() == "trojan"


def _sni_key(n):
    return "sni" if str(n.get("type", "")).lower() == "trojan" else "servername"


def _get_sni(n):
    return str(n.get("servername") or n.get("sni") or "")


def _get_host(n):
    net = _net(n)
    if net == "ws":
        h = (n.get("ws-opts") or {}).get("headers") or {}
        return str(h.get("Host") or h.get("host") or "")
    if net == "h2":
        h = (n.get("h2-opts") or {}).get("host")
        return str(h[0] if isinstance(h, list) and h else (h or ""))
    if net == "http":
        h = ((n.get("http-opts") or {}).get("headers") or {}).get("Host")
        return str(h[0] if isinstance(h, list) and h else (h or ""))
    return ""


def _set_host(n, host):
    net = _net(n)
    if net == "ws":
        hd = n.setdefault("ws-opts", {}).setdefault("headers", {})
        for k in [k for k in hd if str(k).lower() == "host"]:
            del hd[k]
        hd["Host"] = host
    elif net == "h2":
        n.setdefault("h2-opts", {})["host"] = [host]
    elif net == "http":
        n.setdefault("http-opts", {}).setdefault("headers", {})["Host"] = [host]
    else:
        return False
    return True


def clean_node(node):
    return {k: copy.deepcopy(v) for k, v in node.items() if not str(k).startswith("_")}


def apply_variant(node, field, value):
    """Return (node_baru, None) atau (None, (SAME|NA, alasan)). Node asli tidak diubah.
    Mengganti Address: SNI & Host asli dikunci dulu (kalau belum ada) supaya tidak ikut berubah ke Address baru."""
    q = clean_node(node)
    tls = _is_tls(q)
    net = _net(q)
    if field == "server":
        old = str(q.get("server") or "")
        if str(value).lower() == old.lower():
            return None, (SAME, "sama dengan config asli")
        if old and not is_ip(old):
            if tls and not _get_sni(q):
                q[_sni_key(q)] = old
            if net in ("ws", "h2", "http") and not _get_host(q):
                _set_host(q, old)
        q["server"] = value
        if tls:
            q["skip-cert-verify"] = True        # sertifikat IP/CDN lain jarang cocok dengan SNI asli
    elif field == "sni":
        if not tls:
            return None, (NA, "node tanpa TLS")
        if str(value).lower() == _get_sni(q).lower():
            return None, (SAME, "sama dengan config asli")
        q[_sni_key(q)] = value
        q["skip-cert-verify"] = True            # SNI custom -> sertifikat tidak cocok
    elif field == "host":
        if net not in ("ws", "h2", "http"):
            return None, (NA, f"transport {net} tidak punya header Host")
        if str(value).lower() == _get_host(q).lower():
            return None, (SAME, "sama dengan config asli")
        _set_host(q, value)
    elif field == "port":
        if int(value) == int(q.get("port") or 0):
            return None, (SAME, "sama dengan config asli")
        q["port"] = int(value)
    elif field == "path":
        if net == "ws":
            o = q.setdefault("ws-opts", {})
            if o.get("path") == value:
                return None, (SAME, "sama dengan config asli")
            o["path"] = value
        elif net == "h2":
            q.setdefault("h2-opts", {})["path"] = value
        elif net == "http":
            q.setdefault("http-opts", {})["path"] = [value]
        elif net == "grpc":
            q.setdefault("grpc-opts", {})["grpc-service-name"] = str(value).lstrip("/")
        else:
            return None, (NA, f"transport {net} tidak punya path")
    elif field == "alpn":
        if not tls:
            return None, (NA, "node tanpa TLS")
        q["alpn"] = list(value)
    elif field == "fp":
        if not tls:
            return None, (NA, "node tanpa TLS")
        if str(q.get("client-fingerprint") or "").lower() == value:
            return None, (SAME, "sama dengan config asli")
        q["client-fingerprint"] = value
    else:
        raise ValueError(f"field tidak dikenal: {field}")
    return q, None


def _fmt_val(v):
    return ",".join(v) if isinstance(v, (list, tuple)) else str(v)


def _variant(vid, bi, kind, fields, node, base_name, base_node):
    if kind == "base":
        name = base_name
    elif kind == "combo":
        name = f"{base_name} [combo]"
    else:
        name = f"{base_name} [{FIELD_TAG[kind]}:{_fmt_val(fields[kind])}]"
    node = dict(node)
    node["name"] = name
    return {"id": vid, "base": bi, "base_name": base_name, "kind": kind, "fields": dict(fields),
            "node": node, "base_node": base_node, "res": {}, "ok": False, "ms": None, "reason": ""}


def describe_fields(v):
    if v["kind"] == "base":
        return "(config asli)"
    return " ".join(f"{FIELD_TAG[k]}={_fmt_val(v['fields'][k])}" for k in FIELDS if k in v["fields"])


def build_variants(nodes, candidates, include_base=True):
    """nodes: list node Clash. candidates: {field: [nilai]}.
    Return (variants, skipped); skipped = [(index_node, nama, field, alasan)] untuk field yang tak berlaku."""
    variants, skipped, vid = [], [], 0
    for bi, node in enumerate(nodes):
        base_name = str(node.get("name") or f"node{bi + 1}")
        base = clean_node(node)
        if include_base:
            variants.append(_variant(vid, bi, "base", {}, base, base_name, base)); vid += 1
        for field in FIELDS:
            for val in candidates.get(field) or []:
                q, why = apply_variant(base, field, val)
                if q is None:
                    if why[0] == NA:
                        skipped.append((bi, base_name, field, why[1]))
                        break
                    continue
                variants.append(_variant(vid, bi, field, {field: val}, q, base_name, base)); vid += 1
    return variants, skipped


def make_combos(variants, start_id=None):
    """Gabungan terbaik: per node, ambil varian lolos tercepat dari tiap field (min. 2 field) lalu terapkan semuanya
    sekaligus. Return list varian baru (belum dites)."""
    vid = (max((v["id"] for v in variants), default=-1) + 1) if start_id is None else start_id
    best = {}
    for v in variants:
        if v["ok"] and v["kind"] in FIELDS:
            cur = best.setdefault(v["base"], {}).get(v["kind"])
            if cur is None or (v["ms"] or 10 ** 9) < (cur["ms"] or 10 ** 9):
                best[v["base"]][v["kind"]] = v
    out = []
    for bi, per in sorted(best.items()):
        if len(per) < 2:
            continue
        any_v = next(iter(per.values()))
        node, fields = any_v["base_node"], {}
        for f in FIELDS:
            if f in per:
                node, why = apply_variant(node, f, per[f]["fields"][f])
                if node is None:
                    break
                fields[f] = per[f]["fields"][f]
        if node is None or len(fields) < 2:
            continue
        v = _variant(vid, bi, "combo", fields, node, any_v["base_name"], any_v["base_node"]); vid += 1
        out.append(v)
    return out


# =====================================================================
#  Mode TCP / TLS / WebSocket
# =====================================================================
def _ms(t0):
    return max(1, int(round((time.perf_counter() - t0) * 1000)))


def _tls_ctx(alpn=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            ctx.set_alpn_protocols([str(a) for a in alpn])
        except (NotImplementedError, ssl.SSLError):
            pass
    return ctx


def _resolve(host, port):
    host = str(host).strip("[]")
    if is_ip(host):
        return host
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    infos.sort(key=lambda i: i[0] != socket.AF_INET)
    return infos[0][4][0]


def _ws_params(node):
    o = node.get("ws-opts") or {}
    hd = o.get("headers") or {}
    host = hd.get("Host") or hd.get("host") or _get_sni(node) or str(node.get("server") or "")
    return str(host), str(o.get("path") or "/")


def _read_status_line(sock, limit=4096):
    buf = b""
    while b"\r\n" not in buf and len(buf) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")


def tcp_probe(node, timeout=5.0):
    """Tes satu node secara langsung. Return dict(ok True/False/None, ms, conn_ms, detail). Tidak melempar exception.
    ok=None = tidak bisa diuji di mode ini."""
    res = {"ok": False, "ms": None, "conn_ms": None, "detail": ""}
    typ = str(node.get("type", "")).lower()
    if typ in UDP_ONLY_TYPES:
        res.update(ok=None, detail="node UDP — pakai mode Mihomo/V2Ray")
        return res
    host, port = str(node.get("server") or ""), node.get("port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        res["detail"] = "port tidak valid"
        return res
    if not host:
        res["detail"] = "server kosong"
        return res
    t_all = time.perf_counter()
    try:
        ip = _resolve(host, port)
    except (socket.gaierror, OSError) as e:
        res["detail"] = f"DNS gagal ({getattr(e, 'strerror', None) or e})"
        return res
    sock = None
    try:
        t0 = time.perf_counter()
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
        except socket.timeout:
            res["detail"] = "TCP timeout"
            return res
        except ConnectionRefusedError:
            res["detail"] = "TCP ditolak (port tertutup)"
            return res
        except OSError as e:
            res["detail"] = f"TCP gagal ({e.strerror or e})"
            return res
        res["conn_ms"] = _ms(t0)
        stage = "TCP"
        net = _net(node)
        reality = bool(node.get("reality-opts"))
        ws = net == "ws" and typ in ("vless", "vmess", "trojan")
        if _is_tls(node) and not reality:
            sni = _get_sni(node)
            alpn = ["http/1.1"] if ws else node.get("alpn")
            sock.settimeout(timeout)
            try:
                sock = _tls_ctx(alpn).wrap_socket(sock, server_hostname=None if (not sni or is_ip(sni)) else sni)
            except socket.timeout:
                res["detail"] = "TLS timeout"
                return res
            except (ssl.SSLError, OSError) as e:
                res["detail"] = f"TLS gagal ({getattr(e, 'reason', None) or e.__class__.__name__})"
                return res
            stage = "TLS"
        if ws:
            whost, path = _ws_params(node)
            key = base64.b64encode(os.urandom(16)).decode()
            req = (f"GET {path} HTTP/1.1\r\nHost: {whost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
                   f"User-Agent: Mozilla/5.0\r\n\r\n")
            sock.settimeout(timeout)
            try:
                sock.sendall(req.encode("latin-1", "replace"))
                status = _read_status_line(sock)
            except socket.timeout:
                res["detail"] = "WS timeout (tidak ada jawaban)"
                return res
            except (ssl.SSLError, OSError) as e:
                res["detail"] = f"WS gagal ({e.__class__.__name__})"
                return res
            m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status)
            code = int(m.group(1)) if m else 0
            if code != 101:
                res["detail"] = f"WS ditolak (HTTP {code})" if code else "WS: jawaban bukan HTTP"
                return res
            stage = "WS 101"
        res["ok"] = True
        res["ms"] = _ms(t_all)
        if reality:
            res["detail"] = "TCP saja (reality tidak bisa dites di mode ini)"
        elif stage == "TLS" and net in ("grpc", "h2", "http"):
            res["detail"] = f"TLS OK (protokol {net} tidak dites)"
        else:
            res["detail"] = stage + " OK"
        return res
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def tcp_unsupported(v):
    """Alasan varian tidak bisa dites di mode TCP (atau None)."""
    node = v["node"]
    if "fp" in v["fields"]:
        return "fingerprint (uTLS) tidak bisa dites di mode TCP"
    if node.get("reality-opts") and "sni" in v["fields"]:
        return "SNI reality hanya bisa dites lewat core"
    return None


def run_tcp(variants, timeout=5.0, workers=32, progress=None):
    """Isi v['res']['tcp'] untuk tiap varian."""
    done = 0
    lock = threading.Lock()

    def job(v):
        why = tcp_unsupported(v)
        if why:
            return v, {"ok": None, "ms": None, "conn_ms": None, "detail": why}
        return v, tcp_probe(v["node"], timeout)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(variants) or 1))) as ex:
        futs = [ex.submit(job, v) for v in variants]
        for f in as_completed(futs):
            v, r = f.result()
            v["res"]["tcp"] = r
            with lock:
                done += 1
            if progress:
                progress("tcp", done, len(variants))


def tcp_intercepted(variants):
    """True kalau hampir semua TCP connect <=3 ms: koneksi dijawab proxy/VPN lokal (Box/Nikki/TUN), hasil TCP tidak berarti."""
    ms = [v["res"]["tcp"]["conn_ms"] for v in variants if v["res"].get("tcp") and v["res"]["tcp"].get("conn_ms")]
    return len(ms) >= 4 and sum(1 for m in ms if m <= 3) / len(ms) > 0.5


# =====================================================================
#  Mode Mihomo
# =====================================================================
def _sub2yaml():
    import sub2yaml
    return sub2yaml


def find_mihomo():
    try:
        return _sub2yaml().find_core()
    except Exception:
        return None


def download_mihomo():
    return _sub2yaml().download_core()


def run_mihomo(variants, core, test_url=DEFAULT_TEST_URL, timeout_ms=5000, workers=16, progress=None):
    """Isi v['res']['mihomo']. Raise RuntimeError kalau core gagal total (bukan kalau node gagal)."""
    s2y = _sub2yaml()
    proxies = {v["id"]: clean_node(v["node"]) for v in variants}
    done = [0]

    def tick(_ok):
        done[0] += 1
        if progress:
            progress("mihomo", done[0], len(variants))

    ok, fails, rejected = s2y.mihomo_delays(core, proxies, test_url, timeout_ms, workers, tick=tick)
    for v in variants:
        i = v["id"]
        if i in ok:
            v["res"]["mihomo"] = {"ok": True, "ms": ok[i], "detail": f"URL-test {ok[i]}ms"}
        elif i in rejected:
            v["res"]["mihomo"] = {"ok": False, "ms": None, "detail": "ditolak mihomo: " + str(rejected[i])[:100]}
        else:
            kind, msg = fails.get(i, ("urltest", "gagal"))
            v["res"]["mihomo"] = {"ok": False, "ms": None, "detail": f"{kind}: {str(msg)[:100]}"}


# =====================================================================
#  Mode V2Ray / Xray
# =====================================================================
def v2ray_flavor(path):
    """'xray' | 'v2ray' | None (bukan core yang bisa dipakai). v2ray hanya >=5."""
    try:
        r = subprocess.run([path, "version"], capture_output=True, text=True, timeout=15)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        if not out:
            r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=15)
            out = ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception:
        return None
    first = out.splitlines()[0].lower() if out else ""
    if first.startswith("xray"):
        return "xray"
    m = re.match(r"v2ray\s+v?(\d+)", first)
    if m and int(m.group(1)) >= 5:
        return "v2ray"
    return None


def find_v2ray(extra=None):
    """Cari binary xray / v2ray: argumen, env HIKARI_XRAY / HIKARI_V2RAY, ./bin, ~/.hikari-clash/bin, PATH."""
    cands = [extra, os.environ.get("HIKARI_XRAY"), os.environ.get("HIKARI_V2RAY")]
    dirs = [os.path.join(SCRIPT_DIR, "bin"), os.path.join(os.path.expanduser("~"), ".hikari-clash", "bin"), SCRIPT_DIR]
    for name in ("xray", "v2ray"):
        cands += [os.path.join(d, name) for d in dirs] + [shutil.which(name)]
    seen = set()
    for c in cands:
        if c and c not in seen and os.path.isfile(c) and os.access(c, os.X_OK):
            seen.add(c)
            fl = v2ray_flavor(c)
            if fl:
                return c, fl
    return None, None


def _xray_stream(node):
    net, tls = _net(node), _is_tls(node)
    ss = {}
    if net == "ws" and (node.get("ws-opts") or {}).get("v2ray-http-upgrade"):
        o = node["ws-opts"]
        ss["network"] = "httpupgrade"
        hu = {"path": o.get("path") or "/"}
        host = (o.get("headers") or {}).get("Host")
        if host:
            hu["host"] = host
        ss["httpupgradeSettings"] = hu
    elif net == "ws":
        o = node.get("ws-opts") or {}
        ws = {"path": o.get("path") or "/"}
        if o.get("headers"):
            ws["headers"] = {str(k): str(v) for k, v in o["headers"].items()}
        ss["network"] = "ws"
        ss["wsSettings"] = ws
    elif net == "grpc":
        ss["network"] = "grpc"
        ss["grpcSettings"] = {"serviceName": (node.get("grpc-opts") or {}).get("grpc-service-name", "")}
    elif net == "h2":
        o = node.get("h2-opts") or {}
        h = {"path": o.get("path") or "/"}
        if o.get("host"):
            h["host"] = o["host"] if isinstance(o["host"], list) else [o["host"]]
        ss["network"] = "h2"
        ss["httpSettings"] = h
    elif net in ("tcp", "raw"):
        ss["network"] = "tcp"
    else:
        raise ValueError(f"transport '{net}' belum didukung mode V2Ray")
    if node.get("reality-opts"):
        ro = node["reality-opts"]
        ss["security"] = "reality"
        ss["realitySettings"] = {"serverName": _get_sni(node), "fingerprint": node.get("client-fingerprint") or "chrome",
                                 "publicKey": ro.get("public-key", ""), "shortId": ro.get("short-id", ""),
                                 "spiderX": ""}
    elif tls:
        ts = {"serverName": _get_sni(node), "allowInsecure": bool(node.get("skip-cert-verify"))}
        if node.get("alpn"):
            ts["alpn"] = list(node["alpn"])
        if node.get("client-fingerprint"):
            ts["fingerprint"] = node["client-fingerprint"]
        if not ts["serverName"]:
            del ts["serverName"]
        ss["security"] = "tls"
        ss["tlsSettings"] = ts
    return ss


def node_to_xray_outbound(node, tag):
    """Node Clash -> outbound Xray/V2Ray (dict). Raise ValueError untuk tipe/transport yang belum didukung."""
    typ = str(node.get("type", "")).lower()
    addr, port = str(node["server"]), int(node["port"])
    if typ == "vless":
        user = {"id": node["uuid"], "encryption": "none"}
        if node.get("flow"):
            user["flow"] = node["flow"]
        out = {"protocol": "vless", "settings": {"vnext": [{"address": addr, "port": port, "users": [user]}]}}
    elif typ == "vmess":
        user = {"id": node["uuid"], "alterId": int(node.get("alterId") or 0), "security": node.get("cipher") or "auto"}
        out = {"protocol": "vmess", "settings": {"vnext": [{"address": addr, "port": port, "users": [user]}]}}
    elif typ == "trojan":
        out = {"protocol": "trojan", "settings": {"servers": [{"address": addr, "port": port, "password": node["password"]}]}}
    elif typ in ("ss", "shadowsocks"):
        out = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": addr, "port": port, "method": node.get("cipher", ""), "password": node.get("password", "")}]}}
    else:
        raise ValueError(f"tipe '{typ}' belum didukung mode V2Ray")
    out["tag"] = tag
    if typ != "ss":
        out["streamSettings"] = _xray_stream(node)
    return out


def _free_ports(n):
    socks = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def build_xray_config(items, ports):
    """items: [(id, outbound_dict_tanpa_tag)] -> config Xray: satu inbound SOCKS (127.0.0.1) per outbound."""
    inbounds, outbounds, rules = [], [], []
    for (vid, ob), port in zip(items, ports):
        ob = dict(ob)
        ob["tag"] = f"out{vid}"
        inbounds.append({"tag": f"in{vid}", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}})
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in{vid}"], "outboundTag": f"out{vid}"})
    return {"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("koneksi ditutup")
        buf += chunk
    return buf


def socks5_http_status(port, url, timeout=6.0):
    """GET `url` lewat SOCKS5 di 127.0.0.1:port. Return (status_http, ms). Raise OSError/ValueError kalau gagal."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    https = u.scheme == "https"
    dport = u.port or (443 if https else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    t0 = time.perf_counter()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise ValueError("SOCKS5 menolak handshake")
        hb = host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", dport))
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise ValueError(f"koneksi lewat node gagal (SOCKS5 kode {head[1]})")
        atyp = head[3]
        if atyp == 3:                                   # alamat bind berupa domain: 1 byte panjang + isi
            _recv_exact(s, _recv_exact(s, 1)[0] + 2)
        else:                                           # IPv4 (4) / IPv6 (16) + 2 byte port
            _recv_exact(s, (16 if atyp == 4 else 4) + 2)
        if https:
            s = _tls_ctx().wrap_socket(s, server_hostname=host)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
        m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", _read_status_line(s))
        if not m:
            raise ValueError("jawaban bukan HTTP")
        return int(m.group(1)), _ms(t0)
    finally:
        try:
            s.close()
        except OSError:
            pass


def _status_ok(url, status):
    return status == 204 if urllib.parse.urlsplit(url).path.endswith("generate_204") else 200 <= status < 400


def _xray_cmds(core, flavor, cfg_path):
    if flavor == "xray":
        return [core, "run", "-test", "-c", cfg_path], [core, "run", "-c", cfg_path]
    return [core, "test", "-c", cfg_path], [core, "run", "-c", cfg_path]


def _xray_batch(core, flavor, items, test_url, timeout, workers, tick):
    """items: [(vid, outbound)] -> {vid: result}. Config ditolak -> dibelah dua sampai yang rusak ketemu."""
    if not items:
        return {}
    work = tempfile.mkdtemp(prefix="hikari_xray_")
    proc = log = None
    try:
        ports = _free_ports(len(items))
        cfg_path = os.path.join(work, "config.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(build_xray_config(items, ports), f)
        test_cmd, run_cmd = _xray_cmds(core, flavor, cfg_path)
        r = subprocess.run(test_cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            msg = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
            msg = (msg[-1] if msg else f"kode {r.returncode}")[:120]
            if len(items) == 1:
                tick()
                return {items[0][0]: {"ok": False, "ms": None, "detail": "ditolak core: " + msg}}
            mid = len(items) // 2
            out = _xray_batch(core, flavor, items[:mid], test_url, timeout, workers, tick)
            out.update(_xray_batch(core, flavor, items[mid:], test_url, timeout, workers, tick))
            return out
        log = open(os.path.join(work, "core.log"), "wb")
        proc = subprocess.Popen(run_cmd, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.time() + 8
        while True:
            if proc.poll() is not None:
                log.flush()
                tail = open(os.path.join(work, "core.log"), "rb").read()[-200:].decode("utf-8", "replace").strip()
                raise RuntimeError(f"core berhenti sendiri: {tail or 'tanpa pesan'}")
            try:
                socket.create_connection(("127.0.0.1", ports[-1]), timeout=0.5).close()
                break
            except OSError:
                if time.time() > deadline:
                    raise RuntimeError("inbound SOCKS core tidak aktif dalam 8 detik")
                time.sleep(0.15)

        def probe(item_port):
            (vid, _), port = item_port
            try:
                status, ms = socks5_http_status(port, test_url, timeout)
            except (OSError, ValueError) as e:
                res = {"ok": False, "ms": None, "detail": "gagal: " + (str(e) or e.__class__.__name__)[:90]}
            else:
                res = ({"ok": True, "ms": ms, "detail": f"HTTP {status} {ms}ms"} if _status_ok(test_url, status)
                       else {"ok": False, "ms": None, "detail": f"HTTP {status} (bukan jawaban yang diharapkan)"})
            tick()
            return vid, res

        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as ex:
            return dict(ex.map(probe, list(zip(items, ports))))
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        if log is not None:
            log.close()
        shutil.rmtree(work, ignore_errors=True)


def run_v2ray(variants, core, flavor, test_url=DEFAULT_TEST_URL, timeout=6.0, workers=16, batch=40, progress=None):
    """Isi v['res']['v2ray']. Raise RuntimeError kalau core gagal total."""
    done = [0]
    lock = threading.Lock()

    def tick():
        with lock:
            done[0] += 1
            n = done[0]
        if progress:
            progress("v2ray", n, len(variants))

    items = []
    for v in variants:
        try:
            items.append((v["id"], node_to_xray_outbound(v["node"], "x")))
        except (ValueError, KeyError) as e:
            v["res"]["v2ray"] = {"ok": False, "ms": None, "detail": f"tidak didukung: {e}"}
            tick()
    results = {}
    for i in range(0, len(items), batch):
        results.update(_xray_batch(core, flavor, items[i:i + batch], test_url, timeout, workers, tick))
    for v in variants:
        if v["id"] in results:
            v["res"]["v2ray"] = results[v["id"]]


# =====================================================================
#  Orkestrasi
# =====================================================================
def finalize(v, modes):
    """Hitung v['ok'] / v['ms'] / v['reason'] dari hasil per mode yang sudah jalan."""
    rs = [(m, v["res"][m]) for m in modes if m in v["res"]]
    v["ok"] = bool(rs) and all(r["ok"] is not False for _, r in rs) and any(r["ok"] is True for _, r in rs)
    v["ms"] = next((r["ms"] for _, r in reversed(rs) if r.get("ms")), None)
    bad = next(((m, r) for m, r in rs if r["ok"] is False), None)
    if bad:
        v["reason"] = f"{MODE_LABEL[bad[0]]}: {bad[1]['detail']}"
    elif not v["ok"]:
        v["reason"] = "; ".join(f"{MODE_LABEL[m]}: {r['detail']}" for m, r in rs) or "tidak dites"
    else:
        v["reason"] = ""


def test_variants(variants, modes, opts=None, progress=None):
    """Jalankan mode berurutan sesuai urutan MODES. Varian yang gagal di satu mode tidak ikut mode berikutnya.
    opts: timeout (detik), test_url, mihomo_core, v2ray_core, v2ray_flavor, workers.
    Raise RuntimeError kalau core yang dipilih gagal total / tidak tersedia."""
    opts = opts or {}
    modes = [m for m in MODES if m in modes]
    timeout = float(opts.get("timeout", 5.0))
    url = opts.get("test_url") or DEFAULT_TEST_URL
    alive = list(variants)
    for m in modes:
        if not alive:
            break
        if m == "tcp":
            run_tcp(alive, timeout, opts.get("workers", 32), progress)
        elif m == "mihomo":
            if not opts.get("mihomo_core"):
                raise RuntimeError("core Mihomo tidak tersedia")
            run_mihomo(alive, opts["mihomo_core"], url, int(timeout * 1000), opts.get("workers", 16), progress)
        elif m == "v2ray":
            if not opts.get("v2ray_core"):
                raise RuntimeError("core Xray/V2Ray tidak tersedia")
            run_v2ray(alive, opts["v2ray_core"], opts.get("v2ray_flavor") or "xray", url, timeout + 1,
                      opts.get("workers", 16), progress=progress)
        for v in alive:
            finalize(v, modes)
        alive = [v for v in alive if v["res"].get(m, {}).get("ok") is not False]
    for v in variants:
        finalize(v, modes)
    return variants


def passing(variants, include_base=False):
    out = [v for v in variants if v["ok"] and (include_base or v["kind"] != "base")]
    order = {k: i for i, k in enumerate(("base",) + FIELDS + ("combo",))}
    return sorted(out, key=lambda v: (v["base"], order[v["kind"]], v["ms"] or 10 ** 9, v["id"]))


def summarize(variants):
    """{'base': {idx: v}, 'fields': {kind: (tested, ok)}}"""
    base = {v["base"]: v for v in variants if v["kind"] == "base"}
    fields = {}
    for v in variants:
        if v["kind"] == "base":
            continue
        t, o = fields.get(v["kind"], (0, 0))
        fields[v["kind"]] = (t + 1, o + (1 if v["ok"] else 0))
    return {"base": base, "fields": fields}


# =====================================================================
#  Keluaran
# =====================================================================
def report_text(variants, modes, skipped=(), meta=None):
    meta = meta or {}
    L = ["HIKARI /.CLASH — Bug Test", f"waktu  : {meta.get('when', time.strftime('%Y-%m-%d %H:%M:%S'))}",
         "mode   : " + " + ".join(MODE_LABEL[m] for m in MODES if m in modes)]
    if meta.get("test_url") and any(m in modes for m in ("mihomo", "v2ray")):
        L.append(f"url tes: {meta['test_url']}")
    L.append("")
    names = {}
    for v in variants:
        names.setdefault(v["base"], v["base_name"])
    for bi in sorted(names):
        L.append(f"=== {names[bi]} ===")
        base = next((v for v in variants if v["base"] == bi and v["kind"] == "base"), None)
        if base:
            L.append(f"  config asli: {'OK' if base['ok'] else 'GAGAL'}"
                     + (f" {base['ms']}ms" if base["ms"] else "") + ("" if base["ok"] else f"  ({base['reason']})"))
        for s in skipped:
            if s[0] == bi:
                L.append(f"  dilewati {FIELD_LABEL[s[2]]}: {s[3]}")
        for kind in list(FIELDS) + ["combo"]:
            rows = [v for v in variants if v["base"] == bi and v["kind"] == kind]
            if not rows:
                continue
            ok_n = sum(1 for v in rows if v["ok"])
            L.append(f"  -- {FIELD_LABEL.get(kind, 'Gabungan')}: {ok_n}/{len(rows)} lolos")
            for v in sorted(rows, key=lambda v: (not v["ok"], v["ms"] or 10 ** 9, v["id"])):
                tail = f"{v['ms']}ms" if v["ok"] and v["ms"] else v["reason"]
                L.append(f"     {'✓' if v['ok'] else '✗'} {describe_fields(v):<48} {tail}")
        L.append("")
    return "\n".join(L).rstrip() + "\n"


def write_outputs(variants, modes, out_dir, dump, skipped=(), meta=None):
    """Tulis hasil ke out_dir: custom-<field>.yaml (hanya yang punya varian lolos), custom-combined.yaml,
    bug-ok.yaml (semua yang lolos) dan report.txt. dump(list_node) -> teks YAML. Return [(nama_file, jumlah_node)]."""
    os.makedirs(out_dir, exist_ok=True)
    written = []

    def put(fn, nodes):
        with open(os.path.join(out_dir, fn), "w", encoding="utf-8") as f:
            f.write(dump(nodes))
        written.append((fn, len(nodes)))

    ok = passing(variants)
    for kind in list(FIELDS) + ["combo"]:
        nodes = [clean_node(v["node"]) for v in ok if v["kind"] == kind]
        if nodes:
            put(FIELD_FILE[kind], nodes)
    if ok:
        put("bug-ok.yaml", [clean_node(v["node"]) for v in ok])
    with open(os.path.join(out_dir, "report.txt"), "w", encoding="utf-8") as f:
        f.write(report_text(variants, modes, skipped, meta))
    written.append(("report.txt", 0))
    return written
