#!/usr/bin/env python3
"""
Hikari /.CLASH — tester node proxy (tanpa UI; dipakai menu Miscellaneous).

Dua mode:
  1. Offline  : DNS -> TCP connect -> (opsional) TLS handshake ke server node. Menjawab "server-nya hidup
                dan bisa dijangkau dari jaringan ini?", BUKAN "proxy-nya lolos sampai internet".
                Tidak butuh core. Node berbasis UDP (hysteria/tuic) dilewati.
  2. API core : minta Mihomo yang sedang jalan mengukur delay lewat tiap node (GET /proxies/{n}/delay).
                Ini tes sungguhan (proxy -> internet). Butuh core hidup + external-controller (+ secret).
"""

import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

REQUIRED_FIELDS = {
    "vless": ("server", "port", "uuid"),
    "vmess": ("server", "port", "uuid"),
    "trojan": ("server", "port", "password"),
}
UDP_ONLY_TYPES = {"hysteria", "hysteria2", "tuic", "wireguard"}
NON_LEAF_TYPES = {"selector", "urltest", "fallback", "loadbalance", "relay", "direct", "reject",
                  "rejectdrop", "pass", "compatible", "dns"}


def check_node_fields(node):
    """Daftar masalah struktur node (kosong = lengkap)."""
    problems = []
    typ = str(node.get("type", "")).lower()
    for k in REQUIRED_FIELDS.get(typ, ("server", "port")):
        if node.get(k) in (None, ""):
            problems.append(f"field '{k}' kosong")
    try:
        port = int(node.get("port", 0))
        if not 1 <= port <= 65535:
            problems.append("port di luar 1-65535")
    except (TypeError, ValueError):
        problems.append("port bukan angka")
    if node.get("reality-opts") and not (node["reality-opts"] or {}).get("public-key"):
        problems.append("reality tanpa public-key")
    return problems


def _ms(t0):
    return int(round((time.perf_counter() - t0) * 1000))


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _wants_tls(node):
    typ = str(node.get("type", "")).lower()
    return bool(node.get("tls")) or typ == "trojan"


def test_node(node, timeout=5.0, do_tls=True):
    """Tes satu node secara offline. Selalu return dict (tidak melempar exception)."""
    typ = str(node.get("type", "?")).lower()
    res = {"name": str(node.get("name", "?")), "type": typ, "server": str(node.get("server", "")),
           "port": node.get("port"), "ip": "", "dns_ms": None, "tcp_ms": None, "tls_ms": None,
           "ok": False, "status": ""}
    problems = check_node_fields(node)
    if problems:
        res["status"] = "struktur: " + ", ".join(problems)
        return res
    if typ in UDP_ONLY_TYPES:
        res["status"] = "dilewati (UDP)"
        return res

    host, port = str(node["server"]).strip("[]"), int(node["port"])
    try:
        if _is_ip(host):
            ip = host
        else:
            t0 = time.perf_counter()
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            infos.sort(key=lambda i: i[0] != socket.AF_INET)          # utamakan IPv4
            ip = infos[0][4][0]
            res["dns_ms"] = _ms(t0)
        res["ip"] = ip
    except socket.gaierror as e:
        res["status"] = f"DNS gagal ({e.strerror or e})"
        return res
    except OSError as e:
        res["status"] = f"DNS gagal ({e})"
        return res

    sock = None
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=timeout)
        res["tcp_ms"] = _ms(t0)
    except socket.timeout:
        res["status"] = "TCP timeout"
        return res
    except ConnectionRefusedError:
        res["status"] = "TCP ditolak (port tertutup)"
        return res
    except OSError as e:
        res["status"] = f"TCP gagal ({e.strerror or e})"
        return res

    try:
        if do_tls and _wants_tls(node) and str(node.get("network", "tcp")).lower() != "quic":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            alpn = node.get("alpn")
            if isinstance(alpn, list) and alpn:
                try:
                    ctx.set_alpn_protocols([str(a) for a in alpn])
                except (NotImplementedError, ssl.SSLError):
                    pass
            sni = node.get("servername") or node.get("sni") or host
            t0 = time.perf_counter()
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=None if _is_ip(str(sni)) else str(sni)):
                res["tls_ms"] = _ms(t0)
            sock = None
        res["ok"] = True
        res["status"] = "OK"
    except socket.timeout:
        res["status"] = "TLS timeout"
    except (ssl.SSLError, OSError) as e:
        res["status"] = f"TLS gagal ({getattr(e, 'reason', None) or e.__class__.__name__})"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return res


def run_batch(nodes, timeout=5.0, workers=16, do_tls=True, progress=None):
    """Tes banyak node paralel; hasil sesuai urutan input. progress(done, total) opsional."""
    results = [None] * len(nodes)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(nodes) or 1))) as ex:
        futs = {ex.submit(test_node, n, timeout, do_tls): i for i, n in enumerate(nodes)}
        for f in as_completed(futs):
            results[futs[f]] = f.result()
            done += 1
            if progress:
                progress(done, len(nodes))
    return results


def summarize(results):
    ok = [r for r in results if r["ok"]]
    skipped = [r for r in results if r["status"].startswith("dilewati")]
    return {"total": len(results), "ok": len(ok), "skipped": len(skipped),
            "fail": len(results) - len(ok) - len(skipped)}


def sort_key(r):
    """OK dulu (tercepat di atas), lalu gagal."""
    best = (r["tcp_ms"] or 0) + (r["tls_ms"] or 0)
    return (0 if r["ok"] else 1, best if r["ok"] else 0, r["name"])


# =====================================================================
#  Mode API core (Mihomo external-controller)
# =====================================================================
def normalize_base(addr):
    addr = (addr or "").strip().rstrip("/")
    if not addr:
        raise ValueError("alamat controller kosong")
    if "://" not in addr:
        addr = "http://" + addr
    host = urllib.parse.urlsplit(addr).hostname or ""
    if host in ("0.0.0.0", ""):
        addr = addr.replace("0.0.0.0", "127.0.0.1")
    return addr


def _api(base, path, secret="", timeout=5.0):
    req = urllib.request.Request(base + path)
    if secret:
        req.add_header("Authorization", "Bearer " + secret)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace") or "{}")


def api_list_nodes(base, secret="", timeout=5.0):
    """Nama node (bukan group/built-in) yang dikenal core. Raise OSError/ValueError kalau API tidak terjangkau."""
    try:
        data = _api(base, "/proxies", secret, timeout)
    except urllib.error.HTTPError as e:
        raise OSError("API menolak (HTTP %d)%s" % (e.code, " — secret salah?" if e.code == 401 else ""))
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        raise OSError(f"API tidak terjangkau: {getattr(e, 'reason', e)}")
    out = []
    for name, info in (data.get("proxies") or {}).items():
        if str((info or {}).get("type", "")).lower() not in NON_LEAF_TYPES:
            out.append(name)
    return out


def api_delay(base, secret, name, url="http://www.gstatic.com/generate_204", timeout_ms=5000):
    """Return (delay_ms | None, pesan_error)."""
    q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
    path = "/proxies/" + urllib.parse.quote(name, safe="") + "/delay?" + q
    try:
        d = _api(base, path, secret, timeout=timeout_ms / 1000.0 + 3)
        return int(d.get("delay", 0)) or None, ("" if d.get("delay") else str(d.get("message", "tanpa delay")))
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode("utf-8", "replace")).get("message", "")
        except Exception:
            msg = ""
        return None, msg or f"HTTP {e.code}"
    except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
        return None, str(getattr(e, "reason", e))


def run_api_delay(base, secret, names, url, timeout_ms=5000, workers=8, progress=None):
    results = [None] * len(names)
    done = 0

    def job(i):
        ms, msg = api_delay(base, secret, names[i], url, timeout_ms)
        return i, {"name": names[i], "delay": ms, "ok": ms is not None, "status": "OK" if ms else (msg or "gagal")}

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(names) or 1))) as ex:
        for i, r in ex.map(job, range(len(names))):
            results[i] = r
            done += 1
            if progress:
                progress(done, len(names))
    return results
