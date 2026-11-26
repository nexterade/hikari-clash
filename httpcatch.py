#!/usr/bin/env python3
"""
Hikari /.CLASH — penangkap path HTTP ("bug catcher") untuk menu Miscellaneous > Sniffer Only.

Mihomo hanya melihat HOST (SNI / header Host), tidak pernah PATH. Modul ini proxy lokal kecil yang diselipkan di jalur
trafik HTTP polos: mencatat tiap permintaan (metode, Host, path + query, User-Agent) beserta balasannya (status,
header Location = tujuan redirect, Content-Type, Server, petunjuk CDN) lalu meneruskan byte apa adanya.

Cara masuk (salah satu):
  - config sniffer (menu Sniffer Only > Generate Config > penangkap path): rule port HTTP diarahkan ke proxy ini;
  - atur proxy HTTP aplikasi/perangkat ke host:port penangkap (permintaan CONNECT maupun URL absolut diterima).

Batasan (disengaja, jujur):
  - PATH HANYA terlihat pada HTTP POLOS (port 80/8080/...). HTTPS terenkripsi: yang terlihat hanya host:port dari
    CONNECT dan SNI dari ClientHello; path HTTPS TIDAK ditangkap (tidak ada MITM / sertifikat palsu).
  - Parsing berhenti (isi tetap diteruskan) untuk badan "chunked", WebSocket/Upgrade, dan badan tanpa Content-Length.
  - Penangkap TIDAK mengubah byte yang lewat (kecuali baris permintaan URL absolut diubah ke bentuk asal).
  - Hanya stdlib. Satu thread per koneksi.
"""

import argparse
import collections
import json
import os
import select
import socket
import sys
import threading
import time

DEFAULT_PORT = 7893
HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")
MAX_HEAD = 65536
IDLE_TIMEOUT = 120
CONNECT_TIMEOUT = 10


# ---------- parsing ----------
def parse_head(raw):
    """Blok header (tanpa CRLF CRLF akhir) -> (baris_pertama, {nama_kecil: nilai}) atau None."""
    try:
        text = raw.decode("iso-8859-1")
    except (UnicodeDecodeError, AttributeError):
        return None
    lines = text.split("\r\n")
    first = lines[0].strip()
    if not first:
        return None
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            k = k.strip().lower()
            if k and k not in headers:
                headers[k] = v.strip()
    return first, headers


def split_target(target, default_host="", default_port=80):
    """Target permintaan -> (host, port, path). Menerima 'http://h:81/p?q' (URL absolut) atau '/p?q'."""
    t = target.strip()
    if t.lower().startswith("http://"):
        rest = t[7:]
        hostport, sl, path = rest.partition("/")
        path = "/" + path if sl else "/"
        host, port = _host_port(hostport, 80)
        return host, port, path
    return default_host, default_port, t or "/"


def _host_port(text, default_port):
    t = text.strip()
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("["):
        end = t.find("]")
        host = t[1:end] if end > 0 else t
        rest = t[end + 1:] if end > 0 else ""
        return host.lower(), int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
    if t.count(":") == 1:
        h, _, p = t.partition(":")
        if p.isdigit():
            return h.lower(), int(p)
    return t.lower(), default_port


def parse_sni(data):
    """ClientHello TLS -> (sni, [alpn]) atau None kalau bukan/belum lengkap. Tidak ada dekripsi."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        rec_len = int.from_bytes(data[3:5], "big")
        body = data[5:5 + rec_len]
        if len(body) < rec_len or not body or body[0] != 1:
            return None
        p = 4 + 2 + 32                                  # tipe+panjang handshake, versi, random
        p += 1 + body[p]                                # session id
        p += 2 + int.from_bytes(body[p:p + 2], "big")   # cipher suites
        p += 1 + body[p]                                # compression
        end = p + 2 + int.from_bytes(body[p:p + 2], "big")
        p += 2
        sni, alpn = "", []
        while p + 4 <= min(end, len(body)):
            etype = int.from_bytes(body[p:p + 2], "big")
            elen = int.from_bytes(body[p + 2:p + 4], "big")
            ext = body[p + 4:p + 4 + elen]
            if etype == 0 and len(ext) >= 5:            # server_name
                nlen = int.from_bytes(ext[3:5], "big")
                sni = ext[5:5 + nlen].decode("ascii", "replace").lower()
            elif etype == 16 and len(ext) >= 2:         # ALPN
                q, lim = 2, 2 + int.from_bytes(ext[:2], "big")
                while q < min(lim, len(ext)):
                    n = ext[q]
                    alpn.append(ext[q + 1:q + 1 + n].decode("ascii", "replace"))
                    q += 1 + n
            p += 4 + elen
        return sni, alpn
    except (IndexError, ValueError):
        return None


def cdn_hint(headers):
    """Petunjuk CDN dari header balasan (bukan bukti kuat; header bisa dipalsukan/dihapus)."""
    h = headers or {}
    server, via, cache = h.get("server", "").lower(), h.get("via", "").lower(), h.get("x-cache", "").lower()
    if "cf-ray" in h or server.startswith("cloudflare"):
        return "Cloudflare"
    if "x-amz-cf-id" in h or "cloudfront" in via or "cloudfront" in cache or server == "cloudfront":
        return "CloudFront"
    if "akamai" in server or "x-akamai-request-id" in h:
        return "Akamai"
    if "fastly" in server or "x-served-by" in h and "cache" in h.get("x-served-by", "").lower():
        return "Fastly"
    return ""


class HttpStream:
    """Parser satu arah (kind 'req' atau 'res') atas byte yang lewat. Tidak mengubah apa pun; berhenti (opaque)
    kalau tidak bisa melacak batas pesan. on_head(first_line, headers) -> panjang badan (int) atau None (= opaque)."""

    def __init__(self, on_head):
        self.on_head = on_head
        self.buf = b""
        self.skip = 0
        self.opaque = False

    def feed(self, data):
        if self.opaque or not data:
            return
        self.buf += data
        while not self.opaque:
            if self.skip:
                n = min(self.skip, len(self.buf))
                self.buf, self.skip = self.buf[n:], self.skip - n
                if self.skip:
                    return
            i = self.buf.find(b"\r\n\r\n")
            if i < 0:
                if len(self.buf) > MAX_HEAD:
                    self.stop()
                return
            raw, self.buf = self.buf[:i], self.buf[i + 4:]
            parsed = parse_head(raw)
            body = self.on_head(*parsed) if parsed else None
            if body is None:
                self.stop()
                return
            self.skip = body

    def stop(self):
        self.opaque, self.buf = True, b""


# ---------- sink + event ----------
class EventLog:
    """Kumpulan event aman-thread. Tulis JSONL (satu baris per event selesai) bila log_path diisi."""

    def __init__(self, log_path=None, on_event=None):
        self.events = []
        self.lock = threading.Lock()
        self.log_path = log_path
        self.on_event = on_event            # on_event(event, phase) phase: 'req' | 'done'
        self._fh = None
        self._seq = 0
        if log_path:
            os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
            self._fh = open(log_path, "a", encoding="utf-8")

    def new(self, **fields):
        with self.lock:
            self._seq += 1
            ev = {"id": self._seq, "ts": time.strftime("%H:%M:%S"), "t": time.time(), "tls": False,
                  "method": "", "host": "", "port": 80, "path": "", "src": "", "status": None, "reason": "",
                  "location": "", "ctype": "", "server": "", "cdn": "", "ua": "", "note": ""}
            ev.update(fields)
            self.events.append(ev)
        self._emit(ev, "req")
        return ev

    def done(self, ev):
        if ev.get("_done"):
            return
        ev["_done"] = True
        with self.lock:
            if self._fh:
                self._fh.write(json.dumps({k: v for k, v in ev.items() if not k.startswith("_")}, ensure_ascii=False) + "\n")
                self._fh.flush()
        self._emit(ev, "done")

    def _emit(self, ev, phase):
        if self.on_event:
            try:
                self.on_event(ev, phase)
            except Exception:                # tampilan tidak boleh mengganggu relay
                pass

    def close(self):
        for ev in list(self.events):
            self.done(ev)
        if self._fh:
            self._fh.close()
            self._fh = None

    def snapshot(self):
        with self.lock:
            return [{k: v for k, v in e.items() if not k.startswith("_")} for e in self.events]


class Conn:
    """Satu koneksi klien: memetakan permintaan <-> balasan dan mencatat event."""

    def __init__(self, log, src, host, port):
        self.log, self.src, self.host, self.port = log, src, host, port
        self.pending = collections.deque()
        self.proto = None                    # None (belum tahu) | 'http' | 'tls' | 'other'
        self.probe = b""
        self.req = HttpStream(self._on_req)
        self.res = HttpStream(self._on_res)
        self.sni_done = False

    # klien -> server
    def from_client(self, data):
        if self.proto is None:
            self.probe += data
            if self.probe[:1] == b"\x16":
                self.proto = "tls"
            elif any(self.probe.startswith(m + b" ") for m in HTTP_METHODS):
                self.proto = "http"
                self.req.feed(self.probe)
                self.probe = b""
                return
            elif any((m + b" ").startswith(self.probe) for m in HTTP_METHODS):
                return                                   # baru sebagian token metode; tunggu byte berikutnya
            else:
                self.proto = "other"
                self.probe = b""
                return
        elif self.proto == "tls" and not self.sni_done:
            self.probe += data
        elif self.proto == "http":
            self.req.feed(data)
            return
        if self.proto == "tls" and not self.sni_done:
            r = parse_sni(self.probe)
            if r is not None or len(self.probe) > 16384:
                self.sni_done = True
                sni, alpn = r or ("", [])
                ev = self.log.new(tls=True, method="TLS", host=sni or self.host, port=self.port, src=self.src,
                                  note=("ALPN " + ",".join(alpn)) if alpn else "")
                ev["sni"] = sni
                self.log.done(ev)
                self.probe = b""

    def from_server(self, data):
        if self.proto == "http":
            self.res.feed(data)

    def _on_req(self, first, headers):
        parts = first.split(" ")
        if len(parts) < 2:
            return None
        method, target = parts[0].upper(), parts[1]
        host, port, path = split_target(target, "", self.port)
        hh = headers.get("host", "")
        if not host:
            host = _host_port(hh, self.port)[0] if hh else self.host
        ev = self.log.new(method=method, host=host, port=port or self.port, path=path, src=self.src,
                          ua=headers.get("user-agent", ""), host_header=hh, target_host=self.host)
        self.pending.append(ev)
        if headers.get("upgrade") or "chunked" in headers.get("transfer-encoding", "").lower():
            ev["note"] = "upgrade/chunked: parsing berhenti setelah ini"
            return None
        cl = headers.get("content-length", "0")
        return int(cl) if cl.isdigit() else None if method not in ("GET", "HEAD", "DELETE", "OPTIONS") else 0

    def _on_res(self, first, headers):
        parts = first.split(" ", 2)
        if len(parts) < 2 or not parts[0].upper().startswith("HTTP/") or not parts[1].isdigit():
            return None
        code = int(parts[1])
        ev = self.pending.popleft() if self.pending else None
        if ev is not None:
            ev.update(status=code, reason=parts[2] if len(parts) > 2 else "", location=headers.get("location", ""),
                      ctype=headers.get("content-type", ""), server=headers.get("server", ""),
                      cdn=cdn_hint(headers))
            self.log.done(ev)
        if code == 101 or "chunked" in headers.get("transfer-encoding", "").lower():
            return None
        if 100 <= code < 200 or code in (204, 304) or (ev is not None and ev["method"] == "HEAD"):
            return 0
        cl = headers.get("content-length", "")
        return int(cl) if cl.isdigit() else None

    def finish(self):
        for ev in self.pending:
            ev["note"] = ev.get("note") or "tanpa balasan (koneksi ditutup)"
            self.log.done(ev)
        self.pending.clear()


# ---------- server ----------
def _recv_head(sock, limit=MAX_HEAD):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(8192)
        if not d:
            return buf, b""
        buf += d
        if len(buf) > limit:
            break
    i = buf.find(b"\r\n\r\n")
    return (buf[:i], buf[i + 4:]) if i >= 0 else (buf, b"")


class CatchServer:
    """Proxy penangkap. start() di thread latar; stop() menutup dan menulis event tersisa."""

    def __init__(self, host="127.0.0.1", port=DEFAULT_PORT, log_path=None, on_event=None):
        self.host, self.port = host, int(port)
        self.log = EventLog(log_path, on_event)
        self.sock = None
        self.thread = None
        self.running = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.host, self.port))
        except OSError as e:
            self.sock.close()
            raise OSError(f"tidak bisa listen di {self.host}:{self.port} ({e.strerror or e})") from e
        self.port = self.sock.getsockname()[1]
        self.sock.listen(64)
        self.sock.settimeout(0.5)
        self.running = True
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=2)
        self.log.close()

    def _accept(self):
        while self.running:
            try:
                c, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c, f"{addr[0]}:{addr[1]}"), daemon=True).start()

    def _is_self(self, host, port):
        return int(port) == self.port and host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", self.host)

    def _serve(self, c, src):
        up = None
        conn = None
        try:
            c.settimeout(IDLE_TIMEOUT)
            head, rest = _recv_head(c)
            parsed = parse_head(head)
            if not parsed:
                return
            first, headers = parsed
            parts = first.split(" ")
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                host, port = _host_port(target, 443)
                if self._is_self(host, port):
                    c.sendall(b"HTTP/1.1 508 Loop Detected\r\nConnection: close\r\n\r\n")
                    return
                up = self._dial(c, host, port)
                if up is None:
                    return
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                conn = Conn(self.log, src, host, port)
                if rest:
                    conn.from_client(rest)
                    up.sendall(rest)
            elif target.lower().startswith("http://"):          # URL absolut: bentuk proxy HTTP biasa
                host, port, path = split_target(target)
                if self._is_self(host, port):
                    c.sendall(b"HTTP/1.1 508 Loop Detected\r\nConnection: close\r\n\r\n")
                    return
                up = self._dial(c, host, port)
                if up is None:
                    return
                conn = Conn(self.log, src, host, port)
                lines = head.split(b"\r\n")
                lines[0] = f"{parts[0]} {path} {parts[2] if len(parts) > 2 else 'HTTP/1.1'}".encode("iso-8859-1")
                lines = [ln for ln in lines if not ln.lower().startswith(b"proxy-connection:")]
                rebuilt = b"\r\n".join(lines) + b"\r\n\r\n" + rest
                conn.from_client(rebuilt)
                up.sendall(rebuilt)
            else:
                c.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
                          b"Hikari catcher: kirim sebagai proxy HTTP (CONNECT atau URL absolut).\r\n")
                return
            self._relay(c, up, conn)
        except OSError:
            pass
        finally:
            if conn:
                conn.finish()
            for s in (c, up):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass

    def _dial(self, c, host, port):
        try:
            return socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError:
            try:
                c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return None

    def _relay(self, c, u, conn):
        c.settimeout(None)
        u.settimeout(None)
        open_ = [c, u]
        while open_ and self.running:
            r, _, _ = select.select(open_, [], [], IDLE_TIMEOUT)
            if not r:
                return
            for s in r:
                try:
                    d = s.recv(65536)
                except OSError:
                    d = b""
                dst = u if s is c else c
                if not d:
                    open_.remove(s)
                    if s is c:                       # klien selesai kirim: teruskan EOF, tetap tunggu balasan server
                        try:
                            u.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                    else:
                        return
                    continue
                (conn.from_client if s is c else conn.from_server)(d)
                try:
                    dst.sendall(d)
                except OSError:
                    return


# ---------- ringkasan & laporan ----------
def first_segment(path):
    """'/en/page/x?a=1' -> '/en'; '/' atau kosong -> ''."""
    p = (path or "").split("?", 1)[0].split("#", 1)[0]
    segs = [s for s in p.split("/") if s]
    return "/" + segs[0] if segs else ""


def _loc_parts(loc):
    """Header Location -> (host atau '', path tanpa query)."""
    t = (loc or "").strip()
    if "://" in t:
        rest = t.split("://", 1)[1]
        host, sl, path = rest.partition("/")
        return _host_port(host, 0)[0], ("/" + path if sl else "").split("?", 1)[0].split("#", 1)[0]
    return "", t.split("?", 1)[0].split("#", 1)[0]


def aggregate_paths(events):
    """Gabung event HTTP polos: (host, metode, path) -> hitungan, status, redirect. Terurut dari yang paling sering."""
    groups = {}
    for e in events:
        if e.get("tls"):
            continue
        key = (e.get("host") or "", int(e.get("port") or 80), e.get("method") or "", (e.get("path") or "/").split("?", 1)[0])
        g = groups.setdefault(key, {"host": key[0], "port": key[1], "method": key[2], "path": key[3], "count": 0,
                                    "status": [], "location": [], "cdn": [], "ctype": [], "queries": 0})
        g["count"] += 1
        if "?" in (e.get("path") or ""):
            g["queries"] += 1
        for f, v in (("status", e.get("status")), ("location", e.get("location")), ("cdn", e.get("cdn")),
                     ("ctype", (e.get("ctype") or "").split(";")[0])):
            if v and v not in g[f]:
                g[f].append(v)
    out = list(groups.values())
    out.sort(key=lambda g: (-g["count"], g["host"], g["path"]))
    return out


def bug_candidates(events):
    """Kandidat bug berpath (format 'host/path', siap ditempel ke Uji Bug > Lazy) dari event HTTP polos:
    path permintaan yang dibalas < 400 (awalan = segmen pertama) dan tujuan redirect (Location). Return (list, catatan)."""
    seen, out = set(), []

    def add(host, path):
        seg = first_segment(path)
        if host and seg and (host, seg) not in seen:
            seen.add((host, seg))
            out.append(f"{host}{seg}")

    for e in events:
        if e.get("tls"):
            continue
        st = e.get("status")
        if st is not None and int(st) < 400:
            add(e.get("host") or "", e.get("path") or "")
        lh, lp = _loc_parts(e.get("location"))
        if e.get("location"):
            add(lh or e.get("host") or "", lp)
    return out


def fmt_event(e, phase="done"):
    """Satu baris tampilan live."""
    if e.get("tls"):
        return f"{e['ts']} TLS    {e.get('sni') or e['host'] or '?'}:{e['port']}" + (f"  [{e['note']}]" if e.get("note") else "")
    tail = ""
    if phase == "done" or e.get("status") is not None:
        tail = f" → {e['status']}" if e.get("status") is not None else " → (tanpa balasan)"
        if e.get("location"):
            tail += f"  ➜ {e['location']}"
        if e.get("cdn"):
            tail += f"  [{e['cdn']}]"
    return f"{e['ts']} {e['method']:<6} {e['host']}{'' if e['port'] == 80 else ':' + str(e['port'])}{e['path']}{tail}"


def render_markdown(events, source=""):
    ev = [e for e in events if not e.get("tls")]
    tls = [e for e in events if e.get("tls")]
    L = ["# Path HTTP tertangkap", ""]
    if source:
        L += [f"Sumber: {source}", ""]
    L += [f"{len(ev)} permintaan HTTP polos, {len(tls)} handshake TLS (hanya SNI, path HTTPS tidak terlihat).", ""]
    agg = aggregate_paths(events)
    if agg:
        L += ["| Host | Metode | Path | Status | Redirect ke | CDN | Jumlah |", "|---|---|---|---|---|---|---|"]
        for g in agg:
            L.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                _cell(g["host"] + ("" if g["port"] == 80 else f":{g['port']}")), g["method"], _cell(g["path"]),
                _cell(", ".join(map(str, g["status"]))), _cell(", ".join(g["location"][:2])), _cell(", ".join(g["cdn"])),
                g["count"]))
        L.append("")
    cands = bug_candidates(events)
    if cands:
        L += ["## Kandidat bug berpath", "", "Tempel ke Uji Bug > Lazy (otomatis dicoba metode ganti path):", "", "```"] + cands + ["```", "",
              "Kandidat bukan jaminan gratis; buktinya paling kuat kalau direkam di SIM tanpa kuota reguler.", ""]
    snis = sorted({e.get("sni") for e in tls if e.get("sni")})
    if snis:
        L += ["## SNI (handshake TLS lewat penangkap)", "", "```"] + snis + ["```", ""]
    return "\n".join(L)


def _cell(t):
    return str(t if t not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def load_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    pass
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hikari penangkap path HTTP (proxy lokal).")
    ap.add_argument("--host", default="127.0.0.1", help="alamat listen (default 127.0.0.1; 0.0.0.0 untuk perangkat lain)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--log", default="", help="simpan event JSONL ke file ini")
    ap.add_argument("--report", default="", help="tulis laporan Markdown ke file ini saat berhenti")
    a = ap.parse_args(argv)
    srv = CatchServer(a.host, a.port, a.log or None, lambda e, ph: print(fmt_event(e, ph), flush=True) if ph == "done" else None)
    try:
        srv.start()
    except OSError as e:
        print(f"✗ {e}")
        return 1
    print(f"Penangkap path aktif di {a.host}:{srv.port} — Ctrl+C untuk berhenti. Hanya HTTP polos yang menampakkan path.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
    events = srv.log.snapshot()
    srv.stop()
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            f.write(render_markdown(events, "sesi penangkap"))
        print(f"Laporan: {a.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
