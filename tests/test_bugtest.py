"""Tes bugtest.py (Bug Tester) — server lokal sungguhan (WS/TLS/SOCKS5), tanpa core asli.
Jalankan dari root project:  python3 -m unittest discover -s tests -v"""
import builtins
import contextlib
import io
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import bugtest as b   # noqa: E402
import hikari_converter as h   # noqa: E402

WS_NODE = {"name": "WS", "type": "vless", "server": "127.0.0.1", "port": 1, "uuid": "u", "udp": True,
           "tls": False, "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "good.example"}}}
TLS_WS_NODE = {"name": "TWS", "type": "vless", "server": "127.0.0.1", "port": 1, "uuid": "u", "tls": True,
               "servername": "ok.example", "skip-cert-verify": True, "network": "ws",
               "ws-opts": {"path": "/ws", "headers": {"Host": "good.example"}}}


def tcp_node(**kw):
    n = {"name": "T", "type": "vless", "server": "example.com", "port": 443, "uuid": "u", "tls": True,
         "servername": "example.com", "network": "tcp"}
    n.update(kw)
    return n


class _Quiet:
    def log_message(self, *a):
        pass


# ---------------------------------------------------------------- server lokal
class WsServer:
    """Server WebSocket-upgrade palsu: 101 hanya bila Host & path cocok; selain itu 403/404.
    tls_ctx: kalau ada, dibungkus TLS (handshake ditolak bila SNI tidak di allowed_sni)."""

    def __init__(self, good_host="good.example", good_path="/ws", tls_ctx=None, bind="127.0.0.1"):
        self.good_hosts = {good_host} if isinstance(good_host, str) else set(good_host)
        self.good_path = good_path
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.ctx = tls_ctx
        self.stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(3)
            if self.ctx:
                c = self.ctx.wrap_socket(c, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(2048)
                if not chunk:
                    return
                data += chunk
            head = data.decode("latin-1").split("\r\n")
            path = head[0].split(" ")[1]
            host = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("host:")), "")
            if path != self.good_path:
                c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            elif host not in self.good_hosts:
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            else:
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        except Exception:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.sock.close()


def make_cert(d):
    key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "2", "-subj", "/CN=hikari.test"], check=True, capture_output=True)
    return crt, key


def server_tls_ctx(crt, key, allowed_sni):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)

    def cb(sslsock, name, _ctx):
        if name not in allowed_sni:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    ctx.sni_callback = cb
    return ctx


class _H204(_Quiet, BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()


class _TS(ThreadingMixIn, HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------- parsing kandidat
class Candidates(unittest.TestCase):
    def test_clean_host(self):
        c = b.clean_host
        self.assertEqual(c("https://Cdn.Example.com/path?x=1"), "cdn.example.com")
        self.assertEqual(c("a.b.com:8443"), "a.b.com")
        self.assertEqual(c("  'x.y.id' "), "x.y.id")
        self.assertEqual(c("x.y.id."), "x.y.id")
        self.assertEqual(c("localhost"), "localhost")
        self.assertEqual(c("104.16.1.1"), "104.16.1.1")
        self.assertEqual(c("[2606:4700::1]:443"), "2606:4700::1")
        self.assertEqual(c("user@host.com"), "host.com")
        for bad in ("", "a b", "-x.com", "x..com", "http://", "bad_host.com", "a" * 64 + ".com", "kata", "not"):
            self.assertIsNone(c(bad), bad)

    def test_parse_hosts_dedupe_comments(self):
        good, bad = b.parse_candidates("sni", "a.com, B.com  a.com\n# komentar\nhttps://c.com/x  not valid!")
        self.assertEqual(good, ["a.com", "b.com", "c.com"])
        self.assertEqual(bad, ["not", "valid!"])

    def test_parse_port_path_alpn_fp(self):
        self.assertEqual(b.parse_candidates("port", "443 8443,80 0 70000 x")[0], [443, 8443, 80])
        self.assertEqual(b.parse_candidates("path", "/ws /vless svc-name nope?")[0], ["/ws", "/vless", "svc-name"])
        self.assertEqual(b.parse_candidates("alpn", "h2,http/1.1 http/1.1")[0], [["h2", "http/1.1"], ["http/1.1"]])
        self.assertEqual(b.parse_candidates("fp", "Chrome firefox bogus")[0], ["chrome", "firefox"])

    def test_read_lines_with_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bug.txt")
            open(p, "w").write("x.com\ny.com\n")
            text, problems = b.read_candidate_lines(["z.com", "@" + p, "@/tidak/ada.txt"])
            self.assertEqual(b.parse_candidates("sni", text)[0], ["z.com", "x.com", "y.com"])
            self.assertEqual(len(problems), 1)


# ---------------------------------------------------------------- varian
class Variants(unittest.TestCase):
    def test_server_pins_sni_and_host_and_does_not_mutate(self):
        n = {"name": "n", "type": "vless", "server": "orig.example.com", "port": 443, "uuid": "u", "tls": True,
             "network": "ws", "ws-opts": {"path": "/"}}
        snapshot = json.dumps(n, sort_keys=True)
        q, why = b.apply_variant(n, "server", "104.16.0.1")
        self.assertIsNone(why)
        self.assertEqual(q["server"], "104.16.0.1")
        self.assertEqual(q["servername"], "orig.example.com")                 # SNI dikunci ke server lama
        self.assertEqual(q["ws-opts"]["headers"]["Host"], "orig.example.com")  # Host juga
        self.assertTrue(q["skip-cert-verify"])
        self.assertEqual(json.dumps(n, sort_keys=True), snapshot)

    def test_server_keeps_existing_sni_host_and_ip_server_not_pinned(self):
        q, _ = b.apply_variant(TLS_WS_NODE, "server", "9.9.9.9")
        self.assertEqual(q["servername"], "ok.example")
        self.assertEqual(q["ws-opts"]["headers"]["Host"], "good.example")
        ip_node = tcp_node(server="1.2.3.4", servername="")
        q, _ = b.apply_variant(ip_node, "server", "5.6.7.8")
        self.assertFalse(q.get("servername"))

    def test_sni_trojan_key_and_skip_verify(self):
        t = {"name": "t", "type": "trojan", "server": "s.com", "port": 443, "password": "p", "sni": "s.com",
             "skip-cert-verify": False}
        q, _ = b.apply_variant(t, "sni", "bug.com")
        self.assertEqual(q["sni"], "bug.com")
        self.assertNotIn("servername", q)
        self.assertTrue(q["skip-cert-verify"])

    def test_not_applicable_and_same(self):
        plain = {"name": "p", "type": "vless", "server": "s.com", "port": 80, "uuid": "u", "tls": False, "network": "tcp"}
        self.assertEqual(b.apply_variant(plain, "sni", "x.com")[1][0], b.NA)
        self.assertEqual(b.apply_variant(plain, "host", "x.com")[1][0], b.NA)
        self.assertEqual(b.apply_variant(plain, "alpn", ["h2"])[1][0], b.NA)
        grpc = tcp_node(network="grpc", **{"grpc-opts": {"grpc-service-name": "g"}})
        self.assertEqual(b.apply_variant(grpc, "host", "x.com")[1][0], b.NA)
        self.assertEqual(b.apply_variant(grpc, "path", "svc")[0]["grpc-opts"]["grpc-service-name"], "svc")
        self.assertEqual(b.apply_variant(TLS_WS_NODE, "host", "GOOD.example")[1][0], b.SAME)
        self.assertEqual(b.apply_variant(TLS_WS_NODE, "sni", "ok.example")[1][0], b.SAME)
        self.assertEqual(b.apply_variant(TLS_WS_NODE, "port", 1)[1][0], b.SAME)

    def test_host_replaces_case_insensitive_header_and_h2(self):
        n = dict(WS_NODE, **{"ws-opts": {"path": "/", "headers": {"host": "old.com", "X": "1"}}})
        q, _ = b.apply_variant(n, "host", "new.com")
        self.assertEqual(q["ws-opts"]["headers"], {"X": "1", "Host": "new.com"})
        h2 = tcp_node(network="h2", **{"h2-opts": {"host": ["a.com"], "path": "/"}})
        self.assertEqual(b.apply_variant(h2, "host", "b.com")[0]["h2-opts"]["host"], ["b.com"])

    def test_build_variants_counts_names_and_skips(self):
        nodes = [TLS_WS_NODE, tcp_node(name="TCP", network="tcp")]
        cands = {"sni": ["a.com", "b.com", "ok.example"], "host": ["h.com"], "server": ["1.1.1.1"]}
        vs, skipped = b.build_variants(nodes, cands)
        by = {}
        for v in vs:
            by.setdefault((v["base"], v["kind"]), []).append(v)
        self.assertEqual(len(by[(0, "base")]), 1)
        self.assertEqual(len(by[(0, "sni")]), 2)                      # ok.example = sama -> dilewati
        self.assertEqual(len(by[(0, "host")]), 1)
        self.assertEqual(len(by[(1, "sni")]), 3)
        self.assertNotIn((1, "host"), by)                             # tcp tak punya Host
        self.assertEqual([(s[0], s[2]) for s in skipped], [(1, "host")])
        names = [v["node"]["name"] for v in vs]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("TWS [sni:a.com]", names)
        self.assertEqual([v["id"] for v in vs], list(range(len(vs))))

    def test_no_base(self):
        vs, _ = b.build_variants([TLS_WS_NODE], {"sni": ["a.com"]}, include_base=False)
        self.assertEqual([v["kind"] for v in vs], ["sni"])


# ---------------------------------------------------------------- mode TCP
class TcpMode(unittest.TestCase):
    def test_ws_101_only_with_right_host_and_path(self):
        srv = WsServer()
        try:
            n = dict(WS_NODE, port=srv.port)
            self.assertTrue(b.tcp_probe(n, 3)["ok"])
            self.assertEqual(b.tcp_probe(n, 3)["detail"], "WS 101 OK")
            bad_host = b.apply_variant(n, "host", "evil.example")[0]
            r = b.tcp_probe(bad_host, 3)
            self.assertFalse(r["ok"]); self.assertIn("403", r["detail"])
            bad_path = b.apply_variant(n, "path", "/nope")[0]
            self.assertIn("404", b.tcp_probe(bad_path, 3)["detail"])
        finally:
            srv.close()

    def test_address_variant_refused_vs_open(self):
        srv = WsServer()                                              # hanya listen di 127.0.0.1
        try:
            n = dict(WS_NODE, port=srv.port)
            good = b.apply_variant(n, "server", "localhost")[0]       # 'localhost' tetap ke 127.0.0.1
            bad = b.apply_variant(n, "server", "127.0.0.2")[0]        # loopback lain: tidak ada listener
            self.assertTrue(b.tcp_probe(good, 3)["ok"])
            r = b.tcp_probe(bad, 3)
            self.assertFalse(r["ok"]); self.assertIn("TCP", r["detail"])
        finally:
            srv.close()

    @unittest.skipUnless(shutil.which("openssl"), "openssl tidak ada")
    def test_tls_sni_filter_and_ws(self):
        with tempfile.TemporaryDirectory() as d:
            crt, key = make_cert(d)
            srv = WsServer(tls_ctx=server_tls_ctx(crt, key, {"ok.example", "cdn.ok.example"}))
            try:
                n = dict(TLS_WS_NODE, port=srv.port)
                self.assertEqual(b.tcp_probe(n, 3)["detail"], "WS 101 OK")
                good = b.apply_variant(n, "sni", "cdn.ok.example")[0]
                bad = b.apply_variant(n, "sni", "blocked.example")[0]
                self.assertTrue(b.tcp_probe(good, 3)["ok"])
                r = b.tcp_probe(bad, 3)
                self.assertFalse(r["ok"]); self.assertIn("TLS gagal", r["detail"])
                # gRPC/TCP + TLS: hanya sampai TLS
                g = dict(tcp_node(server="127.0.0.1", port=srv.port, servername="ok.example", network="grpc"))
                self.assertEqual(b.tcp_probe(g, 3)["detail"], "TLS OK (protokol grpc tidak dites)")
            finally:
                srv.close()

    def test_batch_chain_and_unsupported(self):
        srv = WsServer()
        try:
            n = dict(WS_NODE, port=srv.port)
            vs, _ = b.build_variants([n], {"host": ["good.example", "x.example", "y.example"], "fp": ["chrome"]})
            # good.example = sama dengan asli -> tidak dibuat; fp tidak berlaku untuk node tanpa TLS -> dilewati
            b.test_variants(vs, ["tcp"], {"timeout": 3})
            self.assertTrue(vs[0]["ok"])
            self.assertEqual([v["ok"] for v in vs[1:]], [False, False])
            tv, _ = b.build_variants([TLS_WS_NODE], {"fp": ["chrome"]}, include_base=False)
            tv[0]["node"]["port"] = srv.port
            b.run_tcp(tv, 2)
            self.assertIsNone(tv[0]["res"]["tcp"]["ok"])              # fp tak bisa dites di TCP
            b.finalize(tv[0], ["tcp"])
            self.assertFalse(tv[0]["ok"])
        finally:
            srv.close()

    def test_dns_failure_and_udp(self):
        r = b.tcp_probe(tcp_node(server="tidak-ada.invalid"), 2)
        self.assertFalse(r["ok"]); self.assertIn("DNS", r["detail"])
        self.assertIsNone(b.tcp_probe({"type": "hysteria2", "server": "x", "port": 1}, 1)["ok"])

    def test_intercept_detection(self):
        vs = [{"res": {"tcp": {"conn_ms": 2}}} for _ in range(5)]
        self.assertTrue(b.tcp_intercepted(vs))
        vs = [{"res": {"tcp": {"conn_ms": 80}}} for _ in range(5)]
        self.assertFalse(b.tcp_intercepted(vs))


# ---------------------------------------------------------------- rantai mode (mihomo dipalsukan)
class Chain(unittest.TestCase):
    def setUp(self):
        self.seen = []
        self._orig = b.run_mihomo

        def fake(variants, core, url, timeout_ms, workers, progress=None):
            self.seen.append([v["id"] for v in variants])
            for v in variants:
                good = "good" in json.dumps(v["fields"])
                v["res"]["mihomo"] = {"ok": good, "ms": 40 if good else None, "detail": "x" if good else "urltest: timeout"}

        b.run_mihomo = fake

    def tearDown(self):
        b.run_mihomo = self._orig

    def test_failed_in_tcp_never_reaches_mihomo(self):
        srv = WsServer()
        try:
            n = dict(WS_NODE, port=srv.port)
            vs, _ = b.build_variants([n], {"host": ["good-a.example", "bad-b.example"]}, include_base=False)
            b.test_variants(vs, ["tcp", "mihomo"], {"timeout": 3, "mihomo_core": "/fake"})
            # kedua host != good.example -> tcp 403 untuk keduanya -> mihomo tidak dipanggil
            self.assertEqual(self.seen, [])
            self.assertFalse(any(v["ok"] for v in vs))
            self.assertIn("TCP/TLS", vs[0]["reason"])
        finally:
            srv.close()

    def test_mihomo_only_and_missing_core(self):
        vs, _ = b.build_variants([tcp_node()], {"sni": ["good1.com", "bad1.com"]}, include_base=False)
        b.test_variants(vs, ["mihomo"], {"mihomo_core": "/fake"})
        self.assertEqual([v["ok"] for v in vs], [True, False])
        self.assertEqual(vs[0]["ms"], 40)
        self.assertIn("Mihomo", vs[1]["reason"])
        with self.assertRaises(RuntimeError):
            b.test_variants(vs, ["mihomo"], {})
        with self.assertRaises(RuntimeError):
            b.test_variants(vs, ["v2ray"], {})

    def test_combos_from_best_of_each_field(self):
        n = tcp_node()
        vs, _ = b.build_variants([n], {"sni": ["good1.com", "good2.com"], "server": ["good.ip.com"]}, include_base=False)
        b.test_variants(vs, ["mihomo"], {"mihomo_core": "/fake"})
        for v in vs:                                                   # sni good2 dibuat paling cepat
            v["ms"] = 10 if v["fields"].get("sni") == "good2.com" else 90
        combos = b.make_combos(vs)
        self.assertEqual(len(combos), 1)
        c = combos[0]
        self.assertEqual(c["kind"], "combo")
        self.assertEqual(c["node"]["servername"], "good2.com")
        self.assertEqual(c["node"]["server"], "good.ip.com")
        self.assertEqual(c["node"]["name"], "T [combo]")
        self.assertEqual(c["id"], max(v["id"] for v in vs) + 1)
        self.assertEqual(b.make_combos([v for v in vs if v["kind"] == "sni"]), [])   # 1 field saja -> tidak ada combo


# ---------------------------------------------------------------- Mihomo (core palsu + mesin sub2yaml asli)
class MihomoMode(unittest.TestCase):
    def test_run_mihomo_through_sub2yaml_engine(self):
        with tempfile.TemporaryDirectory() as d:
            core = os.path.join(d, "mihomo")
            with open(core, "w") as f:
                f.write(FAKE_MIHOMO.format(py=sys.executable))
            os.chmod(core, 0o755)
            self.assertEqual(b.find_mihomo.__name__, "find_mihomo")
            nodes = [tcp_node(name="N", server="good.example", network="tcp")]
            cands = {"server": ["good2.example", "bad.example", "badcfg.example"]}
            vs, _ = b.build_variants(nodes, cands)
            b.test_variants(vs, ["mihomo"], {"mihomo_core": core, "timeout": 3})
            got = {v["fields"].get("server", "base"): v for v in vs}
            self.assertTrue(got["base"]["ok"]); self.assertEqual(got["base"]["ms"], 55)
            self.assertTrue(got["good2.example"]["ok"])
            self.assertFalse(got["bad.example"]["ok"])
            self.assertIn("Mihomo", got["bad.example"]["reason"])
            self.assertFalse(got["badcfg.example"]["ok"])                 # ditolak -t -> hanya dia yang dibuang
            self.assertIn("ditolak mihomo", got["badcfg.example"]["reason"])
            self.assertEqual(sum(1 for v in vs if v["ok"]), 2)

    def test_chain_tcp_then_mihomo_real_engine(self):
        srv = WsServer(good_host={"good.example", "cdn1.example"})
        try:
            with tempfile.TemporaryDirectory() as d:
                core = os.path.join(d, "mihomo")
                with open(core, "w") as f:
                    f.write(FAKE_MIHOMO.format(py=sys.executable))
                os.chmod(core, 0o755)
                n = dict(WS_NODE, port=srv.port)
                vs, _ = b.build_variants([n], {"host": ["cdn1.example", "bad.example"]}, include_base=False)
                b.test_variants(vs, ["tcp", "mihomo"], {"mihomo_core": core, "timeout": 3})
                self.assertEqual([v["ok"] for v in vs], [False, False])   # server node = 127.0.0.1 -> bukan 'good*' di core palsu
                self.assertIn("mihomo", vs[0]["res"])                    # cdn1 lolos TCP lalu dites mihomo
                self.assertNotIn("mihomo", vs[1]["res"])                 # bad.example gagal di TCP, tidak sampai mihomo
        finally:
            srv.close()


# ---------------------------------------------------------------- V2Ray/Xray
class Xray(unittest.TestCase):
    def test_outbounds(self):
        o = b.node_to_xray_outbound(TLS_WS_NODE, "t")
        self.assertEqual(o["protocol"], "vless")
        u = o["settings"]["vnext"][0]
        self.assertEqual((u["address"], u["users"][0]["id"], u["users"][0]["encryption"]), ("127.0.0.1", "u", "none"))
        ss = o["streamSettings"]
        self.assertEqual(ss["network"], "ws")
        self.assertEqual(ss["wsSettings"], {"path": "/ws", "headers": {"Host": "good.example"}})
        self.assertEqual(ss["security"], "tls")
        self.assertEqual(ss["tlsSettings"], {"serverName": "ok.example", "allowInsecure": True})

        rel = tcp_node(flow="xtls-rprx-vision", **{"client-fingerprint": "chrome",
                                                   "reality-opts": {"public-key": "PUB", "short-id": "ab"}})
        o = b.node_to_xray_outbound(rel, "r")
        self.assertEqual(o["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(o["streamSettings"]["security"], "reality")
        self.assertEqual(o["streamSettings"]["realitySettings"]["publicKey"], "PUB")

        vm = {"name": "v", "type": "vmess", "server": "s.com", "port": 80, "uuid": "u", "alterId": 0, "cipher": "auto",
              "tls": False, "network": "grpc", "grpc-opts": {"grpc-service-name": "gs"}}
        o = b.node_to_xray_outbound(vm, "v")
        self.assertEqual(o["settings"]["vnext"][0]["users"][0]["security"], "auto")
        self.assertEqual(o["streamSettings"]["grpcSettings"], {"serviceName": "gs"})
        self.assertNotIn("security", o["streamSettings"])

        tr = {"name": "t", "type": "trojan", "server": "s.com", "port": 443, "password": "pw", "sni": "x.com",
              "skip-cert-verify": False, "network": "ws",
              "ws-opts": {"path": "/", "v2ray-http-upgrade": True, "headers": {"Host": "h.com"}}}
        o = b.node_to_xray_outbound(tr, "t")
        self.assertEqual(o["settings"]["servers"][0]["password"], "pw")
        self.assertEqual(o["streamSettings"]["network"], "httpupgrade")
        self.assertEqual(o["streamSettings"]["httpupgradeSettings"], {"path": "/", "host": "h.com"})
        self.assertFalse(o["streamSettings"]["tlsSettings"]["allowInsecure"])

        with self.assertRaises(ValueError):
            b.node_to_xray_outbound({"type": "hysteria2", "server": "s", "port": 1}, "h")
        with self.assertRaises(ValueError):
            b.node_to_xray_outbound(tcp_node(network="quic"), "q")

    def test_config_shape(self):
        items = [(3, {"protocol": "freedom"}), (7, {"protocol": "freedom"})]
        cfg = b.build_xray_config(items, [10001, 10002])
        self.assertEqual([i["port"] for i in cfg["inbounds"]], [10001, 10002])
        self.assertEqual([o["tag"] for o in cfg["outbounds"]], ["out3", "out7"])
        self.assertEqual(cfg["routing"]["rules"][1], {"type": "field", "inboundTag": ["in7"], "outboundTag": "out7"})

    def test_socks5_probe_against_fake_socks(self):
        http = _TS(("127.0.0.1", 0), _H204)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        socks, port = _fake_socks_server(http.server_address[1], allow=True)
        try:
            status, ms = b.socks5_http_status(port, "http://www.gstatic.com/generate_204", 3)
            self.assertEqual(status, 204)
            self.assertTrue(b._status_ok("http://x/generate_204", 204))
            self.assertFalse(b._status_ok("http://x/generate_204", 200))
            self.assertTrue(b._status_ok("http://x/", 200))
        finally:
            socks.close(); http.shutdown()
        s2, p2 = _fake_socks_server(0, allow=False)
        try:
            with self.assertRaises(ValueError):
                b.socks5_http_status(p2, "http://www.gstatic.com/generate_204", 3)
        finally:
            s2.close()

    def test_flavor_and_batch_with_fake_core(self):
        http = _TS(("127.0.0.1", 0), _H204)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory() as d:
            core = _write_fake_xray(d, http.server_address[1])
            try:
                self.assertEqual(b.v2ray_flavor(core), "xray")
                self.assertEqual(b.find_v2ray(core), (core, "xray"))
                nodes = [tcp_node(name="N", server="good.example", network="tcp")]
                cands = {"server": ["good2.example", "bad.example", "badcfg.example", "good3.example"]}
                vs, _ = b.build_variants(nodes, cands)
                res = b.test_variants(vs, ["v2ray"], {"v2ray_core": core, "v2ray_flavor": "xray", "timeout": 3})
                got = {v["fields"].get("server", "base"): (v["ok"], v["reason"]) for v in res}
                self.assertTrue(got["base"][0])
                self.assertTrue(got["good2.example"][0])
                self.assertTrue(got["good3.example"][0])
                self.assertFalse(got["bad.example"][0])
                self.assertIn("SOCKS5", got["bad.example"][1])
                self.assertFalse(got["badcfg.example"][0])            # ditolak -test -> dibelah dua, hanya dia yang gagal
                self.assertIn("ditolak core", got["badcfg.example"][1])
            finally:
                http.shutdown()

    def test_chain_tcp_then_v2ray_uses_only_survivors(self):
        # node tak didukung mode V2Ray ditandai gagal tanpa menjatuhkan batch
        http = _TS(("127.0.0.1", 0), _H204)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory() as d:
            core = _write_fake_xray(d, http.server_address[1])
            try:
                vs, _ = b.build_variants([tcp_node(server="good.example", network="quic"),
                                          tcp_node(name="ok", server="good.example")], {})
                b.test_variants(vs, ["v2ray"], {"v2ray_core": core, "v2ray_flavor": "xray", "timeout": 3})
                self.assertFalse(vs[0]["ok"]); self.assertIn("tidak didukung", vs[0]["reason"])
                self.assertTrue(vs[1]["ok"])
            finally:
                http.shutdown()

    def test_v2ray4_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v2ray")
            for ver, want in (("4.45.2", None), ("5.16.1", "v2ray")):
                with open(p, "w") as f:
                    f.write(f"#!{sys.executable}\nprint('V2Ray {ver} (V2Fly)')\n")
                os.chmod(p, 0o755)
                self.assertEqual(b.v2ray_flavor(p), want)


FAKE_MIHOMO = r"""#!{py}
import json, sys, yaml
from http.server import BaseHTTPRequestHandler, HTTPServer
args = sys.argv[1:]
if args[:1] == ["-v"]:
    print("Mihomo Meta v1.19.0 linux amd64 (fake)"); sys.exit(0)
cfg = yaml.safe_load(open(args[args.index("-f") + 1]))
servers = {{p["name"]: p["server"] for p in cfg["proxies"]}}
if "-t" in args:
    for i, p in enumerate(cfg["proxies"]):
        if p["server"].startswith("badcfg"):
            print("configuration file test failed: proxy %d: unsupported %s" % (i, p["server"]), file=sys.stderr); sys.exit(1)
    sys.exit(0)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/version"):
            body, code = {{"version": "fake"}}, 200
        else:
            name = self.path.split("/")[2]
            if servers.get(name, "").startswith("good"):
                body, code = {{"delay": 55}}, 200
            else:
                body, code = {{"message": "An error occurred in the delay test"}}, 504
        raw = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
host, port = cfg["external-controller"].rsplit(":", 1)
HTTPServer((host, int(port)), H).serve_forever()
"""


def _fake_socks_server(http_port, allow):
    """SOCKS5 minimal: allow=True -> tunnel ke 127.0.0.1:http_port; False -> balas 'connection refused'."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(32)

    def serve(c):
        try:
            c.settimeout(3)
            c.recv(3); c.sendall(b"\x05\x00")
            head = c.recv(4)
            n = c.recv(1)[0]; c.recv(n + 2)
            if not allow:
                c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); return
            up = socket.create_connection(("127.0.0.1", http_port), timeout=3)
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            def pipe(a, bb):
                try:
                    while True:
                        x = a.recv(4096)
                        if not x:
                            break
                        bb.sendall(x)
                except OSError:
                    pass
                finally:
                    try: bb.shutdown(socket.SHUT_WR)
                    except OSError: pass
            threading.Thread(target=pipe, args=(c, up), daemon=True).start()
            pipe(up, c)
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


FAKE_XRAY = r'''#!{py}
import json, socket, sys, threading, time
HTTP = {http}
args = sys.argv[1:]
if args[:1] == ["version"] or args[:1] == ["-version"]:
    print("Xray 1.8.99 (fake) Custom (go1.22 linux/amd64)"); sys.exit(0)
cfg = json.load(open(args[args.index("-c") + 1]))
obs = {{o["tag"]: o for o in cfg["outbounds"]}}
def addr(o):
    s = o.get("settings", {{}})
    return (s.get("vnext") or s.get("servers"))[0]["address"]
if "-test" in args:
    bad = [addr(o) for o in cfg["outbounds"] if addr(o).startswith("badcfg")]
    if bad:
        print("Failed to start: bad outbound " + bad[0], file=sys.stderr); sys.exit(1)
    sys.exit(0)
rules = {{r["inboundTag"][0]: r["outboundTag"] for r in cfg["routing"]["rules"]}}
def serve(c, good):
    try:
        c.settimeout(5); c.recv(3); c.sendall(b"\x05\x00"); c.recv(4); n = c.recv(1)[0]; c.recv(n + 2)
        if not good:
            c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"); return
        up = socket.create_connection(("127.0.0.1", HTTP), timeout=3)
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        def pipe(a, b):
            try:
                while True:
                    x = a.recv(4096)
                    if not x: break
                    b.sendall(x)
            except OSError: pass
            finally:
                try: b.shutdown(socket.SHUT_WR)
                except OSError: pass
        threading.Thread(target=pipe, args=(c, up), daemon=True).start(); pipe(up, c)
    except Exception: pass
    finally: c.close()
for ib in cfg["inbounds"]:
    good = addr(obs[rules[ib["tag"]]]).startswith("good")
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((ib["listen"], ib["port"])); s.listen(16)
    def loop(s=s, good=good):
        while True:
            c, _ = s.accept(); threading.Thread(target=serve, args=(c, good), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
while True: time.sleep(1)
'''


def _write_fake_xray(d, http_port):
    p = os.path.join(d, "xray")
    with open(p, "w") as f:
        f.write(FAKE_XRAY.format(py=sys.executable, http=http_port))
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    return p


# ---------------------------------------------------------------- alur menu (input dipalsukan)
class MenuFlow(unittest.TestCase):
    """Menjalankan feature_convert_to_clash / feature_regenerate dengan input terskrip + server WS lokal."""

    def setUp(self):
        self._saved = (h.BASE_DIR, h.BUGTEST_DIR, h.SETTINGS_PATH)
        self._tmp = tempfile.TemporaryDirectory()
        h.BASE_DIR = os.path.join(self._tmp.name, "hasil")
        h.BUGTEST_DIR = os.path.join(h.BASE_DIR, "bugtest")
        h.SETTINGS_PATH = os.path.join(self._tmp.name, "settings.json")
        os.makedirs(h.BASE_DIR)
        self.srv = WsServer(good_host={"good.example", "cdn1.example", "cdn2.example"})
        self.uri = (f"vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{self.srv.port}"
                    f"?security=none&type=ws&host=good.example&path=%2Fws#HIKARI%20WS")

    def tearDown(self):
        self.srv.close()
        h.BASE_DIR, h.BUGTEST_DIR, h.SETTINGS_PATH = self._saved
        self._tmp.cleanup()

    def run_flow(self, fn, inputs):
        it = iter(inputs)

        def fake_input(prompt=""):
            try:
                return next(it)
            except StopIteration:
                raise EOFError

        out = io.StringIO()
        old = builtins.input
        builtins.input = fake_input
        try:
            with contextlib.redirect_stdout(out):
                fn()
        finally:
            builtins.input = old
        self.assertEqual(list(it), [], "input skrip tidak terpakai semua -> alur menu bergeser")
        return out.getvalue()

    def active_names(self, plat="box"):
        import yaml
        p = os.path.join(h.BASE_DIR, h.PLATFORMS[plat]["out"], h.PLATFORMS[plat]["proxy_dir"], "active.yaml")
        return [n["name"] for n in yaml.safe_load(open(p, encoding="utf-8"))["proxies"]]

    def bug_dir(self):
        d = os.listdir(h.BUGTEST_DIR)
        self.assertEqual(len(d), 1)
        return os.path.join(h.BUGTEST_DIR, d[0])

    # paste URI -> [U] -> host+address -> TCP -> tambahkan -> [L] -> generate Box
    FLOW_PREFIX = ["u", "2,3", "cdn1.example cdn2.example, bad.example", "", "localhost 127.0.0.2", "",
                   "1", "", "", ""]                               # mode TCP, timeout default, DNS operator (lewati), mulai

    def test_convert_flow_adds_variants_and_writes_outputs(self):
        inputs = [self.uri, ""] + self.FLOW_PREFIX + ["", "1", "l", "b", "1", "", "", ""]
        out = self.run_flow(h.feature_convert_to_clash, inputs)
        self.assertIn("[U] Uji bug", out)
        self.assertIn("2/3 lolos", out)                          # host: cdn1, cdn2 lolos; bad ditolak
        names = self.active_names()
        self.assertEqual(len(names), 5)                          # asli + host x2 + addr + combo
        self.assertTrue(any("[combo]" in n for n in names))
        self.assertTrue(any("[host:cdn1.example]" in n for n in names))
        self.assertFalse(any("bad.example" in n for n in names))
        d = self.bug_dir()
        for f in ("custom-host.yaml", "custom-address.yaml", "custom-combined.yaml", "bug-ok.yaml", "bug-ok-uri.txt", "report.txt"):
            self.assertTrue(os.path.isfile(os.path.join(d, f)), f)
        uris = open(os.path.join(d, "bug-ok-uri.txt"), encoding="utf-8").read().split()
        self.assertEqual(len(uris), 4)
        self.assertTrue(all(u.startswith("vless://") for u in uris))
        self.assertTrue(any("host=cdn1.example" in u for u in uris))
        for u in uris:                                           # URI hasil bisa diparse balik oleh converter sendiri
            n = h.convert_line(u)
            self.assertEqual(n["type"], "vless")

    def test_convert_flow_replace_drops_original(self):
        inputs = [self.uri, ""] + self.FLOW_PREFIX + ["", "2", "l", "b", "1", "", "", ""]
        self.run_flow(h.feature_convert_to_clash, inputs)
        names = self.active_names()
        self.assertEqual(len(names), 4)
        self.assertNotIn("HIKARI WS", [n.split(" ", 1)[-1] for n in names])      # node asli diganti

    def test_convert_flow_dont_use_keeps_only_original(self):
        inputs = [self.uri, ""] + self.FLOW_PREFIX + ["", "3", "l", "b", "1", "", "", ""]
        self.run_flow(h.feature_convert_to_clash, inputs)
        self.assertEqual(len(self.active_names()), 1)
        self.assertTrue(os.path.isfile(os.path.join(self.bug_dir(), "report.txt")))     # file hasil tetap ada

    def test_cancel_candidates_returns_to_preview(self):
        inputs = [self.uri, "", "u", "2", "batal", "b"]
        out = self.run_flow(h.feature_convert_to_clash, inputs)
        self.assertNotIn("Hasil Uji", out)
        self.assertFalse(os.path.isdir(h.BUGTEST_DIR))

    def test_no_valid_candidates_is_reported(self):
        inputs = [self.uri, "", "u", "1", "kata !!!", "", "b"]       # SNI: semua token tidak valid; node tanpa TLS
        out = self.run_flow(h.feature_convert_to_clash, inputs)
        self.assertIn("Tidak ada kandidat yang valid", out)

    def test_delete_variant_number_in_preview(self):
        # hapus varian nomor 2 (varian pertama) lewat [H], lalu lanjut
        inputs = [self.uri, ""] + self.FLOW_PREFIX + ["", "1", "h", "2", "l", "b", "1", "", "", ""]
        self.run_flow(h.feature_convert_to_clash, inputs)
        self.assertEqual(len(self.active_names()), 4)

    def test_lazy_flow_end_to_end(self):
        """[U] -> L (Lazy) -> bug -> TCP: metode yang cocok tampil per metode & tersimpan di file hasil."""
        srv = WsServer(good_host={"localhost"})
        self.addCleanup(srv.close)
        for name, val in (("_resolve", lambda host, port=0: "127.0.0.1"), ("LAZY_PLAIN_PORTS", (srv.port,))):
            self.addCleanup(setattr, b, name, getattr(b, name))
            setattr(b, name, val)
        uri = (f"vless://11111111-2222-3333-4444-555555555555@127.0.0.1:{srv.port}"
               f"?security=none&type=ws&host=localhost&path=%2Fws#LAZY")
        inputs = [uri, "", "u", "l", "bug.example", "", "", str(srv.port), "1", "", "", "", "3", "b"]
        out = self.run_flow(h.feature_convert_to_clash, inputs)
        self.assertIn("Lazy", out)
        self.assertIn("2/6 lolos", out)                                  # http-direct + http-bug-addr
        self.assertIn("per metode", out)
        self.assertIn("✓ http-direct", out)
        self.assertIn("✗ http-host-ip", out)
        self.assertNotIn("gabungan terbaik", out)                        # Lazy tidak punya langkah gabungan
        d = self.bug_dir()
        for f in ("custom-lazy.yaml", "bug-ok.yaml", "bug-ok-uri.txt", "report.txt"):
            self.assertTrue(os.path.isfile(os.path.join(d, f)), f)
        with open(os.path.join(d, "report.txt"), encoding="utf-8") as f:
            self.assertIn("=== Ringkasan metode Lazy ===", f.read())
        with open(os.path.join(d, "bug-ok-uri.txt"), encoding="utf-8") as f:
            uris = f.read().split()
        self.assertEqual(len(uris), 2)
        self.assertTrue(all(u.startswith("vless://") for u in uris))

    def test_pick_fields_accepts_lazy_shortcut(self):
        for raw in ("l", "L", "lazy"):
            it = iter([raw])
            old = builtins.input
            builtins.input = lambda prompt="": next(it)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(h._bug_pick_fields(), ["lazy"])
            finally:
                builtins.input = old

    def test_regenerate_flow_with_bugtest(self):
        _, _, _, error = h.setup_full_config([h.convert_line(self.uri)], "active.yaml", "box")
        self.assertIsNone(error)
        # pilih sumber 1 -> [U] -> Host saja -> TCP -> tambahkan -> [L] -> platform/target Enter -> sisanya default
        inputs = ["1", "u", "2", "cdn1.example cdn2.example bad.example", "", "1", "", "", "", "1", "l", "", "", "", "", ""]
        out = self.run_flow(h.feature_regenerate, inputs)
        self.assertIn("2 varian ditambahkan", out)
        self.assertEqual(len(self.active_names()), 3)

    def test_regenerate_flow_skip_test(self):
        _, _, _, error = h.setup_full_config([h.convert_line(self.uri)], "active.yaml", "box")
        self.assertIsNone(error)
        self.run_flow(h.feature_regenerate, ["1", "", "", "", "", "", ""])
        self.assertEqual(len(self.active_names()), 1)
        self.assertFalse(os.path.isdir(h.BUGTEST_DIR))


# ---------------------------------------------------------------- keluaran
class Outputs(unittest.TestCase):
    def test_write_outputs_and_report(self):
        vs, skipped = b.build_variants([tcp_node(), tcp_node(name="Plain", tls=False, servername="")],
                                       {"sni": ["a.com", "b.com"], "host": ["h.com"]})
        for v in vs:
            v["res"]["mihomo"] = {"ok": v["fields"].get("sni") == "a.com" or v["kind"] == "base",
                                  "ms": 50, "detail": "URL-test 50ms" if v["fields"].get("sni") == "a.com" else "urltest: timeout"}
            b.finalize(v, ["mihomo"])
        with tempfile.TemporaryDirectory() as d:
            files = b.write_outputs(vs, ["mihomo"], d, lambda nodes: json.dumps({"proxies": nodes}), skipped,
                                    {"when": "2026-11-24 03:00:00"})
            names = dict(files)
            self.assertEqual(names["custom-sni.yaml"], 1)
            self.assertEqual(names["bug-ok.yaml"], 1)
            self.assertNotIn("custom-host.yaml", names)                    # tak ada host yang lolos
            nodes = json.load(open(os.path.join(d, "custom-sni.yaml")))["proxies"]
            self.assertEqual(nodes[0]["name"], "T [sni:a.com]")
            self.assertFalse(any(k.startswith("_") for k in nodes[0]))
            rep = open(os.path.join(d, "report.txt"), encoding="utf-8").read()
            self.assertIn("config asli: OK", rep)
            self.assertIn("SNI: 1/2 lolos", rep)
            self.assertIn("sni=b.com", rep)
            self.assertIn("dilewati SNI: node tanpa TLS", rep)


if __name__ == "__main__":
    unittest.main()


FAKE_MIHOMO_API = r'''#!{py}
import http.server, json, re, sys, urllib.parse
args = sys.argv[1:]
cfg_path = args[args.index("-f") + 1]
if "-t" in args:
    sys.exit(0)
cfg = open(cfg_path, encoding="utf-8").read()
port = int(re.search(r"external-controller: 127.0.0.1:(\d+)", cfg).group(1))
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/version":
            body = b'{{"version": "fake"}}'
        else:
            q = urllib.parse.parse_qs(u.query)
            json.dump({{"timeout": q.get("timeout", [""])[0], "config": cfg}}, open("{log}", "w"))
            body = b'{{"delay": 123}}'
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
'''


class MihomoTimeoutAndDns(unittest.TestCase):
    """Log nyata: timeout 40 dtk -> 40000 ms -> API mihomo (int16) menolak 'Body invalid' untuk SEMUA node."""

    def test_timeout_is_clamped_below_int16(self):
        import sub2yaml as s2y
        import nodetest as nt
        self.assertEqual(s2y.clamp_delay_timeout(40000), 30000)
        self.assertEqual(s2y.clamp_delay_timeout(5000), 5000)
        self.assertEqual(s2y.clamp_delay_timeout("bukan angka"), 5000)
        self.assertEqual(s2y.clamp_delay_timeout(0), 1)
        self.assertLess(s2y.MIHOMO_DELAY_MAX_MS, 32768)
        self.assertEqual(nt.MIHOMO_DELAY_MAX_MS, s2y.MIHOMO_DELAY_MAX_MS)

    def test_mihomo_delays_sends_clamped_timeout_and_dns_to_core(self):
        import sub2yaml as s2y
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "calls.json")
            core = os.path.join(d, "mihomo")
            with open(core, "w") as f:
                f.write(FAKE_MIHOMO_API.format(py=sys.executable, log=log))
            os.chmod(core, os.stat(core).st_mode | stat.S_IEXEC)
            ok, fails, rej = s2y.mihomo_delays(core, {1: {"type": "vless", "server": "1.2.3.4", "port": 443}},
                                               "http://www.gstatic.com/generate_204", 40000, 1,
                                               dns_servers=["112.215.203.254"])
            calls = json.load(open(log, encoding="utf-8"))
        self.assertEqual(ok, {1: 123})
        self.assertEqual(calls["timeout"], "30000")                          # 40000 ms dipotong ke 30000
        self.assertIn("proxy-server-nameserver", calls["config"])
        self.assertIn("112.215.203.254", calls["config"])

    def test_probe_config_without_dns_has_no_dns_block(self):
        import yaml
        import sub2yaml as s2y
        cfg = yaml.safe_load(s2y.mihomo_probe_config([{"name": "p1", "type": "vless"}], 9090))
        self.assertNotIn("dns", cfg)
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9090")

    def test_probe_config_with_operator_dns(self):
        import yaml
        import sub2yaml as s2y
        cfg = yaml.safe_load(s2y.mihomo_probe_config([{"name": "p1", "type": "vless"}], 9090,
                                                     ["112.215.203.254", "118.98.44.10"]))
        d = cfg["dns"]
        self.assertTrue(d["enable"])
        for k in ("default-nameserver", "nameserver", "proxy-server-nameserver"):
            self.assertEqual(d[k], ["112.215.203.254", "118.98.44.10"], k)
        self.assertEqual(d["enhanced-mode"], "normal")


class OperatorDnsResolver(unittest.TestCase):
    def tearDown(self):
        b.set_dns_servers(None)

    def _server(self, answer_ip="112.215.212.72", rcode=0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        seen = []

        def run():
            sock.settimeout(5)
            try:
                data, addr = sock.recvfrom(512)
            except OSError:
                return
            seen.append(data)
            import struct as st
            qend = 12
            while data[qend] != 0:
                qend += 1 + data[qend]
            question = data[12:qend + 5]
            if rcode:
                resp = st.pack(">HHHHHH", st.unpack(">H", data[:2])[0], 0x8180 | rcode, 1, 0, 0, 0) + question
            else:
                resp = (st.pack(">HHHHHH", st.unpack(">H", data[:2])[0], 0x8180, 1, 1, 0, 0) + question +
                        b"\xc0\x0c" + st.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip))
            sock.sendto(resp, addr)
        th = threading.Thread(target=run, daemon=True)
        th.start()
        return sock, th, seen

    def test_dns_query_a_roundtrip(self):
        sock, th, seen = self._server()
        try:
            ips = b.dns_query_a("i.scdn.co", "127.0.0.1", timeout=3, port=sock.getsockname()[1])
        finally:
            th.join(2); sock.close()
        self.assertEqual(ips, ["112.215.212.72"])
        self.assertIn(b"\x01i\x04scdn\x02co\x00", seen[0])

    def test_nxdomain_raises(self):
        sock, th, _ = self._server(rcode=3)
        try:
            with self.assertRaises(OSError) as cm:
                b.dns_query_a("nope.example", "127.0.0.1", timeout=3, port=sock.getsockname()[1])
        finally:
            th.join(2); sock.close()
        self.assertIn("NXDOMAIN", str(cm.exception))

    def test_invalid_names_rejected(self):
        for bad in ("", "a..b", "x" * 64 + ".com"):
            with self.assertRaises(ValueError):
                b.build_dns_query(bad, 1)

    def test_resolve_uses_operator_dns_when_set_and_ip_passthrough(self):
        self.assertEqual(b._resolve("1.2.3.4", 443), "1.2.3.4")           # IP tidak diresolve
        b.set_dns_servers(["127.0.0.1"])
        # port 53 lokal tidak ada server -> gagal dengan pesan jelas, TIDAK jatuh diam-diam ke resolver sistem
        with self.assertRaises(OSError) as cm:
            b._resolve("host.example", 443)
        self.assertIn("DNS operator gagal", str(cm.exception))

    def test_tcp_probe_reports_operator_dns_failure(self):
        b.set_dns_servers(["127.0.0.1"])
        res = b.tcp_probe({"type": "vless", "server": "host.example", "port": 443}, timeout=1)
        self.assertFalse(res["ok"])
        self.assertIn("DNS gagal", res["detail"])
        self.assertIn("DNS operator", res["detail"])

    def test_test_variants_sets_and_resets_dns_servers(self):
        seen = {}
        orig = b.run_tcp
        b.run_tcp = lambda alive, *a, **k: seen.update(dns=list(b.DNS_SERVERS))
        try:
            b.test_variants([], ["tcp"], {"dns_servers": ["10.0.0.1"]})
            v = [{"id": 1, "res": {}, "node": {"server": "1.2.3.4", "port": 1}, "kind": "base", "base": 0,
                  "base_name": "n", "fields": {}}]
            b.test_variants(v, ["tcp"], {"dns_servers": ["10.0.0.1"]})
        finally:
            b.run_tcp = orig
        self.assertEqual(seen.get("dns"), ["10.0.0.1"])
        self.assertEqual(b.DNS_SERVERS, [])                              # selalu dikembalikan


# ---------------------------------------------------------------- Phantom (PhantomNG)
PH_NODE = {"name": "PH", "type": "vless", "server": "127.0.0.1", "port": 1, "uuid": "u", "tls": True,
           "servername": "srv.example", "network": "ws",
           "ws-opts": {"path": "/ws", "headers": {"Host": "srv.example"}}}


def make_san_cert(d, *dns):
    key, crt = os.path.join(d, "ks.pem"), os.path.join(d, "cs.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "2", "-subj", "/CN=" + dns[0], "-addext",
                    "subjectAltName=" + ",".join("DNS:" + n for n in dns)], check=True, capture_output=True)
    return crt, key


class PhantomSni(unittest.TestCase):
    def test_parse_and_build(self):
        self.assertEqual(b.parse_phantom_sni("phantom:srv.example:bug.example:rand"),
                         {"server": "srv.example", "bug": "bug.example", "mode": "rand"})
        self.assertEqual(b.parse_phantom_sni("Phantom:srv.example:bug.example:auto")["mode"], "auto")
        self.assertEqual(b.parse_phantom_sni("phantom:srv.example:bug.example")["mode"], "")
        for bad in ("", "srv.example", "phantom:srv.example", "phantom:a.b:c.d:zzz", "phantom:a.b:c.d:rand:x",
                    "phantom:1.2.3.4:bug.example", "phantom:srv.example:1.2.3.4", "phantom:nodot:bug.example"):
            self.assertIsNone(b.parse_phantom_sni(bad), bad)
        self.assertEqual(b.build_phantom_sni("s.example", "b.example"), "phantom:s.example:b.example:rand")
        self.assertEqual(b.build_phantom_sni("s.example", "b.example", ""), "phantom:s.example:b.example")

    def test_candidates_reject_ip(self):
        good, bad = b.parse_candidates("phantom", "a.example 1.2.3.4, B.example https://c.example/x")
        self.assertEqual(good, ["a.example", "b.example", "c.example"])
        self.assertEqual(bad, ["1.2.3.4"])

    def test_normalize_from_converter_uri(self):
        u = ("vless://uuid@1.2.3.4:443?encryption=none&security=tls&type=ws&path=%2Fvless"
             "&sni=phantom%3Asrv.example.com%3Abug.example.com%3Arand&host=srv.example.com#t")
        n = b.normalize_phantom(h.convert_line(u))
        self.assertEqual(n["servername"], "bug.example.com")
        self.assertEqual(n["ws-opts"]["headers"]["Host"], "srv.example.com")
        self.assertTrue(n["skip-cert-verify"])
        self.assertEqual(n[b.PH], {"server": "srv.example.com", "mode": "rand"})
        # tanpa parameter host: converter mengisi Host dengan string phantom -> harus diganti domain server
        u2 = u.replace("&host=srv.example.com", "")
        raw = h.convert_line(u2)
        self.assertTrue(raw["ws-opts"]["headers"]["Host"].startswith("phantom:"))
        self.assertEqual(b.normalize_phantom(raw)["ws-opts"]["headers"]["Host"], "srv.example.com")
        # trojan memakai kunci 'sni'
        t = {"name": "t", "type": "trojan", "server": "1.1.1.1", "port": 443, "password": "p",
             "sni": "phantom:srv.example.com:bug.example.com", "network": "tcp"}
        nt = b.normalize_phantom(t)
        self.assertEqual((nt["sni"], nt[b.PH]["server"], nt[b.PH]["mode"]), ("bug.example.com", "srv.example.com", ""))
        # node biasa tidak disentuh; node asli tidak diubah
        self.assertNotIn(b.PH, b.normalize_phantom(PH_NODE))
        self.assertTrue(raw["servername"].startswith("phantom:"))

    def test_build_variants_normalizes_base(self):
        t = {"name": "t", "type": "vless", "server": "1.1.1.1", "port": 443, "uuid": "u", "tls": True,
             "servername": "phantom:srv.example.com:bug.example.com:rand", "network": "ws",
             "ws-opts": {"path": "/", "headers": {"Host": "srv.example.com"}}}
        vs, _ = b.build_variants([t], {})
        self.assertEqual(vs[0]["node"]["servername"], "bug.example.com")
        self.assertEqual(vs[0]["node"][b.PH]["server"], "srv.example.com")


class PhantomVariant(unittest.TestCase):
    def test_apply(self):
        q, why = b.apply_variant(PH_NODE, "phantom", "bug.example")
        self.assertIsNone(why)
        self.assertEqual(q["servername"], "bug.example")
        self.assertEqual(q["ws-opts"]["headers"]["Host"], "srv.example")
        self.assertTrue(q["skip-cert-verify"])
        self.assertEqual(q[b.PH], {"server": "srv.example", "mode": "rand"})
        self.assertNotIn(b.PH, b.clean_node(q))                          # tidak bocor ke YAML
        self.assertNotIn(b.PH, PH_NODE)                                  # node asli utuh
        # varian sama dengan asli (SNI sudah bug itu & sudah Phantom) -> SAME
        self.assertEqual(b.apply_variant(q, "phantom", "bug.example")[1][0], b.SAME)
        # field lain mempertahankan metadata Phantom
        self.assertEqual(b.apply_variant(q, "port", 8443)[0][b.PH]["server"], "srv.example")
        self.assertEqual(b.apply_variant(q, "path", "/x")[0][b.PH]["server"], "srv.example")

    def test_server_from_host_then_sni_then_address(self):
        n = dict(PH_NODE, **{"ws-opts": {"path": "/", "headers": {"Host": "h.example"}}})
        self.assertEqual(b.apply_variant(n, "phantom", "b.example")[0][b.PH]["server"], "h.example")
        n = dict(tcp_node(server="addr.example", servername="sni.example"))
        q = b.apply_variant(n, "phantom", "b.example")[0]
        self.assertEqual(q[b.PH]["server"], "sni.example")               # tcp: tidak ada Host
        n = dict(tcp_node(server="addr.example", servername="1.2.3.4"))
        self.assertEqual(b.apply_variant(n, "phantom", "b.example")[0][b.PH]["server"], "addr.example")

    def test_not_applicable(self):
        self.assertEqual(b.apply_variant(dict(PH_NODE, tls=False), "phantom", "b.example")[1][0], b.NA)
        self.assertEqual(b.apply_variant(dict(PH_NODE, **{"reality-opts": {"public-key": "k"}}), "phantom", "b.example")[1][0], b.NA)
        ip_only = tcp_node(server="1.2.3.4", servername="")
        why = b.apply_variant(ip_only, "phantom", "b.example")[1]
        self.assertEqual(why[0], b.NA); self.assertIn("domain server", why[1])
        vs, skipped = b.build_variants([ip_only], {"phantom": ["a.example", "b.example"]})
        self.assertEqual([s[2] for s in skipped], ["phantom"])
        self.assertEqual(len(vs), 1)                                     # hanya config asli

    def test_variant_naming(self):
        vs, _ = b.build_variants([PH_NODE], {"phantom": ["b.example"]})
        v = vs[1]
        self.assertEqual((v["kind"], v["node"]["name"]), ("phantom", "PH [phantom:b.example]"))
        self.assertEqual(b.describe_fields(v), "phantom=b.example")

    def test_combo_phantom_supersedes_sni_and_keeps_server(self):
        vs, _ = b.build_variants([PH_NODE], {"sni": ["a.example"], "host": ["h.example"], "phantom": ["b.example"]})
        for v in vs:
            v["ok"], v["ms"] = True, 10
        combos = b.make_combos(vs)
        self.assertEqual(len(combos), 1)
        c = combos[0]
        self.assertEqual(sorted(c["fields"]), ["host", "phantom"])        # sni dibuang
        self.assertEqual(c["node"]["servername"], "b.example")
        self.assertEqual(c["node"]["ws-opts"]["headers"]["Host"], "h.example")
        self.assertEqual(c["node"][b.PH]["server"], "srv.example")        # bukan h.example

    def test_xray_outbound_verifies_by_name(self):
        q = b.apply_variant(PH_NODE, "phantom", "bug.example")[0]
        ts = b.node_to_xray_outbound(q, "t")["streamSettings"]["tlsSettings"]
        self.assertEqual(ts, {"serverName": "bug.example", "verifyPeerCertByName": "srv.example"})
        plain = b.node_to_xray_outbound(b.apply_variant(PH_NODE, "sni", "x.example")[0], "t")
        self.assertEqual(plain["streamSettings"]["tlsSettings"]["allowInsecure"], True)   # non-Phantom tak berubah

    def test_mihomo_node_has_no_meta_and_skips_verify(self):
        q = b.apply_variant(PH_NODE, "phantom", "bug.example")[0]
        m = b.clean_node(q)
        self.assertNotIn(b.PH, m)
        self.assertTrue(m["skip-cert-verify"])
        self.assertEqual(m["servername"], "bug.example")

    def test_export_node_and_uri_roundtrip(self):
        q = b.apply_variant(PH_NODE, "phantom", "bug.example")[0]
        e = b.phantom_export_node(q)
        self.assertEqual(e["servername"], "phantom:srv.example:bug.example:rand")
        self.assertFalse(e["skip-cert-verify"])
        self.assertIsNone(b.phantom_export_node(PH_NODE))
        uri = h.build_uri_from_proxy(e)
        self.assertIn("phantom", uri)
        self.assertNotIn("allowInsecure", uri)
        back = b.normalize_phantom(h.convert_line(uri))
        self.assertEqual(back["servername"], "bug.example")
        self.assertEqual(back[b.PH], {"server": "srv.example", "mode": "rand"})

    def test_menu_has_phantom_last_and_defaults_unchanged(self):
        self.assertEqual(h.BUG_FIELD_MENU[-1][0], "phantom")
        self.assertEqual([f for f, _, _ in h.BUG_FIELD_MENU[:3]], ["sni", "host", "server"])   # default menu "1,2,3"
        self.assertEqual([f for f, _, _ in h.BUG_FIELD_MENU], list(b.FIELDS))


@unittest.skipUnless(shutil.which("openssl"), "openssl tidak ada")
class PhantomTcpVerify(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.crt, self.key = make_san_cert(self._tmp.name, "srv.example", "*.wild.example")
        self.srv = WsServer(good_host=("srv.example", "other.example", "x.wild.example"),
                            tls_ctx=server_tls_ctx(self.crt, self.key, {"bug.example", "srv.example"}))
        self.addCleanup(self.srv.close)
        self._ca = b.CA_FILE
        b.CA_FILE = self.crt
        self.addCleanup(setattr, b, "CA_FILE", self._ca)
        self.node = dict(PH_NODE, port=self.srv.port)

    def test_cert_matches_server_name(self):
        q = b.apply_variant(self.node, "phantom", "bug.example")[0]
        r = b.tcp_probe(q, 3)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["detail"], "WS 101 OK · cert ✓ srv.example")

    def test_cert_mismatch_with_server_name_fails(self):
        n = dict(self.node, **{"ws-opts": {"path": "/ws", "headers": {"Host": "other.example"}}})
        q = b.apply_variant(n, "phantom", "bug.example")[0]
        r = b.tcp_probe(q, 3)
        self.assertFalse(r["ok"])
        self.assertIn("sertifikat tidak cocok dengan other.example", r["detail"])
        self.assertIn("srv.example", r["detail"])
        self.assertTrue(b.tcp_probe(q, 3, phantom_verify=False)["ok"])     # verifikasi bisa dimatikan

    def test_wildcard_san(self):
        n = dict(self.node, **{"ws-opts": {"path": "/ws", "headers": {"Host": "x.wild.example"}}})
        q = b.apply_variant(n, "phantom", "bug.example")[0]
        self.assertTrue(b.tcp_probe(q, 3)["ok"])
        self.assertTrue(b.cert_matches({"subjectAltName": (("DNS", "*.wild.example"),)}, "a.wild.example"))
        self.assertFalse(b.cert_matches({"subjectAltName": (("DNS", "*.wild.example"),)}, "a.b.wild.example"))
        self.assertFalse(b.cert_matches({"subjectAltName": (("DNS", "*.wild.example"),)}, "wild.example"))
        self.assertTrue(b.cert_matches({"subject": ((("commonName", "cn.example"),),)}, "cn.example"))

    def test_untrusted_cert_fails(self):
        other_crt, _ = make_san_cert(self._tmp.name, "zzz.example")
        b.CA_FILE = other_crt                                               # CA yang tidak menandatangani server
        q = b.apply_variant(self.node, "phantom", "bug.example")[0]
        r = b.tcp_probe(q, 3)
        self.assertFalse(r["ok"])
        self.assertIn("sertifikat tidak valid", r["detail"])

    def test_no_ca_available_skips_verification_with_note(self):
        b.CA_FILE = os.path.join(self._tmp.name, "tidak-ada.pem")
        q = b.apply_variant(self.node, "phantom", "bug.example")[0]
        r = b.tcp_probe(q, 3)
        self.assertTrue(r["ok"], r)
        self.assertIn("sertifikat tidak diverifikasi", r["detail"])

    def test_non_phantom_variant_never_verifies(self):
        q = b.apply_variant(self.node, "sni", "bug.example")[0]
        self.assertEqual(b.tcp_probe(q, 3)["detail"], "WS 101 OK")

    def test_unknown_bug_rejected_by_server_sni(self):
        q = b.apply_variant(self.node, "phantom", "blocked.example")[0]
        r = b.tcp_probe(q, 3)
        self.assertFalse(r["ok"]); self.assertIn("TLS gagal", r["detail"])

    def test_full_run_outputs(self):
        vs, _ = b.build_variants([self.node], {"phantom": ["bug.example", "blocked.example"]})
        b.test_variants(vs, ["tcp"], {"timeout": 3})
        self.assertEqual([v["ok"] for v in vs], [True, True, False])        # asli (SNI srv.example), bug, blocked
        out = os.path.join(self._tmp.name, "out")
        files = dict(b.write_outputs(vs, ["tcp"], out, lambda ns: json.dumps(ns)))
        self.assertEqual(files.get("custom-phantom.yaml"), 1)
        with open(os.path.join(out, "custom-phantom.yaml"), encoding="utf-8") as f:
            body = f.read()
        self.assertNotIn("_phantom", body)
        self.assertIn("bug.example", body)
        with open(os.path.join(out, "report.txt"), encoding="utf-8") as f:
            rep = f.read()
        self.assertIn("catatan Phantom", rep)
        self.assertIn("-- Phantom: 1/2 lolos", rep)



# ---------------------------------------------------------------- Mode Lazy
LZ_NODE = {"name": "karin", "type": "vless", "server": "servervpn.com", "port": 443, "uuid": "u", "tls": True,
           "servername": "servervpn.com", "network": "ws",
           "ws-opts": {"path": "/ws", "headers": {"Host": "servervpn.com"}}}


def lazy_tuples(vs):
    """{(address, port, host, sni)} semua varian lazy ('' = tidak dipakai)."""
    out = set()
    for v in vs:
        if v["kind"] == "lazy":
            lz = v["fields"]["lazy"]
            out.add((lz["addr"], lz["port"], lz["host"], lz["sni"]))
    return out


def lazy_methods(vs):
    return {v["fields"]["lazy"]["method"] for v in vs if v["kind"] == "lazy"}


class LazyBuild(unittest.TestCase):
    def setUp(self):
        self._ra = b._resolve_all
        b._resolve_all = lambda host: ["13.35.1.58"]
        self.addCleanup(setattr, b, "_resolve_all", self._ra)

    def test_covers_the_user_examples(self):
        vs, skipped = b.build_lazy_variants([LZ_NODE], ["instagram.com"])
        self.assertEqual(skipped, [])
        S, B, IP = "servervpn.com", "instagram.com", "13.35.1.58"
        t = lazy_tuples(vs)
        for want in [(S, 443, S, B), (S, 80, S, ""),            # server asli + bug di SNI (port 80: SNI tidak dipakai)
                     (B, 443, S, S), (B, 80, S, ""),            # address = bug
                     (IP, 443, S, S), (IP, 80, S, ""),          # address = IP edge
                     (S, 443, IP, IP),                          # host & SNI = IP
                     (S, 443, S, IP)]:                          # SNI = IP
            self.assertIn(want, t)

    def test_cloudfront_example_with_ip_address(self):
        cf = "servervpn.cloudfront.net"
        n = dict(LZ_NODE, server="13.35.1.58", servername=cf, **{"ws-opts": {"path": "/ws", "headers": {"Host": cf}}})
        vs, skipped = b.build_lazy_variants([n], [])
        self.assertEqual(skipped, [])
        t = lazy_tuples(vs)
        self.assertIn((cf, 443, "13.35.1.58", "13.35.1.58"), t)  # address=cloudfront host=IP sni=IP
        self.assertIn((cf, 443, cf, "13.35.1.58"), t)            # sni=IP
        self.assertIn(("13.35.1.58", 80, cf, ""), t)             # IP edge, port 80
        self.assertNotIn(("13.35.1.58", 443, cf, cf), t)         # = config asli -> tidak diuji ulang

    def test_variant_shape(self):
        orig = json.dumps(LZ_NODE, sort_keys=True)
        vs, _ = b.build_lazy_variants([LZ_NODE], ["instagram.com", "x.example"])
        self.assertEqual(json.dumps(LZ_NODE, sort_keys=True), orig)          # node asli utuh
        self.assertEqual(vs[0]["kind"], "base")
        names = [v["node"]["name"] for v in vs]
        self.assertEqual(len(names), len(set(names)))                          # nama unik (wajib di Clash)
        v = next(v for v in vs if v["node"]["name"] == "karin [bug-sni:instagram.com:443]")
        self.assertEqual(v["node"]["servername"], "instagram.com")
        self.assertTrue(v["node"]["skip-cert-verify"])
        self.assertEqual(v["node"]["ws-opts"]["headers"]["Host"], "servervpn.com")
        self.assertEqual(b.describe_fields(v), "bug-sni servervpn.com:443 host=servervpn.com sni=instagram.com")
        for v in vs:
            self.assertFalse([k for k in v["node"] if str(k).startswith("_")])  # tanpa metadata internal

    def test_plain_port_drops_tls_fields_and_merges_sni_variants(self):
        n = dict(LZ_NODE, alpn=["h2"], **{"client-fingerprint": "chrome"})
        vs, _ = b.build_lazy_variants([n], ["a.example", "b.example"], ports=[80])
        plain = [v for v in vs if v["kind"] == "lazy"]
        self.assertTrue(plain)
        for v in plain:
            q = v["node"]
            self.assertFalse(q["tls"])
            for k in ("servername", "sni", "skip-cert-verify", "alpn", "client-fingerprint"):
                self.assertNotIn(k, q)
            self.assertTrue(v["fields"]["lazy"]["method"].startswith("http-"))
        self.assertEqual(len(lazy_tuples(vs)), len(plain))                      # tidak ada duplikat efektif
        self.assertEqual(sum(1 for v in plain if v["fields"]["lazy"]["method"] == "http-host-bug"), 2)   # per bug

    def test_bug_free_methods_only_when_no_bugs(self):
        vs, _ = b.build_lazy_variants([LZ_NODE], [])
        self.assertEqual(lazy_methods(vs), {"ip-edge", "host-ip", "sni-ip", "http-direct", "http-ip-edge", "http-host-ip"})

    def test_ip_methods_skipped_when_no_ip_known(self):
        b._resolve_all = lambda host: (_ for _ in ()).throw(OSError("NXDOMAIN"))
        vs, skipped = b.build_lazy_variants([LZ_NODE], ["x.example"])
        self.assertTrue(any("IP edge" in s[3] and "NXDOMAIN" in s[3] for s in skipped), skipped)
        self.assertFalse({m for m in lazy_methods(vs)} & {"ip-edge", "host-ip", "sni-ip", "ip-bug-sni", "wildcard-ip"})
        self.assertIn("bug-sni", lazy_methods(vs))
        vs, skipped = b.build_lazy_variants([LZ_NODE], ["x.example"], extra_ips=["104.18.43.252"])
        self.assertEqual(skipped, [])
        self.assertIn("ip-edge", lazy_methods(vs))
        self.assertIn(("104.18.43.252", 443, "servervpn.com", "servervpn.com"), lazy_tuples(vs))

    def test_resolved_ips_limited_and_deduped(self):
        b._resolve_all = lambda host: ["1.1.1.1", "2.2.2.2", "3.3.3.3", "1.1.1.1"]
        ips, note = b.lazy_edge_ips({"server": "9.9.9.9"}, "s.example", extra=["2.2.2.2", "4.4.4.4"])
        self.assertEqual(ips, ["9.9.9.9", "1.1.1.1", "2.2.2.2", "4.4.4.4"])    # IP node, 2 hasil resolve, tambahan
        self.assertEqual(note, "")

    def test_grpc_ignores_host_so_host_only_methods_collapse(self):
        g = {"name": "g", "type": "vless", "server": "servervpn.com", "port": 443, "uuid": "u", "tls": True,
             "servername": "servervpn.com", "network": "grpc", "grpc-opts": {"grpc-service-name": "x"}}
        vs, _ = b.build_lazy_variants([g], ["instagram.com"])
        m = lazy_methods(vs)
        self.assertNotIn("host-bug", m)            # = config asli
        self.assertNotIn("host-bug-sni", m)        # = bug-sni (Host tak dipakai grpc)
        self.assertIn("bug-sni", m)
        self.assertFalse(any(v["fields"]["lazy"]["tls"] is False for v in vs if v["kind"] == "lazy"))   # grpc tak bisa tanpa TLS
        self.assertTrue(all(v["fields"]["lazy"]["host"] == "" for v in vs if v["kind"] == "lazy"))

    def test_trojan_uses_sni_key_and_no_plain(self):
        t = {"name": "t", "type": "trojan", "server": "servervpn.com", "port": 443, "password": "p",
             "sni": "servervpn.com", "network": "ws", "ws-opts": {"path": "/", "headers": {"Host": "servervpn.com"}}}
        vs, _ = b.build_lazy_variants([t], ["instagram.com"])
        v = next(v for v in vs if v["fields"].get("lazy", {}).get("method") == "bug-sni")
        self.assertEqual(v["node"]["sni"], "instagram.com")
        self.assertNotIn("servername", v["node"])
        self.assertNotIn("tls", v["node"])
        self.assertFalse(any(not v["fields"]["lazy"]["tls"] for v in vs if v["kind"] == "lazy"))

    def test_unsupported_nodes_are_skipped_with_reason(self):
        ss = {"name": "ss", "type": "ss", "server": "a.example", "port": 1, "cipher": "aes-128-gcm", "password": "p"}
        rl = dict(LZ_NODE, name="rl", **{"reality-opts": {"public-key": "k"}})
        ip_only = {"name": "ip", "type": "vless", "server": "1.2.3.4", "port": 443, "uuid": "u", "tls": True, "network": "tcp"}
        vs, skipped = b.build_lazy_variants([ss, rl, ip_only], ["x.example"])
        self.assertEqual([s[1] for s in skipped], ["ss", "rl", "ip"])
        self.assertTrue(all(s[2] == "lazy" for s in skipped))
        self.assertIn("tipe ss", skipped[0][3]); self.assertIn("Reality", skipped[1][3]); self.assertIn("domain server", skipped[2][3])
        self.assertEqual([v["kind"] for v in vs], ["base"] * 3)

    def test_phantom_link_node_is_normalized_first(self):
        n = dict(LZ_NODE, servername="phantom:servervpn.com:old.example:rand")
        vs, _ = b.build_lazy_variants([n], ["instagram.com"])
        self.assertIn("bug-sni", lazy_methods(vs))
        self.assertNotIn("phantom:", json.dumps([v["node"] for v in vs]))

    def test_custom_ports_and_tls_classification(self):
        self.assertTrue(b.port_is_tls(443)); self.assertTrue(b.port_is_tls(8443)); self.assertTrue(b.port_is_tls(31337))
        self.assertFalse(b.port_is_tls(80)); self.assertFalse(b.port_is_tls(8080))
        vs, _ = b.build_lazy_variants([LZ_NODE], ["x.example"], ports=[8443, 8080])
        by_port = {v["fields"]["lazy"]["port"]: v["fields"]["lazy"]["tls"] for v in vs if v["kind"] == "lazy"}
        self.assertEqual(by_port, {8443: True, 8080: False})

    def test_candidate_parsers_for_bug_and_ip(self):
        self.assertEqual(b.parse_candidates("bug", "a.example 1.2.3.4 https://B.example/x"), (["a.example", "b.example"], ["1.2.3.4"]))
        self.assertEqual(b.parse_candidates("ip", "1.2.3.4, a.example 5.6.7.8"), (["1.2.3.4", "5.6.7.8"], ["a.example"]))

    def test_summary_and_report(self):
        vs, _ = b.build_lazy_variants([LZ_NODE], ["instagram.com", "x.example"])
        for v in vs:
            v["ok"] = v["kind"] == "base" or v["fields"]["lazy"]["method"] in ("bug-sni", "http-direct")
            v["ms"] = 100 if v["ok"] else None
            v["reason"] = "" if v["ok"] else "x"
        sm = {r["method"]: r for r in b.lazy_summary(vs)}
        self.assertEqual((sm["bug-sni"]["ok"], sm["bug-sni"]["tested"], sm["bug-sni"]["best"]), (2, 2, 100))
        self.assertEqual((sm["bug-addr"]["ok"], sm["bug-addr"]["tested"]), (0, 2))
        self.assertEqual(sm["bug-sni"]["pattern"], "addr=S host=S sni=B")
        self.assertEqual([r["method"] for r in b.lazy_summary(vs)][:2], ["bug-sni", "bug-addr"])   # urutan tabel metode
        rep = b.report_text(vs, ["tcp"])
        self.assertIn("-- Lazy:", rep)
        self.assertIn("=== Ringkasan metode Lazy ===", rep)
        self.assertIn("✓ bug-sni", rep); self.assertIn("✗ bug-addr", rep)
        self.assertEqual(b.passing(vs)[0]["kind"], "lazy")
        with tempfile.TemporaryDirectory() as d:
            files = dict(b.write_outputs(vs, ["tcp"], d, lambda ns: json.dumps(ns)))
            self.assertEqual(files["custom-lazy.yaml"], 3)           # bug-sni x2 + http-direct
            self.assertNotIn("_", "".join(k for n in json.load(open(os.path.join(d, "custom-lazy.yaml"))) for k in n if k.startswith("_")))

    def test_no_combo_for_lazy(self):
        vs, _ = b.build_lazy_variants([LZ_NODE], ["x.example"])
        for v in vs:
            v["ok"], v["ms"] = True, 5
        self.assertEqual(b.make_combos(vs), [])


@unittest.skipUnless(shutil.which("openssl"), "openssl tidak ada")
class LazyRun(unittest.TestCase):
    """Server lokal: hanya kombinasi yang benar-benar diterima server yang lolos."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        for name, val in (("_resolve", lambda host, port=0: "127.0.0.1"), ("_resolve_all", lambda host: [])):
            self.addCleanup(setattr, b, name, getattr(b, name))
            setattr(b, name, val)

    def test_tls_ws_finds_the_working_methods(self):
        crt, key = make_cert(self._tmp.name)
        srv = WsServer(good_host={"srv.example"}, tls_ctx=server_tls_ctx(crt, key, {"srv.example", "bug.example"}))
        self.addCleanup(srv.close)
        node = {"name": "N", "type": "vless", "server": "127.0.0.1", "port": srv.port, "uuid": "u", "tls": True,
                "servername": "srv.example", "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "srv.example"}}}
        vs, _ = b.build_lazy_variants([node], ["bug.example"], ports=[srv.port])
        b.test_variants(vs, ["tcp"], {"timeout": 3})
        self.assertTrue(vs[0]["ok"])                                          # config asli
        ok = {v["fields"]["lazy"]["method"] for v in vs if v["kind"] == "lazy" and v["ok"]}
        bad = {v["fields"]["lazy"]["method"] for v in vs if v["kind"] == "lazy" and not v["ok"]}
        self.assertEqual(ok, {"bug-sni", "bug-addr", "bug-addr-sni", "ip-bug-sni"})
        self.assertEqual(bad, {"host-ip", "sni-ip", "wildcard", "wildcard-ip", "host-bug", "host-bug-sni"})
        why = {v["fields"]["lazy"]["method"]: v["reason"] for v in vs if v["kind"] == "lazy" and not v["ok"]}
        self.assertIn("TLS gagal", why["sni-ip"])                              # tanpa SNI ditolak server
        self.assertIn("403", why["host-bug"])                                  # Host salah ditolak CDN

    def test_plain_ws_ports(self):
        srv = WsServer(good_host={"srv.example"})
        self.addCleanup(srv.close)
        self.addCleanup(setattr, b, "LAZY_PLAIN_PORTS", b.LAZY_PLAIN_PORTS)
        b.LAZY_PLAIN_PORTS = (srv.port,)
        node = {"name": "N", "type": "vless", "server": "127.0.0.1", "port": srv.port, "uuid": "u", "tls": False,
                "network": "ws", "ws-opts": {"path": "/ws", "headers": {"Host": "srv.example"}}}
        vs, _ = b.build_lazy_variants([node], ["bug.example"], ports=[srv.port])
        b.test_variants(vs, ["tcp"], {"timeout": 3})
        ok = {v["fields"]["lazy"]["method"] for v in vs if v["kind"] == "lazy" and v["ok"]}
        self.assertEqual(ok, {"http-direct", "http-bug-addr"})
