"""Tes penangkap path HTTP (httpcatch.py): parser, SNI, proxy end-to-end lokal (tanpa internet)."""
import os
import socket
import ssl
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpcatch as hc  # noqa: E402


class Origin:
    """Server HTTP polos kecil: '/' -> 302 ke /id, '/id/vless' -> 200, HEAD -> 200 tanpa badan, lainnya 404."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.seen = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.settimeout(3)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        return
                    buf += d
                head, buf = buf.split(b"\r\n\r\n", 1)
                first = head.split(b"\r\n")[0].decode()
                self.seen.append(first)
                method, path = first.split(" ")[:2]
                if path == "/":
                    c.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://xlsmart.co.id/id\r\nServer: cloudflare\r\n"
                              b"CF-RAY: abc\r\nContent-Length: 0\r\n\r\n")
                elif path.startswith("/id/vless"):
                    body = b"hello"
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body)
                              + (b"" if method == "HEAD" else body))
                else:
                    c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.sock.close()


def read_response(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(4096)
        if not d:
            break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    n = 0
    for ln in head.split(b"\r\n"):
        if ln.lower().startswith(b"content-length:"):
            n = int(ln.split(b":")[1])
    while len(rest) < n:
        d = sock.recv(4096)
        if not d:
            break
        rest += d
    return head.decode(), rest


def wait_for(cond, t=3.0):
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


class Parsers(unittest.TestCase):
    def test_split_target(self):
        self.assertEqual(hc.split_target("http://a.com:81/x?y=1"), ("a.com", 81, "/x?y=1"))
        self.assertEqual(hc.split_target("http://a.com"), ("a.com", 80, "/"))
        self.assertEqual(hc.split_target("/p?q", "h", 8080), ("h", 8080, "/p?q"))

    def test_parse_head(self):
        first, h = hc.parse_head(b"GET /a HTTP/1.1\r\nHost: x.com\r\nUser-Agent: T\r\n")
        self.assertEqual(first, "GET /a HTTP/1.1")
        self.assertEqual(h["host"], "x.com")
        self.assertIsNone(hc.parse_head(b""))

    def test_parse_sni_from_real_client_hello(self):
        ctx = ssl.create_default_context()
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname="www.Line.me")
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = out.read()
        sni, alpn = hc.parse_sni(hello)
        self.assertEqual(sni, "www.line.me")
        self.assertIsNone(hc.parse_sni(hello[:20]))          # belum lengkap
        self.assertIsNone(hc.parse_sni(b"GET / HTTP/1.1\r\n\r\n"))

    def test_stream_skips_bodies_and_tracks_pipeline(self):
        got = []

        def on_head(first, h):
            got.append(first)
            return int(h.get("content-length", "0"))

        s = hc.HttpStream(on_head)
        data = (b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: x\r\n\r\n")
        for i in range(0, len(data), 7):                       # potongan kecil
            s.feed(data[i:i + 7])
        self.assertEqual(got, ["POST /a HTTP/1.1", "GET /b HTTP/1.1"])

    def test_cdn_hint(self):
        self.assertEqual(hc.cdn_hint({"cf-ray": "1"}), "Cloudflare")
        self.assertEqual(hc.cdn_hint({"x-amz-cf-id": "1"}), "CloudFront")
        self.assertEqual(hc.cdn_hint({"server": "nginx"}), "")


class ProxyEndToEnd(unittest.TestCase):
    def setUp(self):
        self.origin = Origin()
        self.srv = hc.CatchServer("127.0.0.1", 0).start()
        self.addCleanup(self.origin.close)
        self.addCleanup(self.srv.stop)

    def _connect(self):
        s = socket.create_connection(("127.0.0.1", self.srv.port), timeout=3)
        s.sendall(f"CONNECT 127.0.0.1:{self.origin.port} HTTP/1.1\r\nHost: 127.0.0.1:{self.origin.port}\r\n\r\n".encode())
        head, _ = read_response(s)
        self.assertIn("200", head.split("\r\n")[0])
        return s

    def test_connect_tunnel_captures_path_status_location_and_relays_bytes(self):
        s = self._connect()
        with s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: xlsmart.co.id\r\nUser-Agent: UA1\r\n\r\n")
            head, _ = read_response(s)
            self.assertIn("302", head)
            self.assertIn("Location: https://xlsmart.co.id/id", head)        # byte lewat apa adanya
            s.sendall(b"GET /id/vless?x=1 HTTP/1.1\r\nHost: xlsmart.co.id\r\n\r\n")     # keep-alive, permintaan kedua
            head, body = read_response(s)
            self.assertIn("200", head)
            self.assertEqual(body, b"hello")
        self.assertTrue(wait_for(lambda: len([e for e in self.srv.log.snapshot() if e.get("status")]) >= 2))
        ev = self.srv.log.snapshot()
        self.assertEqual([(e["method"], e["host"], e["path"], e["status"]) for e in ev],
                         [("GET", "xlsmart.co.id", "/", 302), ("GET", "xlsmart.co.id", "/id/vless?x=1", 200)])
        self.assertEqual(ev[0]["location"], "https://xlsmart.co.id/id")
        self.assertEqual(ev[0]["cdn"], "Cloudflare")
        self.assertEqual(ev[0]["ua"], "UA1")
        self.assertEqual(self.origin.seen, ["GET / HTTP/1.1", "GET /id/vless?x=1 HTTP/1.1"])

    def test_absolute_uri_forward_proxy_rewrites_to_origin_form(self):
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=3) as s:
            s.sendall(f"GET http://127.0.0.1:{self.origin.port}/id/vless HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      f"Proxy-Connection: keep-alive\r\n\r\n".encode())
            head, body = read_response(s)
        self.assertIn("200", head)
        self.assertEqual(body, b"hello")
        self.assertEqual(self.origin.seen, ["GET /id/vless HTTP/1.1"])
        self.assertTrue(wait_for(lambda: any(e.get("status") == 200 for e in self.srv.log.snapshot())))
        self.assertEqual(self.srv.log.snapshot()[0]["path"], "/id/vless")

    def test_head_request_has_no_body_and_next_request_still_parsed(self):
        with self._connect() as s:
            s.sendall(b"HEAD /id/vless HTTP/1.1\r\nHost: h\r\n\r\n")
            s.settimeout(3)
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += s.recv(4096)
            s.sendall(b"GET /nope HTTP/1.1\r\nHost: h\r\n\r\n")
            head, _ = read_response(s)
            self.assertIn("404", head)
        self.assertTrue(wait_for(lambda: len([e for e in self.srv.log.snapshot() if e.get("status")]) >= 2))
        self.assertEqual([e["status"] for e in self.srv.log.snapshot()], [200, 404])

    def test_unanswered_request_is_logged_on_close(self):
        s = self._connect()
        s.sendall(b"GET /id/vless HTTP/1.1\r\nHost: h\r\n\r\n")
        read_response(s)
        s.sendall(b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
        s.close()
        self.assertTrue(wait_for(lambda: len(self.srv.log.snapshot()) >= 2))

    def test_tls_connect_records_sni_only(self):
        ctx = ssl.create_default_context()
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname="instagram.com")
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = out.read()
        with self._connect() as s:
            s.sendall(hello)
            time.sleep(0.2)
        self.assertTrue(wait_for(lambda: any(e.get("tls") for e in self.srv.log.snapshot())))
        e = [e for e in self.srv.log.snapshot() if e["tls"]][0]
        self.assertEqual((e["sni"], e["path"]), ("instagram.com", ""))

    def test_self_connect_is_refused_as_loop(self):
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=3) as s:
            s.sendall(f"CONNECT 127.0.0.1:{self.srv.port} HTTP/1.1\r\n\r\n".encode())
            head, _ = read_response(s)
        self.assertIn("508", head)

    def test_non_proxy_request_gets_400_and_unreachable_target_502(self):
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=3) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            head, _ = read_response(s)
        self.assertIn("400", head)
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=3) as s:
            s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
            head, _ = read_response(s)
        self.assertIn("502", head)

    def test_jsonl_log_and_report(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.jsonl")
            srv = hc.CatchServer("127.0.0.1", 0, path).start()
            with socket.create_connection(("127.0.0.1", srv.port), timeout=3) as s:
                s.sendall(f"CONNECT 127.0.0.1:{self.origin.port} HTTP/1.1\r\n\r\n".encode())
                read_response(s)
                s.sendall(b"GET / HTTP/1.1\r\nHost: xlsmart.co.id\r\n\r\n")
                read_response(s)
            self.assertTrue(wait_for(lambda: srv.log.snapshot() and srv.log.snapshot()[0].get("status")))
            srv.stop()
            events = hc.load_jsonl(path)
            self.assertEqual(events[0]["status"], 302)
            md = hc.render_markdown(events)
            self.assertIn("xlsmart.co.id/id", md)                  # kandidat dari header Location
            self.assertIn("Kandidat bug berpath", md)


class Aggregation(unittest.TestCase):
    EV = [
        {"tls": False, "host": "www.line.me", "port": 80, "method": "GET", "path": "/en/home?x=1", "status": 200, "location": "", "cdn": "", "ctype": "text/html; c"},
        {"tls": False, "host": "www.line.me", "port": 80, "method": "GET", "path": "/en/home", "status": 200, "location": "", "cdn": "", "ctype": ""},
        {"tls": False, "host": "xlsmart.co.id", "port": 80, "method": "GET", "path": "/", "status": 302, "location": "https://xlsmart.co.id/id/", "cdn": "Cloudflare", "ctype": ""},
        {"tls": False, "host": "bad.com", "port": 80, "method": "GET", "path": "/zzz", "status": 404, "location": "", "cdn": "", "ctype": ""},
        {"tls": True, "host": "t.com", "port": 443, "sni": "t.com", "method": "TLS", "path": ""},
    ]

    def test_aggregate_merges_query_variants(self):
        agg = hc.aggregate_paths(self.EV)
        top = agg[0]
        self.assertEqual((top["host"], top["path"], top["count"], top["queries"]), ("www.line.me", "/en/home", 2, 1))

    def test_bug_candidates_use_first_segment_and_redirects_skip_errors(self):
        self.assertEqual(hc.bug_candidates(self.EV), ["www.line.me/en", "xlsmart.co.id/id"])
        self.assertEqual(hc.first_segment("/a/b?c"), "/a")
        self.assertEqual(hc.first_segment("/"), "")

    def test_candidates_feed_bugtest_parser(self):
        import bugtest as bt
        good, bad = bt.parse_candidates("bug", "\n".join(hc.bug_candidates(self.EV)))
        self.assertEqual((good, bad), (["www.line.me/en", "xlsmart.co.id/id"], []))


class SnifferIntegration(unittest.TestCase):
    def test_add_catcher_places_rules_before_cdn_and_validates(self):
        import hikari_converter as h
        cfg, notes = h.build_sniffer_config("box", catcher=("127.0.0.1", 7893))
        rules = cfg["rules"]
        first_cdn = next(i for i, r in enumerate(rules) if "CloudFront" in r or "Cloudflare" in r)
        idx = [i for i, r in enumerate(rules) if h.CATCHER_GROUP in r]
        self.assertEqual(len(idx), len(h.CATCHER_HTTP_PORTS))
        self.assertLess(max(idx), first_cdn)                                   # sebelum rule CDN
        self.assertGreater(min(idx), rules.index("DST-PORT,853,🧭 DNS"))       # setelah LAN/DNS
        self.assertEqual(cfg["proxies"], [{"name": h.CATCHER_PROXY, "type": "http", "server": "127.0.0.1", "port": 7893}])
        self.assertEqual(h.validate_config(cfg, "box"), [])
        self.assertTrue(any("Penangkap path" in n for n in notes))

    def test_catcher_off_by_default_and_idempotent(self):
        import hikari_converter as h
        cfg, _ = h.build_sniffer_config("box")
        self.assertNotIn("proxies", cfg)
        self.assertFalse([r for r in cfg["rules"] if h.CATCHER_GROUP in r])
        h.add_catcher(cfg, enabled=False)
        h.add_catcher(cfg, "10.0.0.2", 9000, enabled=False)                    # dua kali: tidak dobel
        self.assertEqual(len(cfg["proxies"]), 1)
        self.assertEqual(cfg["proxies"][0]["server"], "10.0.0.2")
        grp = next(g for g in cfg["proxy-groups"] if g["name"] == h.CATCHER_GROUP)
        self.assertEqual(grp["proxies"][0], "DIRECT")
        self.assertEqual(len([r for r in cfg["rules"] if h.CATCHER_GROUP in r]), len(h.CATCHER_HTTP_PORTS))

    def test_written_config_is_valid_yaml_with_catcher(self):
        import tempfile
        import yaml
        import hikari_converter as h
        with tempfile.TemporaryDirectory() as d:
            path, issues, _ = h.write_sniffer_config("nikki", out_root=d, catcher=("127.0.0.1", 7893))
            self.assertEqual([i for i in issues if i[0] == "ERR"], [])
            with open(path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
            self.assertIn(h.CATCHER_GROUP, [g["name"] for g in cfg["proxy-groups"]])

    def test_markdown_report_has_path_section_even_without_data_rows(self):
        import sniffer as sn
        events = Aggregation.EV
        md = sn.render_markdown([], "t", path_events=events)
        self.assertIn("# Path HTTP tertangkap", md)
        self.assertIn("www.line.me/en", md)
        self.assertNotIn("# Path HTTP tertangkap", sn.render_markdown([], "t"))

    def test_menu_flow_standalone_catcher(self):
        import tempfile
        import hikari_converter as h
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        origin = Origin()
        self.addCleanup(origin.close)
        answers = iter(["", str(port)])
        calls = {"n": 0}
        real_sleep = time.sleep

        def fake_sleep(t):
            calls["n"] += 1
            if calls["n"] == 1:                       # "pengguna" membuka situs lewat penangkap, lalu Ctrl+C
                with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                    s.sendall(f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\n\r\n".encode())
                    read_response(s)
                    s.sendall(b"GET / HTTP/1.1\r\nHost: xlsmart.co.id\r\n\r\n")
                    read_response(s)
                wait_for(lambda: True, 0.3)
                real_sleep(0.3)
                return
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as d:
            old = (h.SNIFFER_OUT_DIR, h.ask, h.pause, h.clear_screen, h.banner, time.sleep)
            h.SNIFFER_OUT_DIR = d
            h.ask = lambda *a, **k: next(answers)
            h.pause = h.clear_screen = lambda *a, **k: None
            h.banner = lambda *a, **k: None
            time.sleep = fake_sleep
            try:
                h._sniffer_catcher()
            finally:
                h.SNIFFER_OUT_DIR, h.ask, h.pause, h.clear_screen, h.banner, time.sleep = old
            names = sorted(os.listdir(d))
            self.assertTrue(any(n.endswith(".md") for n in names), names)
            self.assertTrue(any(n.endswith(".jsonl") for n in names), names)
            with open(os.path.join(d, [n for n in names if n.endswith(".md")][0]), encoding="utf-8") as f:
                md = f.read()
            self.assertIn("xlsmart.co.id/id", md)


if __name__ == "__main__":
    unittest.main()
