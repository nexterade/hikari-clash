import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import sub2yaml as s   # noqa: E402
import hikari_converter as h   # noqa: E402
import yaml   # noqa: E402

UUID = "4e4f1f70-5e56-4a76-bb9d-db087f4690c4"
PBK = "G5fbtso9OktJfpHqg7demmUt8zfjnnEAL_QDRqvOzEU"


def b64(x):
    return base64.b64encode(x.encode()).decode()


class YamlStyle(unittest.TestCase):
    """Keluaran harus block style seperti active.yaml: tanpa {} / [] inline, nilai berisiko di-kutip."""

    def test_roundtrip_and_no_flow_style(self):
        p = {"name": "🇧🇾 BY | @x | 010655 | 26ms #2", "type": "vless", "server": "1.2.3.4", "port": 443,
             "uuid": UUID, "password": "12345", "udp": True, "alpn": ["h2", "http/1.1"],
             "ws-opts": {"path": "/a?ed=2048", "headers": {"Host": "a.b"}},
             "reality-opts": {"public-key": PBK, "short-id": ""},
             "http-opts": {"method": "GET", "path": ["/"], "headers": {"Host": ["a.b"]}},
             "a": "true", "b": "1e3", "c": "2024-01-01", "d": "a: b", "e": 'say "x"', "f": "line x",
             "g": "null", "h": "~", "i": " spasi ", "j": "#komentar", "k": "x,y", "l": "[z]"}
        text = s.to_yaml({"proxies": [p, dict(p, name="B")]}, "# header")
        self.assertNotIn("{", text.replace('"{', ""))        # tidak ada flow mapping
        self.assertEqual(yaml.safe_load(text)["proxies"][0], p)
        self.assertEqual(yaml.safe_load(text)["proxies"][1]["name"], "B")
        self.assertIn("    udp: true\n", text)                 # indentasi sama dengan active.yaml

    def test_empty_containers_dropped(self):
        t = s.to_yaml({"proxies": [{"name": "a", "ws-opts": {}, "alpn": []}]})
        self.assertEqual(yaml.safe_load(t)["proxies"], [{"name": "a"}])


class Parsing(unittest.TestCase):
    def test_extract_links_ignores_metadata(self):
        raw = "#profile-title: x\n#support-url: https://github.com/a/b\nss://YWVzLTI1Ni1nY206cHc=@1.1.1.1:1#a\n"
        for text in (raw, b64(raw)):
            self.assertEqual(len(s.extract_links(text)), 1)

    def test_validate_rejects_bad_uuid_and_reality(self):
        good = {"name": "a", "type": "vless", "server": "1.2.3.4", "port": 443, "uuid": UUID}
        self.assertIsNone(s.validate_proxy(good))
        self.assertTrue(s.validate_proxy(dict(good, uuid="Fluffy_VPN-Oth8rOq3")))
        self.assertTrue(s.validate_proxy(dict(good, **{"reality-opts": {"public-key": "xx", "short-id": ""}})))
        self.assertTrue(s.validate_proxy(dict(good, **{"reality-opts": {"public-key": PBK, "short-id": "zz"}})))
        self.assertTrue(s.validate_proxy(dict(good, network="http", **{"reality-opts": {"public-key": PBK, "short-id": ""}})))
        self.assertIsNone(s.validate_proxy(dict(good, network="grpc", **{"reality-opts": {"public-key": PBK, "short-id": "ab"}})))
        self.assertTrue(s.validate_proxy(dict(good, servername="sp</div>")))
        self.assertTrue(s.validate_proxy(dict(good, flow="xtls-rprx-vision", network="ws")))

    def test_parse_all_filters_invalid(self):
        links = [f"vless://{UUID}@1.1.1.1:443?security=tls&sni=a.com#ok",
                 "vless://Fluffy_VPN-Oth8rOq3@1.1.1.1:443?security=tls#bad-uuid",
                 f"vless://{UUID}@1.1.1.1:443?security=tls&sni=a.com#dup",
                 "hysteria2://x@1.1.1.1:443#unsupported"]
        nodes, st, skipped = s.parse_all(links)
        self.assertEqual([n["name"] for n in nodes], ["ok"])
        self.assertEqual((st["invalid"], st["duplicate"], st["unsupported"]), (1, 1, 1))
        self.assertTrue(any("UUID" in r for _, _, r in skipped))

    def test_name_cleanup(self):
        self.assertEqual(s.strip_flags("🇧🇾 BY  🇧🇾 | x", "f"), "BY | x")
        self.assertNotIn("‎", s.clean_name("a‎b\U000E0067", "f"))


class OutputIntegratesWithHikari(unittest.TestCase):
    def test_free_yaml_is_importable(self):
        nodes, _, _ = s.parse_all([f"vless://{UUID}@1.1.1.1:443?security=tls&sni=a.com&type=ws&path=/p&host=a.com#A",
                                   "ss://" + b64("aes-256-gcm:pw") + "@2.2.2.2:8388#B"])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "hasil", "proxy", "free.yaml")
            os.makedirs(os.path.dirname(out))
            s.write_yaml_file(out, nodes, "# test\n")
            loaded, err = h.load_sub2yaml_output(out)
            self.assertIsNone(err)
            self.assertEqual([n["name"] for n in loaded], ["A", "B"])
            res = h.import_free_nodes(out, ["box"], base_dir=os.path.join(d, "hasil"))
            self.assertEqual(res[0][1], 2)


class Paths(unittest.TestCase):
    def test_defaults_relative_to_script(self):
        self.assertEqual(s.DEFAULT_OUTDIR, os.path.join(s.SCRIPT_DIR, "hasil", "proxy"))
        self.assertEqual(s.resolve_dir("hasil/x"), os.path.join(s.SCRIPT_DIR, "hasil", "x"))
        self.assertEqual(s.resolve_dir("/abs/x"), "/abs/x")
        self.assertEqual(h.SUB2YAML_OUT_DIR, s.DEFAULT_OUTDIR)   # hikari & sub2yaml sepakat soal folder keluaran

    def test_update_source_keeps_old_file_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            old = s.SRC_DIR
            s.SRC_DIR = d
            try:
                p = os.path.join(d, "a.txt")
                with open(p, "w") as f:
                    f.write(b64("ss://" + b64("aes-256-gcm:pw") + "@1.1.1.1:1#x"))
                with open(p) as f:
                    before = f.read()
                self.assertFalse(s.update_source("a.txt", "http://127.0.0.1:9/none"))   # port tertutup
                with open(p) as f:
                    self.assertEqual(f.read(), before)
            finally:
                s.SRC_DIR = old


FAKE_CORE = """#!{py}
import json, re, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import yaml
if "-v" in sys.argv:
    print("Mihomo Meta v1.99.0 fake"); sys.exit(0)
cfg = yaml.safe_load(open(sys.argv[sys.argv.index("-f") + 1]))
px = {{p["name"]: p for p in cfg["proxies"]}}
if "-t" in sys.argv:
    for i, p in enumerate(cfg["proxies"]):
        if p.get("password") == "invalid":
            print(f"proxy {{i}}: unsupported field"); sys.exit(1)
    sys.exit(0)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/version": return self._send(200, {{"version": "fake"}})
        m = re.fullmatch(r"/proxies/(.+)/delay", u.path)
        pw = px[m.group(1)].get("password") if m else None
        url = parse_qs(u.query).get("url", [""])[0]
        if pw == "ok": return self._send(200, {{"delay": 40}})
        if pw == "slow": return self._send(200, {{"delay": 8000}})
        if pw == "flaky" and "cloudflare" not in url: return self._send(200, {{"delay": 30}})
        return self._send(503, {{"message": "Timeout"}})
HTTPServer(("127.0.0.1", int(cfg["external-controller"].split(":")[1])), H).serve_forever()
"""


class CoreLogic(unittest.TestCase):
    def test_pick_asset_prefers_android_and_compatible(self):
        names = ["mihomo-linux-amd64-v1.19.2.gz", "mihomo-linux-amd64-compatible-v1.19.2.gz",
                 "mihomo-linux-amd64-compatible-go120-v1.19.2.gz", "mihomo-android-arm64-v8-v1.19.2.gz",
                 "mihomo-linux-arm64-v1.19.2.gz"]
        self.assertEqual(s.pick_asset(names, ["mihomo-android-arm64-v8-{v}.gz", "mihomo-linux-arm64-{v}.gz"]),
                         "mihomo-android-arm64-v8-v1.19.2.gz")
        self.assertEqual(s.pick_asset(names, ["mihomo-linux-amd64-compatible-{v}.gz", "mihomo-linux-amd64-{v}.gz"]),
                         "mihomo-linux-amd64-compatible-v1.19.2.gz")
        self.assertIsNone(s.pick_asset(names, ["mihomo-freebsd-amd64-{v}.gz"]))

    def test_tcp_interception_detected(self):
        self.assertTrue(s.tcp_intercepted([1, 2, 1, 3] * 10))          # semua 1-3ms = dicegat Box/VPN
        self.assertFalse(s.tcp_intercepted([40, 120, 250, 90] * 10))   # ping nyata
        self.assertFalse(s.tcp_intercepted([1, 2, 1]))                 # sampel terlalu kecil


class EndToEnd(unittest.TestCase):
    """Jalankan sub2yaml.py sungguhan dengan core palsu: hanya node yang lolos URL-test yang boleh masuk file."""

    def setUp(self):
        import socket
        import stat
        import subprocess
        self.subprocess, self.tmp = subprocess, tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.core = os.path.join(d, "fakecore")
        with open(self.core, "w") as f:
            f.write(FAKE_CORE.format(py=sys.executable))
        os.chmod(self.core, os.stat(self.core).st_mode | stat.S_IEXEC)
        self.socks, links = [], []
        for n, pw in enumerate(["ok", "ok", "ok", "bad", "flaky", "slow", "invalid"]):
            sk = socket.socket(); sk.bind(("127.0.0.1", 0)); sk.listen(5); self.socks.append(sk)
            links.append("ss://" + b64(f"aes-128-gcm:{pw}") + f"@127.0.0.1:{sk.getsockname()[1]}#node-{pw}-{n}")
        self.src = os.path.join(d, "sub.txt")
        with open(self.src, "w") as f:
            f.write("\n".join(links))

    def tearDown(self):
        for sk in self.socks:
            sk.close()
        self.tmp.cleanup()

    def run_cli(self, *extra, core=True):
        out = os.path.join(self.tmp.name, "out")
        cmd = [sys.executable, os.path.join(os.path.dirname(s.__file__), "sub2yaml.py"), self.src, "--no-menu",
               "-o", out, "--timeout", "1"] + (["--mihomo", self.core] if core else ["--no-download"]) + list(extra)
        env = dict(os.environ, PATH="/nonexistent", NO_COLOR="1")
        env.pop("HIKARI_MIHOMO", None)
        r = self.subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        return r, out

    def names(self, out):
        with open(os.path.join(out, "free.yaml")) as f:
            return [p["name"] for p in yaml.safe_load(f)["proxies"]]

    def test_only_working_nodes_and_custom_count(self):
        r, out = self.run_cli("--top", "0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        names = self.names(out)
        self.assertEqual(len(names), 3)
        self.assertTrue(all("node-ok" in n and n.endswith("ms") for n in names), names)
        report = open(os.path.join(out, "report.txt"), encoding="utf-8").read()
        self.assertIn("URL-test mihomo", report)
        for word in ("tidak stabil", "Terlalu lambat", "Ditolak mihomo"):
            self.assertIn(word, report)
        r, out = self.run_cli("--top", "2")          # jumlah bebas: 2 node
        self.assertEqual(len(self.names(out)), 2)

    def test_tcp_only_is_never_silent_fallback(self):
        r, out = self.run_cli(core=False)            # tanpa core & tanpa unduh -> berhenti, bukan jatuh ke TCP
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "free.yaml")))
        r, out = self.run_cli("--tcp-only", core=False)
        self.assertEqual(r.returncode, 0)
        self.assertIn("BUKAN jaminan", open(os.path.join(out, "report.txt"), encoding="utf-8").read())


if __name__ == "__main__":
    unittest.main()
