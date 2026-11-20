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


if __name__ == "__main__":
    unittest.main()
