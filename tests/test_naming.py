"""Tes v0.10: nama file per operator, folder provider per operator, nama hasil sniffer, validasi input, daftar file sniffer."""
import builtins
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import hikari_converter as h   # noqa: E402
import yaml                    # noqa: E402

VLESS = ("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws&host=example.com"
         "&path=%2Fws&sni=example.com#Singapore")
OPERATORS = ("xl", "axis", "smartfren", "telkomsel", "byu", "indosat", "three")


def _w(path, text=""):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class Base(unittest.TestCase):
    def setUp(self):
        self._saved = (h.BASE_DIR, h.SETTINGS_PATH, h.SNIFFER_OUT_DIR)
        self._tmp = tempfile.TemporaryDirectory()
        h.BASE_DIR = os.path.join(self._tmp.name, "hasil")
        h.SETTINGS_PATH = os.path.join(self._tmp.name, "settings.json")
        h.SNIFFER_OUT_DIR = os.path.join(h.BASE_DIR, "sniffer")
        os.makedirs(h.BASE_DIR)

    def tearDown(self):
        h.BASE_DIR, h.SETTINGS_PATH, h.SNIFFER_OUT_DIR = self._saved
        self._tmp.cleanup()

    def out(self, plat):
        return os.path.join(h.BASE_DIR, h.PLATFORMS[plat]["out"])

    def run_flow(self, fn, inputs):
        it = iter(inputs)

        def fake_input(prompt=""):
            try:
                return next(it)
            except StopIteration:
                raise EOFError
        buf, old = io.StringIO(), builtins.input
        builtins.input = fake_input
        try:
            with contextlib.redirect_stdout(buf):
                fn()
        finally:
            builtins.input = old
        return buf.getvalue(), list(it)


class OperatorConfig(Base):
    def test_each_operator_gets_own_file_and_provider_dir(self):
        for plat in h.PLATFORMS:
            for op in OPERATORS:
                _, _, issues, error = h.setup_full_config([h.convert_line(VLESS)], "active.yaml", plat, operator=op)
                self.assertIsNone(error, (plat, op))
                self.assertEqual([m for l, m in issues if l == "ERR"], [], (plat, op, issues))
                out = self.out(plat)
                self.assertTrue(os.path.isfile(os.path.join(out, f"{op}.yaml")), (plat, op))
                pdir = h.PLATFORMS[plat]["proxy_dir"]
                self.assertTrue(os.path.isfile(os.path.join(out, pdir, op, "active.yaml")))
                self.assertTrue(os.path.isfile(os.path.join(out, pdir, op, "trial.yaml")))
            self.assertFalse(os.path.exists(os.path.join(self.out(plat), "config.yaml")))     # tidak ada nama bentrok
            self.assertEqual(len([f for f in os.listdir(self.out(plat)) if f.endswith(".yaml")]), len(OPERATORS))

    def test_provider_paths_follow_operator(self):
        for plat in h.PLATFORMS:
            h.setup_full_config([h.convert_line(VLESS)], "active.yaml", plat, operator="telkomsel")
            cfg = yaml.safe_load(h.read_text(os.path.join(self.out(plat), "telkomsel.yaml")))
            P = h.PLATFORMS[plat]
            paths = {k: v["path"] for k, v in cfg["proxy-providers"].items()}
            for pv in paths.values():
                if os.path.basename(pv) in ("active.yaml", "trial.yaml"):
                    self.assertIn(f"{P['proxy_dir']}/telkomsel/", pv)
                    self.assertTrue(pv.startswith(P["prefix"]))
            self.assertTrue(any(v.endswith("/telkomsel/active.yaml") for v in paths.values()))
            self.assertTrue(any(v.endswith("/telkomsel/trial.yaml") for v in paths.values()))

    def test_operators_do_not_overwrite_each_other(self):
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "nikki", operator="xl")
        n2 = h.convert_line(VLESS); n2["name"] = "Other"
        h.setup_full_config([n2], "active.yaml", "nikki", operator="byu")
        a = h.load_provider_nodes(os.path.join(self.out("nikki"), "proxy", "xl", "active.yaml"))
        b = h.load_provider_nodes(os.path.join(self.out("nikki"), "proxy", "byu", "active.yaml"))
        self.assertEqual([x["name"] for x in a], ["Singapore"])
        self.assertEqual([x["name"] for x in b], ["Other"])

    def test_without_operator_keeps_legacy_layout(self):
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "nikki")
        self.assertTrue(os.path.isfile(os.path.join(self.out("nikki"), "config.yaml")))
        self.assertTrue(os.path.isfile(os.path.join(self.out("nikki"), "proxy", "active.yaml")))

    def test_xl_injects_isp_dns_only_for_xl(self):
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "nikki", operator="xl")
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "nikki", operator="byu")
        self.assertIn("112.215.203.254", h.read_text(os.path.join(self.out("nikki"), "xl.yaml")))
        self.assertNotIn("112.215.203.254", h.read_text(os.path.join(self.out("nikki"), "byu.yaml")))

    def test_operator_name_sanitized(self):
        _, _, _, error = h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "box", operator="../Evil Name!")
        self.assertIsNone(error)
        self.assertTrue(os.path.isfile(os.path.join(self.out("box"), "evil-name.yaml")))
        self.assertEqual(h.safe_name("By.U"), "by.u")
        self.assertEqual(h.safe_name("!!!"), "")

    def test_regenerate_keeps_operator(self):
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "nikki", operator="xl")
        h.setup_full_config([h.convert_line(VLESS)], "trial.yaml", "nikki", operator="three")
        src = h.stored_node_sources()
        self.assertEqual({s[0] for s in src}, {"nikki/xl/active.yaml", "nikki/three/trial.yaml"})
        for p in (os.path.join(self.out("nikki"), "xl.yaml"), os.path.join(self.out("nikki"), "three.yaml")):
            _w(p, "# usang\n")
        res = h.regenerate_all(src)
        self.assertTrue(all(e is None for *_, e in res))
        for op in ("xl", "three"):
            self.assertNotIn("usang", h.read_text(os.path.join(self.out("nikki"), f"{op}.yaml")))
        self.assertFalse(os.path.exists(os.path.join(self.out("nikki"), "config.yaml")))
        self.assertEqual(h.source_operator("nikki/xl/active.yaml"), "xl")
        self.assertIsNone(h.source_operator("nikki/active.yaml"))

    def test_status_lists_all_configs(self):
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "box", operator="xl")
        h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "box", operator="three")
        self.assertEqual([os.path.basename(f) for f in h.generated_config_files("box")], ["three.yaml", "xl.yaml"])
        self.assertEqual(len(h._generated_configs()), 2)

    def test_settings_remember_operator(self):
        h.save_settings({"operator": "xl"})
        self.assertEqual(h.load_settings()["operator"], "xl")


class GenerateFlow(Base):
    def test_full_flow_asks_operator_and_names_file(self):
        # platform N, target 1, operator [5]=byu, rule 1, secret 1, pause
        out, left = self.run_flow(lambda: h._generate_and_report([h.convert_line(VLESS)]),
                                  ["n", "1", "5", "", "", ""])
        self.assertEqual(left, [])
        self.assertIn("byu.yaml", out)
        self.assertIn("proxy/byu/active.yaml", out)
        self.assertTrue(os.path.isfile(os.path.join(self.out("nikki"), "byu.yaml")))
        self.assertEqual(h.load_settings()["operator"], "byu")

    def test_invalid_answers_are_rejected_not_defaulted(self):
        # Kasus layar pengguna: 'x', 'e', 'g' dulu diproses diam-diam sebagai Enter.
        inputs = ["", "q", "n", "9", "1", "", "!!!", "xl", "x", "1", "e", "1", ""]
        out, left = self.run_flow(lambda: h._generate_and_report([h.convert_line(VLESS)]), inputs)
        self.assertEqual(left, [])
        self.assertGreaterEqual(out.count("tidak valid"), 5)
        self.assertTrue(os.path.isfile(os.path.join(self.out("nikki"), "xl.yaml")))

    def test_operator_enter_uses_last_operator(self):
        h.save_settings({"operator": "indosat"})
        self.run_flow(lambda: h._generate_and_report([h.convert_line(VLESS)]), ["b", "2", "", "", "", ""])
        self.assertTrue(os.path.isfile(os.path.join(self.out("box"), "indosat.yaml")))
        self.assertTrue(os.path.isfile(os.path.join(self.out("box"), "proxy", "indosat", "trial.yaml")))

    def test_custom_operator_name(self):
        self.run_flow(lambda: h._generate_and_report([h.convert_line(VLESS)]), ["b", "1", "8", "My Isp", "", "", ""])
        self.assertTrue(os.path.isfile(os.path.join(self.out("box"), "my-isp.yaml")))


class AskHelpers(Base):
    def feed(self, inputs, fn):
        out, left = self.run_flow(fn, inputs)
        return out, left

    def test_ask_choice(self):
        res = []
        out, left = self.run_flow(lambda: res.append(h.ask_choice("? ", ("1", "2"), default="1")), ["x", "3", "2"])
        self.assertEqual((res, left), (["2"], []))
        self.assertEqual(out.count("tidak valid"), 2)
        res.clear()
        self.run_flow(lambda: res.append(h.ask_choice("? ", ("1", "2"), default="1")), [""])
        self.assertEqual(res, ["1"])
        res.clear()
        self.run_flow(lambda: res.append(h.ask_choice("? ", ("1",), cancel=("0",))), ["", "0"])      # tanpa default: Enter ditolak
        self.assertEqual(res, ["0"])

    def test_ask_yn(self):
        res = []
        out, _ = self.run_flow(lambda: res.append(h.ask_yn("? ")), ["asal", "y"])
        self.assertEqual(res, [True]); self.assertIn("bukan jawaban y/n", out)
        res.clear()
        self.run_flow(lambda: res.append(h.ask_yn("? ", default=True)), [""])
        self.assertEqual(res, [True])
        res.clear()
        self.run_flow(lambda: res.append(h.ask_yn("? ")), ["N"])
        self.assertEqual(res, [False])


class SnifferNaming(Base):
    def test_sniffer_config_filename(self):
        self.assertEqual(h.sniffer_config_filename("three"), "sniffer-three.yaml")
        self.assertEqual(h.sniffer_config_filename("Three Xl"), "sniffer-three-xl.yaml")
        self.assertEqual(h.sniffer_config_filename(""), "config.yaml")
        self.assertEqual(h.sniffer_config_filename(None), "config.yaml")

    def test_write_sniffer_config_with_name(self):
        with tempfile.TemporaryDirectory() as d:
            p1, _, _ = h.write_sniffer_config("nikki", out_root=d, name="three")
            p2, _, _ = h.write_sniffer_config("nikki", out_root=d)
            p3, _, _ = h.write_sniffer_config("nikki", out_root=d, name="xl")
            self.assertEqual([os.path.basename(p) for p in (p1, p2, p3)], ["sniffer-three.yaml", "config.yaml", "sniffer-xl.yaml"])
            self.assertEqual(len(os.listdir(os.path.join(d, "nikki"))), 3)

    def test_generate_flow_asks_name(self):
        # platform N, nama three, ASN n, secret n, DNS operator (Enter), penangkap n, pause
        out, left = self.run_flow(h._sniffer_generate, ["n", "three", "n", "n", "", "n", ""])
        self.assertEqual(left, [])
        self.assertTrue(os.path.isfile(os.path.join(h.SNIFFER_OUT_DIR, "nikki", "sniffer-three.yaml")))
        self.assertIn("sniffer-three.yaml", out)

    def test_generate_flow_default_name_and_rejects_garbage(self):
        out, left = self.run_flow(h._sniffer_generate, ["z", "b", "###", "", "maybe", "n", "n", "", "n", ""])
        self.assertEqual(left, [])
        self.assertTrue(os.path.isfile(os.path.join(h.SNIFFER_OUT_DIR, "box", "config.yaml")))
        self.assertGreaterEqual(out.count("tidak valid"), 2)

    def test_result_path_naming(self):
        j = lambda *a, **k: os.path.basename(h.sniffer_result_path(*a, **k))
        self.assertEqual(j("instagram", "20261126_132543", "csv"), "instagram_20261126_132543.csv")
        self.assertEqual(j("", "20261126_132543", "json"), "koneksi_20261126_132543.json")
        self.assertEqual(j("Instagram", "20261126_132543", "md", "path"), "instagram_path_20261126_132543.md")
        self.assertEqual(j("", "20261126_132543", "jsonl", "path"), "path_20261126_132543.jsonl")


class SnifferFilesInBugtest(Base):
    def make(self, name, rows):
        os.makedirs(h.SNIFFER_OUT_DIR, exist_ok=True)
        p = os.path.join(h.SNIFFER_OUT_DIR, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(rows, f)
        return p

    ROWS = [{"sniff_host": "api.instagram.com", "dst_ip": "13.35.1.58", "dst_port": "443", "network": "TCP", "download": 900, "upload": 10},
            {"host": "cdn.example.net", "dst_ip": "1.2.3.4", "dst_port": "80", "network": "TCP", "download": 50, "upload": 1},
            {"sniff_host": "dead.example", "dst_ip": "9.9.9.9", "dst_port": "443", "network": "TCP", "download": 0, "upload": 5},
            {"dst_ip": "5.6.7.8", "dst_port": "8443", "network": "TCP", "download": 70, "upload": 1}]

    def test_lists_one_entry_per_recording_and_skips_md(self):
        self.make("instagram_20261126_132543.json", self.ROWS)
        _w(os.path.join(h.SNIFFER_OUT_DIR, "instagram_20261126_132543.csv"), "x")
        _w(os.path.join(h.SNIFFER_OUT_DIR, "instagram_20261126_132543.md"), "x")
        _w(os.path.join(h.SNIFFER_OUT_DIR, "lain_20261126_000000.csv"), "x")
        _w(os.path.join(h.SNIFFER_OUT_DIR, "path_20261126_132600.jsonl"), "")
        names = [n for _, n in h.sniffer_result_files()]
        self.assertEqual(sorted(names), ["instagram_20261126_132543.json", "lain_20261126_000000.csv", "path_20261126_132600.jsonl"])

    def test_candidates_only_from_connections_that_received_data(self):
        c = h.sniffer_file_candidates(self.make("a.json", self.ROWS))
        self.assertEqual(c["domains"], ["api.instagram.com", "cdn.example.net"])
        self.assertNotIn("dead.example", c["domains"])
        self.assertIn("13.35.1.58", c["ips"]); self.assertIn("5.6.7.8", c["ips"])
        self.assertEqual(sorted(c["ports"]), ["443", "80", "8443"])

    def test_tokens_per_field(self):
        c = h.sniffer_file_candidates(self.make("a.json", self.ROWS))
        self.assertEqual(h._sniffer_tokens_for("sni", c), ["api.instagram.com", "cdn.example.net"])
        self.assertIn("13.35.1.58", h._sniffer_tokens_for("server", c))
        self.assertNotIn("api.instagram.com", h._sniffer_tokens_for("ip", c))
        self.assertIn("443", h._sniffer_tokens_for("port", c))

    def test_path_log_candidates(self):
        os.makedirs(h.SNIFFER_OUT_DIR, exist_ok=True)
        p = os.path.join(h.SNIFFER_OUT_DIR, "path_1.jsonl")
        with open(p, "w", encoding="utf-8") as f:
            f.write(json.dumps({"host": "www.line.me", "path": "/en/home", "status": 200, "tls": False}) + "\n")
        c = h.sniffer_file_candidates(p)
        self.assertIn("www.line.me", c["domains"])
        self.assertIn("www.line.me/en", h._sniffer_tokens_for("bug", c))

    def test_picker_returns_tokens_and_validates(self):
        self.make("a.json", self.ROWS)
        res = []
        out, left = self.run_flow(lambda: res.append(h._pick_sniffer_tokens("bug", "bug")), ["x", "7", "1"])
        self.assertEqual(left, [])
        self.assertEqual(res, [["api.instagram.com", "cdn.example.net"]])
        self.assertIn("a.json", out)
        self.assertEqual(out.count("tidak valid") + out.count("di luar daftar"), 2)

    def test_picker_skippable_and_silent_without_files(self):
        res = []
        out, left = self.run_flow(lambda: res.append(h._pick_sniffer_tokens("bug", "bug")), [])
        self.assertEqual((res, out), ([[]], ""))              # tidak ada file: tidak ada prompt sama sekali
        self.make("a.json", self.ROWS)
        res.clear()
        self.run_flow(lambda: res.append(h._pick_sniffer_tokens("bug", "bug")), [""])
        self.assertEqual(res, [[]])

    def test_lazy_collect_uses_sniffer_file(self):
        import bugtest as bt
        self.make("a.json", self.ROWS)
        got = []
        # file sniffer #1 -> bug; (Enter akhiri paste bug) ; IP edge: tidak ada file-IP dipilih (Enter), paste kosong; port Enter
        out, left = self.run_flow(lambda: got.append(h._bug_collect_lazy(bt)), ["1", "", "", "", ""])
        self.assertEqual(left, [])
        self.assertEqual(got[0]["bugs"], ["api.instagram.com", "cdn.example.net"])


if __name__ == "__main__":
    unittest.main()
