"""Tes Box Utilities (boxutil.py + menu): 'perangkat' tiruan = folder sementara, perintah root dijalankan lewat sh biasa."""
import builtins
import contextlib
import io
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import boxutil as bx            # noqa: E402
import hikari_converter as h    # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "box_settings.ini")
VLESS = ("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=ws&host=example.com"
         "&path=%2Fws&sni=example.com#Singapore")


def _r(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _w(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class Device(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        t = self._tmp.name
        self.box = os.path.join(t, "dev", "adb", "box")
        text = _r(FIXTURE).replace("/data/adb/box", self.box)
        _w(os.path.join(self.box, "settings.ini"), text)
        os.makedirs(os.path.join(self.box, "run"), exist_ok=True)
        scripts = os.path.join(self.box, "scripts")
        pid = os.path.join(self.box, "run", "box.pid")
        calls = os.path.join(self.box, "run", "calls.log")
        _w(os.path.join(scripts, "box.service"),
           f'echo "service $1" >> {calls}\ncase "$1" in start) echo {os.getpid()} > {pid};; stop) rm -f {pid};; '
           f'status) echo "status-ok";; esac\n')
        _w(os.path.join(scripts, "box.iptables"), f'echo "iptables $1" >> {calls}\n')
        _w(os.path.join(scripts, "box.tool"), f'echo "tool $1" >> {calls}\n')
        for s in ("box.service", "box.iptables", "box.tool"):
            os.chmod(os.path.join(scripts, s), 0o755)
        _w(os.path.join(self.box, "clash", "config.yaml"), "mixed-port: 7890\nexternal-controller: 0.0.0.0:9090\nsecret: s3\n")
        self.calls = calls
        # hasil generate tiruan
        self._saved = (h.BASE_DIR, h.SETTINGS_PATH, h.SNIFFER_OUT_DIR, bx.RUNNER, bx.BOX_DIR)
        h.BASE_DIR = os.path.join(t, "hasil")
        h.SETTINGS_PATH = os.path.join(t, "settings.json")
        h.SNIFFER_OUT_DIR = os.path.join(h.BASE_DIR, "sniffer")
        os.makedirs(h.BASE_DIR)
        bx.RUNNER = bx.run_local
        bx.BOX_DIR = self.box
        self.src = os.path.join(h.BASE_DIR, h.PLATFORMS["box"]["out"])

    def tearDown(self):
        h.BASE_DIR, h.SETTINGS_PATH, h.SNIFFER_OUT_DIR, bx.RUNNER, bx.BOX_DIR = self._saved
        self._tmp.cleanup()

    def generate(self, operator="xl"):
        _, _, issues, error = h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "box", operator=operator)
        self.assertIsNone(error)

    def dev(self, *parts):
        return os.path.join(self.box, *parts)

    def settings_text(self):
        return _r(self.dev("settings.ini"))

    def calls_text(self):
        return _r(self.calls) if os.path.exists(self.calls) else ""

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


class Settings(unittest.TestCase):
    def test_parse_real_settings(self):
        s = bx.parse_settings(_r(FIXTURE))
        self.assertEqual(s["name_clash_config"], "config.yaml")
        self.assertEqual(s["clash_config"], "/data/adb/box/clash/config.yaml")
        self.assertEqual(s["clash_provide_path"], "/data/adb/box/clash/proxy")
        self.assertEqual((s["bin_name"], s["xclash_option"], s["network_mode"]), ("clash", "mihomo", "tproxy"))
        self.assertEqual((s["tproxy_port"], s["redir_port"]), ("9898", "9797"))
        self.assertEqual(s["box_pid"], "/data/adb/box/run/box.pid")
        self.assertNotIn("bin_list", s)               # array dilewati
        self.assertNotIn("current_time", s)           # $(...) dilewati

    def test_valid_config_name(self):
        for ok in ("xl.yaml", "by.u.yml", "sniffer-three.yaml"):
            self.assertTrue(bx.valid_config_name(ok), ok)
        for bad in ("", "x", "a b.yaml", 'x";rm -rf /.yaml', "../x.yaml", "x.yaml;ls", ".yaml", "a/b.yaml"):
            self.assertFalse(bx.valid_config_name(bad), bad)

    def test_root_path_mapping(self):
        self.assertEqual(bx.root_path("/storage/emulated/0/Project/h/hasil"), "/data/media/0/Project/h/hasil")
        self.assertEqual(bx.root_path("/sdcard/x"), "/data/media/0/x")
        self.assertEqual(bx.root_path("/data/data/com.termux/files/home/h"), "/data/data/com.termux/files/home/h")

    def test_dashboard_url_and_ports(self):
        self.assertEqual(bx.dashboard_url({"external-controller": "0.0.0.0:9090"}), "http://127.0.0.1:9090/ui/")
        self.assertEqual(bx.dashboard_url({"external-controller": "127.0.0.1:9191"}), "http://127.0.0.1:9191/ui/")
        self.assertEqual(bx.dashboard_url({}), "http://127.0.0.1:9090/ui/")
        w = bx.port_warnings({"tproxy-port": 1111, "redir-port": 9797}, {"tproxy_port": "9898", "redir_port": "9797"})
        self.assertEqual(len(w), 1)


class Control(Device):
    def test_info(self):
        info = bx.box_info()
        self.assertEqual(info["clash_dir"], self.dev("clash"))
        self.assertEqual(info["config_name"], "config.yaml")
        self.assertEqual(info["provide_path"], self.dev("clash", "proxy"))
        self.assertTrue(info["has_name_key"])

    def test_info_error_when_unreadable(self):
        os.remove(self.dev("settings.ini"))
        self.assertIn("settings.ini tidak terbaca", bx.box_info()["error"])

    def test_start_stop_status(self):
        info = bx.box_info()
        self.assertEqual(bx.is_running(info), (False, ""))
        ok, _ = bx.run_steps(bx.start_cmds(info))
        self.assertTrue(ok)
        running, pid = bx.is_running(info)
        self.assertTrue(running); self.assertEqual(pid, str(os.getpid()))
        self.assertEqual(self.calls_text().split(), ["service", "start", "iptables", "enable"])
        ok, _ = bx.run_steps(bx.stop_cmds(info))
        self.assertTrue(ok)
        self.assertFalse(bx.is_running(info)[0])
        self.assertEqual(self.calls_text().split()[4:], ["iptables", "disable", "service", "stop"])   # urutan: iptables dulu, lalu service
        self.assertIn("status-ok", bx.service_status_text(info)[1])

    def test_steps_stop_at_first_failure(self):
        ok, log = bx.run_steps(["true", "false", "echo never"])
        self.assertFalse(ok); self.assertEqual(len(log), 2)


class Install(Device):
    def test_install_copies_everything_and_keeps_shared_files(self):
        self.generate("xl")
        info = bx.box_info()
        _w(self.dev("clash", "proxy", "subs.yaml"), "proxies: []  # versi perangkat\n")
        ok, log = bx.run_steps(bx.plan_install(self.src, "xl", info))
        self.assertTrue(ok, log)
        self.assertTrue(os.path.isfile(self.dev("clash", "xl.yaml")))
        self.assertTrue(os.path.isfile(self.dev("clash", "proxy", "xl", "active.yaml")))
        self.assertTrue(os.path.isfile(self.dev("clash", "proxy", "xl", "trial.yaml")))
        self.assertTrue(os.path.isfile(self.dev("clash", "proxy", "free.yaml")))                 # belum ada: disalin
        self.assertIn("versi perangkat", _r(self.dev("clash", "proxy", "subs.yaml")))   # sudah ada: tidak ditimpa
        self.assertTrue(os.listdir(self.dev("clash", "ruleset")))
        self.assertTrue(os.path.isfile(self.dev("clash", "config.yaml")))                        # config lama tidak disentuh
        self.assertIn("provider", _r(self.dev("clash", "xl.yaml")))

    def test_reinstall_makes_backup(self):
        self.generate("xl")
        info = bx.box_info()
        bx.run_steps(bx.plan_install(self.src, "xl", info))
        _w(self.dev("clash", "xl.yaml"), "# versi lama di perangkat\n")
        bx.run_steps(bx.plan_install(self.src, "xl", info))
        self.assertEqual(_r(self.dev("clash", "xl.yaml.bak")), "# versi lama di perangkat\n")

    def test_two_operators_side_by_side(self):
        self.generate("xl"); self.generate("byu")
        info = bx.box_info()
        for op in ("xl", "byu"):
            self.assertTrue(bx.run_steps(bx.plan_install(self.src, op, info))[0])
        self.assertEqual({f for f in os.listdir(self.dev("clash")) if f.endswith(".yaml")}, {"config.yaml", "xl.yaml", "byu.yaml"})
        self.assertEqual(sorted(os.listdir(self.dev("clash", "proxy"))), ["byu", "free.yaml", "subs.yaml", "xl"])

    def test_install_path_with_spaces(self):
        self.generate("xl")
        spaced = os.path.join(self._tmp.name, "dir dengan spasi")
        os.rename(self.src, spaced)
        self.assertTrue(bx.run_steps(bx.plan_install(spaced, "xl", bx.box_info()))[0])
        self.assertTrue(os.path.isfile(self.dev("clash", "xl.yaml")))

    def test_generated_box_config_matches_settings_ports(self):
        self.generate("xl")
        s = bx.config_summary(h.read_text(os.path.join(self.src, "xl.yaml")))
        self.assertEqual(bx.port_warnings(s, bx.box_info()), [])
        self.assertTrue(any(v.endswith("/proxy/xl/active.yaml") for v in s["providers"].values()))


class Activate(Device):
    def test_activate_edits_only_name_line_with_backup(self):
        before = self.settings_text()
        info = bx.box_info()
        ok, log = bx.run_steps(bx.plan_activate("xl.yaml", info))
        self.assertTrue(ok, log)
        after = self.settings_text()
        self.assertTrue(bx.verify_active("xl.yaml", info))
        self.assertEqual(after.replace('name_clash_config="xl.yaml"', 'name_clash_config="config.yaml"'), before)
        self.assertEqual(_r(self.dev("settings.ini.hikari.bak")), before)
        self.assertEqual(bx.box_info()["config_path"], self.dev("clash", "xl.yaml"))     # clash_config ikut berubah

    def test_rejects_unsafe_names(self):
        for bad in ('x";rm.yaml', "../a.yaml", "a b.yaml", "plain"):
            with self.assertRaises(ValueError):
                bx.plan_activate(bad, bx.box_info())

    def test_list_configs_marks_active(self):
        _w(self.dev("clash", "xl.yaml"), "a: 1\n"); _w(self.dev("clash", "notes.txt"), "x")
        cfgs = bx.list_configs(bx.box_info())
        self.assertEqual([(c["name"], c["active"]) for c in cfgs], [("config.yaml", True), ("xl.yaml", False)])

    def test_config_summary(self):
        s = bx.config_summary(_r(self.dev("clash", "config.yaml")))
        self.assertEqual((s["mixed-port"], s["secret"], s["external-controller"]), (7890, "s3", "0.0.0.0:9090"))
        with self.assertRaises(ValueError):
            bx.config_summary("- a\n- b\n")


class MenuFlows(Device):
    def test_no_root_environment(self):
        bx.RUNNER = None
        if bx.can_use_root():
            self.skipTest("lingkungan tes ini Android berroot")
        out, left = self.run_flow(h.feature_box_menu, [""])
        self.assertIn("Android", out)

    def test_start_stop_with_consent(self):
        # Start: setuju y, pause; Stop: setuju y, pause; kembali
        out, left = self.run_flow(h.feature_box_menu, ["1", "y", "", "2", "y", "", "0"])
        self.assertEqual(left, [])
        self.assertEqual(self.calls_text().split(), ["service", "start", "iptables", "enable", "iptables", "disable", "service", "stop"])
        self.assertIn("su -c", out)                                   # perintah ditampilkan sebelum dijalankan

    def test_declined_consent_runs_nothing(self):
        out, left = self.run_flow(h.feature_box_menu, ["1", "n", "", "0"])
        self.assertEqual(self.calls_text(), "")
        self.assertIn("Dibatalkan", out)

    def test_invalid_menu_input_rejected(self):
        out, left = self.run_flow(h.feature_box_menu, ["x", "", "0"])
        self.assertIn("tidak valid", out)
        self.assertEqual(self.calls_text(), "")

    def test_install_via_menu_and_activate(self):
        self.generate("xl")
        # 5 → pilih config 1 → setuju pasang → jadikan aktif (Y) → setuju ubah settings → Start? n → pause
        out, left = self.run_flow(h.feature_box_menu, ["5", "1", "y", "y", "y", "n", "", "0"])
        self.assertEqual(left, [])
        self.assertTrue(os.path.isfile(self.dev("clash", "xl.yaml")))
        self.assertTrue(bx.verify_active("xl.yaml", bx.box_info()))
        self.assertEqual(self.calls_text(), "")                       # tidak ada start tanpa persetujuan

    def test_install_declined_leaves_device_untouched(self):
        self.generate("xl")
        self.run_flow(h.feature_box_menu, ["5", "1", "n", "", "0"])
        self.assertFalse(os.path.exists(self.dev("clash", "xl.yaml")))
        self.assertIn('name_clash_config="config.yaml"', self.settings_text())

    def test_install_restarts_when_running(self):
        self.generate("xl")
        bx.run_steps(bx.start_cmds(bx.box_info()))
        _w(self.calls, "")
        # menu: 5, pilih 1, setuju, aktifkan Y, setuju, restart Y, setuju restart, pause
        out, left = self.run_flow(h.feature_box_menu, ["5", "1", "y", "y", "y", "y", "y", "", "0"])
        self.assertEqual(left, [])
        self.assertEqual(self.calls_text().split(), ["iptables", "disable", "service", "stop", "service", "start", "iptables", "enable"])

    def test_change_active_config(self):
        _w(self.dev("clash", "byu.yaml"), "mixed-port: 1\n")
        # 6 → [1] = satu-satunya selain aktif → setuju → (tidak berjalan, tanpa tawaran restart) → pause
        out, left = self.run_flow(h.feature_box_menu, ["6", "1", "y", "", "0"])
        self.assertEqual(left, [])
        self.assertTrue(bx.verify_active("byu.yaml", bx.box_info()))

    def test_view_config(self):
        out, left = self.run_flow(h.feature_box_menu, ["7", "1", "n", "", "0"])
        self.assertEqual(left, [])
        self.assertIn("7890", out); self.assertIn("s3", out)

    def test_logs(self):
        _w(self.dev("run", "runs.log"), "baris-log-1\nbaris-log-2\n")
        out, left = self.run_flow(h.feature_box_menu, ["9", "1", "", "0"])
        self.assertIn("baris-log-2", out)

    def test_tools_update(self):
        out, left = self.run_flow(h.feature_box_menu, ["a", "1", "y", "", "0"])
        self.assertEqual(self.calls_text().split(), ["tool", "geox"])

    def test_dashboard_shows_url_and_secret(self):
        out, left = self.run_flow(h.feature_box_menu, ["8", "n", "", "0"] if bx.open_url_cmd("x") else ["8", "", "0"])
        self.assertIn("http://127.0.0.1:9090/ui/", out)
        self.assertIn("s3", out)

    def test_generate_flow_offers_install_for_box(self):
        # platform B, target 1, operator xl, rule, secret, Pasang ke Box? y, setuju pasang, aktifkan Y, setuju, Start? n, pause
        out, left = self.run_flow(lambda: h._generate_and_report([h.convert_line(VLESS)]),
                                  ["b", "1", "xl", "", "", "y", "y", "y", "y", "n", ""])
        self.assertEqual(left, [])
        self.assertTrue(os.path.isfile(self.dev("clash", "proxy", "xl", "active.yaml")))
        self.assertTrue(bx.verify_active("xl.yaml", bx.box_info()))

    def test_generate_flow_no_offer_for_nikki_or_without_root(self):
        out, left = self.run_flow(lambda: h._generate_and_report([h.convert_line(VLESS)]), ["n", "1", "xl", "", "", ""])
        self.assertEqual(left, [])
        self.assertNotIn("Pasang ke Box", out)


if __name__ == "__main__":
    unittest.main()
