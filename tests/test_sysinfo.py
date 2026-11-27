"""Tes info pengguna di bawah banner (sysinfo.py): format, deteksi jaringan/platform, status core, usage, tampilan.
Semua offline: controller Mihomo dan NetStat ditiru dengan server HTTP lokal."""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import banner as bn            # noqa: E402
import sysinfo as si           # noqa: E402


def put(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def fake_server(routes, secret=""):
    """Server HTTP lokal: routes {path: json}; bila secret diisi, tanpa Bearer yang cocok -> 401 (seperti Mihomo)."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if secret and self.headers.get("Authorization") != "Bearer " + secret:
                self.send_response(401); self.end_headers(); self.wfile.write(b'{"message":"Unauthorized"}')
                return
            if self.path not in routes:
                self.send_response(404); self.end_headers()
                return
            body = json.dumps(routes[self.path]).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=lambda: srv.serve_forever(poll_interval=0.02), daemon=True).start()
    return srv, f"127.0.0.1:{srv.server_address[1]}"


MIHOMO = {"/version": {"meta": True, "version": "v1.19.2"}, "/configs": {"mode": "rule"},
          "/connections": {"downloadTotal": 5 * 2**30, "uploadTotal": 600 * 2**20, "connections": [{}] * 42}}
NETSTAT = {"/api/summary": {
    "daily": [{"active": False, "nets": {}},
              {"active": True, "nets": {"wifi": {"up": 300 * 2**20, "down": 2**30},
                                        "data": {"up": 40 * 2**20, "down": 800 * 2**20}}}],
    "overview": {"limit": {"bytes": 20 * 2**30, "remaining": 12 * 2**30}}}}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.settings = os.path.join(self.tmp, "settings.json")
        p = mock.patch.object(si, "SETTINGS_PATH", self.settings); p.start(); self.addCleanup(p.stop)
        env = {k: v for k, v in os.environ.items() if not k.startswith("HIKARI_")}
        p = mock.patch.dict(os.environ, env, clear=True); p.start(); self.addCleanup(p.stop)
        si.clear_cache()
        self.addCleanup(si.clear_cache)

    def serve(self, routes, secret=""):
        srv, hp = fake_server(routes, secret)
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return hp


class Formatting(unittest.TestCase):
    def test_fmt_bytes(self):
        self.assertEqual(si.fmt_bytes(0), "0 B")
        self.assertEqual(si.fmt_bytes(512), "512 B")
        self.assertEqual(si.fmt_bytes(1536), "1.5 KB")
        self.assertEqual(si.fmt_bytes(340 * 2**20), "340 MB")
        self.assertEqual(si.fmt_bytes(int(1.2 * 2**30)), "1.2 GB")
        self.assertEqual(si.fmt_bytes(None), "0 B")

    def test_fmt_duration(self):
        self.assertEqual(si.fmt_duration(30), "0 mnt")
        self.assertEqual(si.fmt_duration(3 * 3600 + 12 * 60), "3 jam 12 mnt")
        self.assertEqual(si.fmt_duration(2 * 86400 + 5 * 3600), "2 hari 5 jam")

    def test_mask_ip(self):
        self.assertEqual(si.mask_ip("36.71.12.34"), "36.71.x.x")
        self.assertEqual(si.mask_ip("2001:db8::1"), "2001:x")
        self.assertEqual(si.mask_ip(None), "")

    def test_classify_iface(self):
        for n in ("wlan0", "wlan1", "swlan0"):
            self.assertEqual(si.classify_iface(n), "wifi", n)
        for n in ("rmnet_data1", "ccmni1", "v4-rmnet_data2", "seth_w0"):
            self.assertEqual(si.classify_iface(n), "data", n)
        for n in ("eth0", "br-lan", "rndis0"):
            self.assertEqual(si.classify_iface(n), "lan", n)
        self.assertEqual(si.classify_iface("foo0"), "other")

    def test_guess_kind_by_ip(self):
        self.assertEqual(si.guess_kind_by_ip("192.168.1.23"), "wifi")
        self.assertEqual(si.guess_kind_by_ip("10.20.30.40"), "data")

    def test_parse_route_and_gateway_guess(self):
        tbl = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
               "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
               "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
        self.assertEqual(si.parse_route(tbl), "192.168.1.1")
        self.assertEqual(si.parse_route(tbl, "wlan0"), "192.168.1.1")
        self.assertEqual(si.parse_route(tbl, "rmnet0"), "192.168.1.1")      # iface tak cocok -> default pertama
        self.assertIsNone(si.parse_route(""))
        self.assertEqual(si.guess_gateway("192.168.1.23"), "192.168.1.1")
        self.assertIsNone(si.guess_gateway("36.71.12.34"))
        self.assertIsNone(si.guess_gateway("bukan-ip"))


class Prefs(Base):
    def test_defaults(self):
        self.assertEqual(si.load_prefs(), si.PREF_DEFAULTS)

    def test_file_then_env_override(self):
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"isp": "xl", "info": {"mode": "compact", "mask": True, "api": "10.0.0.1:9090", "bogus": 1}}, f)
        p = si.load_prefs()
        self.assertEqual((p["mode"], p["mask"], p["api"]), ("compact", True, "10.0.0.1:9090"))
        self.assertNotIn("bogus", p)
        os.environ["HIKARI_INFO"] = "off"
        os.environ["HIKARI_INFO_MASK"] = "0"
        self.assertEqual((si.load_prefs()["mode"], si.load_prefs()["mask"]), ("off", False))
        self.assertEqual(si.load_prefs(use_env=False)["mode"], "compact")

    def test_invalid_values_fall_back(self):
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"info": {"mode": "ngawur", "platform": "xyz", "mask": "ya"}}, f)
        p = si.load_prefs()
        self.assertEqual((p["mode"], p["platform"], p["mask"]), ("full", "auto", False))

    def test_save_keeps_other_keys(self):
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"isp": "xl", "isp_fields": ["fallback"]}, f)
        p = si.load_prefs(); p["mask"] = True
        si.save_prefs(p)
        data = load(self.settings)
        self.assertEqual(data["isp"], "xl")
        self.assertTrue(data["info"]["mask"])

    def test_converter_save_settings_keeps_info(self):
        import hikari_converter as h
        with mock.patch.object(h, "SETTINGS_PATH", self.settings):
            si.save_prefs({**si.PREF_DEFAULTS, "mode": "compact"})
            h.save_settings({"isp": "xl", "isp_fields": ["default-nameserver"]})
            data = load(self.settings)
        self.assertEqual(data["info"]["mode"], "compact")
        self.assertEqual(data["isp"], "xl")


class PlatformDetect(Base):
    def _root(self, *paths):
        root = tempfile.mkdtemp()
        for p in paths:
            full = os.path.join(root, p.lstrip("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            put(full, "")
        return root

    def test_openwrt_nikki_and_openclash(self):
        prefs = si.load_prefs()
        self.assertEqual(si.detect_platform(prefs, self._root("/etc/openwrt_release", "/etc/init.d/nikki")), "nikki")
        self.assertEqual(si.detect_platform(prefs, self._root("/etc/openwrt_release", "/etc/openclash/x")), "openclash")
        self.assertIsNone(si.detect_platform(prefs, self._root("/etc/openwrt_release")))

    def test_android_is_box(self):
        self.assertEqual(si.detect_platform(si.load_prefs(), self._root("/system/build.prop")), "box")
        with mock.patch.dict(os.environ, {"PREFIX": "/data/data/com.termux/files/usr"}):
            self.assertEqual(si.detect_platform(si.load_prefs(), self._root()), "box")

    def test_pref_wins(self):
        prefs = {**si.load_prefs(), "platform": "nikki"}
        self.assertEqual(si.detect_platform(prefs, self._root("/system/build.prop")), "nikki")

    def test_core_process_scan(self):
        proc = tempfile.mkdtemp()
        for pid, comm in (("12", "python3"), ("34", "mihomo")):
            os.makedirs(os.path.join(proc, pid))
            put(os.path.join(proc, pid, "comm"), comm + "\n")
        os.makedirs(os.path.join(proc, "self"))
        self.assertTrue(si.core_process_running(proc))
        put(os.path.join(proc, "34", "comm"), "sh\n")
        self.assertFalse(si.core_process_running(proc))
        self.assertFalse(si.core_process_running(os.path.join(proc, "tidak-ada")))


class Core(Base):
    def test_probe_without_secret(self):
        hp = self.serve(MIHOMO)
        r = si.probe_controller(hp, [""])
        self.assertEqual((r["auth"], r["version"], r["mode"], r["conns"]), (True, "v1.19.2", "rule", 42))
        self.assertEqual((r["down"], r["up"]), (5 * 2**30, 600 * 2**20))

    def test_probe_tries_next_secret_on_401(self):
        hp = self.serve(MIHOMO, secret="rahasia")
        self.assertEqual(si.probe_controller(hp, ["", "salah", "rahasia"])["version"], "v1.19.2")

    def test_probe_locked_when_no_secret_matches(self):
        hp = self.serve(MIHOMO, secret="rahasia")
        r = si.probe_controller(hp, ["", "salah"])
        self.assertEqual(r["auth"], False)
        self.assertNotIn("version", r)

    def test_probe_nothing_listening(self):
        srv, hp = fake_server({})
        srv.shutdown(); srv.server_close()
        self.assertIsNone(si.probe_controller(hp, [""]))

    def test_collect_core_active_labels_box(self):
        hp = self.serve(MIHOMO)
        prefs = {**si.load_prefs(), "api": hp, "platform": "box"}
        core = si.collect_core({"online": True, "kind": "wifi", "gateway": None}, prefs)
        self.assertTrue(core["alive"])
        self.assertEqual((core["label"], core["local"]), ("Box", True))
        self.assertEqual(si.status_text(core), ("Box Aktif", "ok"))

    def test_collect_core_uses_template_secret(self):
        hp = self.serve(MIHOMO, secret="dari-template")
        prefs = {**si.load_prefs(), "api": hp, "platform": "nikki"}
        with mock.patch.object(si, "template_secret", return_value="dari-template"):
            core = si.collect_core({"online": False}, prefs)
        self.assertEqual((core["alive"], core["label"], core["auth"]), (True, "Nikki", True))

    def test_collect_core_inactive(self):
        srv, hp = fake_server({})
        srv.shutdown(); srv.server_close()
        prefs = {**si.load_prefs(), "api": hp, "platform": "box"}
        with mock.patch.object(si, "DEFAULT_API", hp), mock.patch.object(si, "core_process_running", return_value=False):
            core = si.collect_core({"online": True, "kind": "data", "gateway": None}, prefs)
        self.assertFalse(core["alive"])
        self.assertEqual(si.status_text(core), ("Box Tidak Aktif", "bad"))

    def test_collect_core_process_fallback(self):
        srv, hp = fake_server({})
        srv.shutdown(); srv.server_close()
        prefs = {**si.load_prefs(), "platform": "box"}
        with mock.patch.object(si, "DEFAULT_API", hp), mock.patch.object(si, "core_process_running", return_value=True):
            core = si.collect_core({"online": False}, prefs)
        self.assertEqual((core["alive"], core["label"]), (True, "Box"))

    def test_remote_router_core_gets_router_label(self):
        # core di router (gateway), bukan di perangkat ini; labelnya dari heuristik LuCI
        def fake_probe(hp, secrets):
            return {"auth": True, "host": hp} if hp == "192.168.1.1:9090" else None
        prefs = {**si.load_prefs(), "api": "", "platform": "auto"}
        net = {"online": True, "kind": "wifi", "gateway": "192.168.1.1"}
        with mock.patch.object(si, "probe_controller", side_effect=fake_probe), \
                mock.patch.object(si, "remote_label", return_value="Nikki") as rl:
            core = si.collect_core(net, prefs)
        self.assertEqual((core["alive"], core["label"], core["local"]), (True, "Nikki", False))
        self.assertEqual(core["where"], "router 192.168.1.1")
        rl.assert_called_once_with("192.168.1.1", prefs)

    def test_router_is_not_probed_on_mobile_data(self):
        seen = []
        net = {"online": True, "kind": "data", "gateway": "10.0.0.1"}
        with mock.patch.object(si, "probe_controller", side_effect=lambda hp, s: seen.append(hp)), \
                mock.patch.object(si, "core_process_running", return_value=False):
            core = si.collect_core(net, {**si.load_prefs(), "platform": "box"})
        self.assertFalse(core["alive"])
        self.assertEqual(seen, [si.DEFAULT_API])

    def test_remote_label_heuristic(self):
        prefs = si.load_prefs()

        def fake(status_by_slug):
            def _get(url, timeout=1.0, headers=None, direct=True):
                for slug, st in status_by_slug.items():
                    if url.endswith("/" + slug):
                        return st, b""
                return 404, b""
            return _get
        with mock.patch.object(si, "_http_get", fake({"nikki": 403})):
            self.assertEqual(si.remote_label("192.168.1.1", prefs), "Nikki")
        with mock.patch.object(si, "_http_get", fake({"openclash": 403})):
            self.assertEqual(si.remote_label("192.168.1.1", prefs), "OpenClash")
        # router yang membalas 403 untuk SEMUA halaman (termasuk yang palsu) tidak boleh salah tebak
        with mock.patch.object(si, "_http_get", lambda *a, **k: (403, b"")):
            self.assertEqual(si.remote_label("192.168.1.1", prefs), "Mihomo")
        with mock.patch.object(si, "_http_get", lambda *a, **k: (None, b"")):
            self.assertEqual(si.remote_label("192.168.1.1", prefs), "Mihomo")
        self.assertEqual(si.remote_label("192.168.1.1", {**prefs, "platform": "openclash"}), "OpenClash")

    def test_template_secret_reads_template(self):
        root = tempfile.mkdtemp(); os.makedirs(os.path.join(root, "template"))
        put(os.path.join(root, "template", "config_v1.2.yaml"), "secret: 'lama'\n")
        put(os.path.join(root, "template", "config_v1.10.yaml"), 'port: 1\nsecret: "baru"  # komentar\n')
        self.assertEqual(si.template_secret(root), "baru")
        put(os.path.join(root, "template", "template.yaml"), "secret: salinan\n")
        self.assertEqual(si.template_secret(root), "salinan")
        self.assertEqual(si.template_secret(tempfile.mkdtemp()), "")


class Usage(Base):
    def test_netstat_today_preferred(self):
        hp = self.serve(NETSTAT)
        u = si.collect_usage({"iface": "wlan0"}, {"down": 1, "up": 1}, {**si.load_prefs(), "stats": hp})
        self.assertEqual(u["source"], "hari ini")
        self.assertEqual((u["down"], u["up"]), (2**30 + 800 * 2**20, 340 * 2**20))
        self.assertEqual((u["wifi"], u["data"]), (2**30 + 300 * 2**20, 840 * 2**20))
        self.assertEqual(u["remaining"], 12 * 2**30)

    def test_netstat_without_quota(self):
        routes = json.loads(json.dumps(NETSTAT))
        routes["/api/summary"]["overview"]["limit"] = {"bytes": 0, "remaining": 0}
        u = si.collect_usage({}, None, {**si.load_prefs(), "stats": self.serve(routes)})
        self.assertIsNone(u["remaining"])

    def test_falls_back_to_core_session(self):
        srv, hp = fake_server({}); srv.shutdown(); srv.server_close()
        u = si.collect_usage({}, {"down": 5 * 2**30, "up": 600 * 2**20}, {**si.load_prefs(), "stats": hp})
        self.assertEqual((u["source"], u["down"], u["up"]), ("sesi core", 5 * 2**30, 600 * 2**20))

    def test_falls_back_to_iface_counters(self):
        srv, hp = fake_server({}); srv.shutdown(); srv.server_close()
        dev = os.path.join(self.tmp, "dev")
        put(dev, "Inter-|   Receive\n face |bytes\n"
                 "  wlan0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n")
        self.assertEqual(si._iface_counters("wlan0", dev), (1000, 2000))
        self.assertIsNone(si._iface_counters("rmnet0", dev))
        with mock.patch.object(si, "_iface_counters", return_value=(1000, 2000)):
            u = si.collect_usage({"iface": "wlan0"}, None, {**si.load_prefs(), "stats": hp})
        self.assertEqual((u["source"], u["down"], u["up"]), ("sejak boot", 1000, 2000))

    def test_nothing_available(self):
        srv, hp = fake_server({}); srv.shutdown(); srv.server_close()
        with mock.patch.object(si, "_iface_counters", return_value=None):
            self.assertIsNone(si.collect_usage({"iface": "?"}, None, {**si.load_prefs(), "stats": hp}))


class PublicLookup(Base):
    def test_ipwho_is(self):
        o = {"success": True, "ip": "203.0.113.9", "city": "Jakarta", "region": "Jakarta", "country_code": "ID",
             "connection": {"isp": "XL Axiata"}}
        with mock.patch.object(si, "_get_json", return_value=(200, o)):
            self.assertEqual(si.collect_public(), {"ip": "203.0.113.9", "city": "Jakarta", "region": "Jakarta",
                                                   "cc": "ID", "isp": "XL Axiata"})

    def test_falls_back_to_ipinfo(self):
        seq = [(None, None), (200, {"ip": "203.0.113.9", "city": "Bandung", "region": "West Java",
                                    "country": "ID", "org": "AS24203 PT XL Axiata"})]
        with mock.patch.object(si, "_get_json", side_effect=seq):
            p = si.collect_public()
        self.assertEqual((p["city"], p["cc"], p["isp"]), ("Bandung", "ID", "PT XL Axiata"))

    def test_failure_is_none(self):
        with mock.patch.object(si, "_get_json", return_value=(None, None)):
            self.assertIsNone(si.collect_public())

    def test_ipwho_failure_flag_is_ignored(self):
        seq = [(200, {"success": False, "message": "limit"}), (None, None)]
        with mock.patch.object(si, "_get_json", side_effect=seq):
            self.assertIsNone(si.collect_public())


class Cache(Base):
    def test_fresh_cache_not_refetched_and_failures_are_cached(self):
        calls = []
        fn = lambda: calls.append(1) or "nilai"
        th = si._start("k", 60, fn)
        th.join(2)
        self.assertEqual(si._value("k"), "nilai")
        self.assertIsNone(si._start("k", 60, fn))
        self.assertEqual(len(calls), 1)

        def boom():
            raise RuntimeError("x")
        si._start("err", 60, boom).join(2)
        self.assertIsNone(si._value("err"))
        self.assertIsNone(si._start("err", 60, boom))          # kegagalan juga di-cache: tidak menunggu timeout lagi

    def test_expired_cache_refetches_and_keeps_stale_value_meanwhile(self):
        si._start("k", 0, lambda: "lama").join(2)
        gate = threading.Event()
        th = si._start("k", 0, lambda: gate.wait(2) and "baru")
        self.assertEqual(si._value("k"), "lama")
        gate.set(); th.join(2)
        self.assertEqual(si._value("k"), "baru")


class Rendering(Base):
    NET = {"online": True, "iface": "wlan0", "ip": "192.168.1.23", "kind": "wifi", "operator": None, "gateway": "192.168.1.1"}
    CORE = {"alive": True, "label": "Box", "where": "", "version": "v1.19.2", "meta": True, "mode": "rule",
            "conns": 42, "auth": True}
    PUB = {"ip": "203.0.113.9", "city": "Jakarta", "region": "Jakarta", "cc": "ID", "isp": "XL Axiata"}
    USAGE = {"source": "hari ini", "up": 340 * 2**20, "down": int(1.2 * 2**30), "wifi": 2**30, "data": 5 * 2**20,
             "remaining": 12 * 2**30}

    def info(self, **kw):
        base = {"net": self.NET, "core": self.CORE, "public": self.PUB, "usage": self.USAGE, "ping": 87, "uptime": 3 * 3600}
        base.update(kw)
        return base

    def text(self, info, prefs=None, level="full", width=80):
        rows = si.build_rows(info, prefs or si.load_prefs(), level)
        return "\n".join(si.render(rows, width, color=False))

    def test_full_panel_has_all_fields(self):
        t = self.text(self.info())
        for needle in ("IP       : 192.168.1.23 lokal  ·  203.0.113.9 publik", "Lokasi   : Jakarta, ID · XL Axiata",
                       "Jaringan : WiFi  (wlan0)", "Status   : Box Aktif", "↓ 1.2 GB", "↑ 340 MB", "(hari ini)",
                       "sisa 12.0 GB", "mihomo v1.19.2", "mode rule", "42 koneksi", "uptime 3 jam 0 mnt", "ping 87 ms"):
            self.assertIn(needle, t)

    def test_status_variants(self):
        nikki = {**self.CORE, "label": "Nikki", "where": "router 192.168.1.1"}
        self.assertIn("Status   : Nikki Aktif  (router 192.168.1.1)", self.text(self.info(core=nikki)))
        off = {"alive": False, "label": "Box"}
        self.assertIn("Status   : Box Tidak Aktif", self.text(self.info(core=off)))
        self.assertIn("Status   : -", self.text(self.info(core=None)))

    def test_parse_operators_dual_sim(self):
        self.assertEqual(si.parse_operators("XL Axiata,by.U"), ["XL Axiata", "by.U"])
        self.assertEqual(si.parse_operators(",Telkomsel"), ["Telkomsel"])
        self.assertEqual(si.parse_operators("Telkomsel,Telkomsel"), ["Telkomsel"])
        self.assertEqual(si.parse_operators(""), [])
        self.assertEqual(si.parse_operators(None), [])

    def test_operator_name_lists_every_sim(self):
        fake = mock.Mock(stdout="XL Axiata,by.U\n")
        with mock.patch.object(si.subprocess, "run", return_value=fake):
            self.assertEqual(si._operator_name(), "XL Axiata / by.U")
        with mock.patch.object(si.subprocess, "run", side_effect=OSError):
            self.assertIsNone(si._operator_name())

    def test_operator_pref_overrides_detected_sim(self):
        net = {**self.NET, "iface": "rmnet_data1", "kind": "data", "operator": "XL Axiata / by.U"}
        t = self.text(self.info(net=net), {**si.load_prefs(), "operator": "by.U"})
        self.assertIn("Jaringan : Data  (rmnet_data1 · by.U)", t)
        jar = [ln for ln in t.splitlines() if ln.strip().startswith("Jaringan")][0]
        self.assertNotIn("XL Axiata", jar)                  # baris Lokasi memang memuat ISP dari lookup IP publik
        os.environ["HIKARI_OPERATOR"] = "Telkomsel"
        self.assertEqual(si.load_prefs()["operator"], "Telkomsel")

    def test_data_network_shows_operator(self):
        net = {**self.NET, "iface": "rmnet_data1", "kind": "data", "operator": "XL Axiata"}
        self.assertIn("Jaringan : Data  (rmnet_data1 · XL Axiata)", self.text(self.info(net=net)))

    def test_offline(self):
        t = self.text(self.info(net={"online": False}, public=None, usage=None, ping=None, uptime=None))
        self.assertIn("Jaringan : Offline", t)
        self.assertIn("IP       : -", t)
        self.assertIn("Usage    : -", t)

    def test_missing_pieces_render_dash_not_crash(self):
        t = self.text(self.info(public=None, usage=None, ping=None, uptime=None))
        self.assertIn("Lokasi   : -", t)
        self.assertIn("Usage    : -", t)
        self.assertIn("publik: -", t)

    def test_lookup_off_hides_public_placeholder(self):
        t = self.text(self.info(public=None), {**si.load_prefs(), "lookup": False})
        self.assertNotIn("publik", t)

    def test_mask_hides_public_ip_and_city(self):
        t = self.text(self.info(), {**si.load_prefs(), "mask": True})
        self.assertIn("203.0.x.x publik", t)
        self.assertNotIn("203.0.113.9", t)
        self.assertNotIn("Jakarta", t)
        self.assertIn("Lokasi   : ID · XL Axiata", t)

    def test_locked_controller_hint(self):
        t = self.text(self.info(core={"alive": True, "label": "Box", "where": "", "auth": False}, usage=None))
        self.assertIn("controller minta secret", t)

    def test_compact_is_one_line(self):
        t = self.text(self.info(), level="compact")
        self.assertEqual(t.strip(), "Box Aktif  ·  WiFi  ·  192.168.1.23")
        off = self.text(self.info(net={"online": False}), level="compact")
        self.assertIn("Offline", off)

    def test_no_ansi_without_color_and_width_is_respected(self):
        t = self.text(self.info(), width=40)
        self.assertNotIn("\033", t)
        for ln in t.splitlines():
            self.assertLessEqual(len(ln), 40, ln)

    def test_long_rows_wrap_instead_of_being_cut(self):
        rows = si.build_rows(self.info(), si.load_prefs(), "full", width=48)
        out = "\n".join(si.render(rows, 48, color=False))
        for needle in ("sisa 12.0 GB", "42 koneksi", "ping 87 ms", "uptime 3 jam 0 mnt"):
            self.assertIn(needle, out)
        self.assertNotIn("…", out)
        for ln in out.splitlines():
            self.assertLessEqual(len(ln), 47, ln)

    def test_wrap_helper(self):
        self.assertEqual(si._wrap(["aa", "bb", "cc"], 100), ["aa  ·  bb  ·  cc"])
        self.assertEqual(si._wrap(["aaaa", "bbbb", "cc"], 12), ["aaaa", "bbbb  ·  cc"])
        self.assertEqual(si._wrap([], 10), [])

    def test_color_applies_when_asked(self):
        with mock.patch.object(bn, "GREEN", "<G>"), mock.patch.object(bn, "RESET", "<R>"):
            out = "\n".join(si.render(si.build_rows(self.info(), si.load_prefs()), 80, color=True))
        self.assertIn("<G>Box Aktif<R>", out)


class Entry(Base):
    def test_off_mode_and_bad_level_return_nothing(self):
        os.environ["HIKARI_INFO"] = "off"
        self.assertEqual(si.lines("full", force=True), [])
        os.environ["HIKARI_INFO"] = "full"
        self.assertEqual(si.lines("bogus"), [])

    def test_disabled_when_not_a_terminal(self):
        with mock.patch.object(si.sys.stdout, "isatty", return_value=False, create=True):
            self.assertFalse(si.enabled())
        os.environ["HIKARI_INFO"] = "compact"
        self.assertTrue(si.enabled())

    def test_user_mode_caps_requested_level(self):
        os.environ["HIKARI_INFO"] = "compact"
        seen = []
        with mock.patch.object(si, "collect", side_effect=lambda lvl, p: seen.append(lvl) or {"net": {"online": False}, "core": None}):
            out = si.lines("full", 80, False)
        self.assertEqual(seen, ["compact"])
        self.assertEqual(len(out), 1)

    def test_lines_never_raise(self):
        os.environ["HIKARI_INFO"] = "full"
        with mock.patch.object(si, "collect", side_effect=RuntimeError("x")):
            self.assertEqual(si.lines("full"), [])

    def test_collect_end_to_end_with_fake_services(self):
        hp = self.serve(MIHOMO)
        st = self.serve(NETSTAT)
        prefs = {**si.load_prefs(), "api": hp, "stats": st, "platform": "box", "lookup": False}
        net = {"online": True, "iface": "wlan0", "ip": "192.168.1.23", "kind": "wifi", "operator": None, "gateway": None}
        with mock.patch.object(si, "collect_net", return_value=net), mock.patch.object(si, "collect_ping", return_value=55):
            info = si.collect("full", prefs)
        self.assertEqual(si.status_text(info["core"]), ("Box Aktif", "ok"))
        self.assertEqual(info["usage"]["source"], "hari ini")
        self.assertEqual(info["ping"], 55)
        self.assertIsNone(info["public"])
        t = "\n".join(si.render(si.build_rows(info, prefs), 80, False))
        self.assertIn("Status   : Box Aktif", t)


class BannerIntegration(Base):
    def run_banner(self, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            bn.banner(**kw)
        return buf.getvalue()

    def test_banner_without_info_is_unchanged(self):
        out = self.run_banner()
        self.assertIn("H I K A R I", out)
        self.assertNotIn("Status", out)

    def test_banner_prints_info_rows_under_it(self):
        with mock.patch.object(si, "lines", return_value=["  Status   : Box Aktif"]) as ln:
            out = self.run_banner(info="full")
        ln.assert_called_once()
        self.assertLess(out.index("Box / Nikki / OpenClash"), out.index("Status   : Box Aktif"))

    def test_banner_survives_info_failure(self):
        with mock.patch.object(si, "lines", side_effect=RuntimeError("x")):
            self.assertIn("H I K A R I", self.run_banner(info="full"))

    def test_converter_banner_defaults_to_compact_and_menu_uses_full(self):
        import hikari_converter as h
        with mock.patch.object(h, "_show_banner") as sb, contextlib.redirect_stdout(io.StringIO()):
            h.banner()
            h.banner("MISC", info="full")
        self.assertEqual([c.kwargs["info"] for c in sb.call_args_list], ["compact", "full"])


if __name__ == "__main__":
    unittest.main()
