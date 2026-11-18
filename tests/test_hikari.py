"""Tes Hikari /.CLASH — jalankan dari root project:  python3 -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import hikari_converter as h   # noqa: E402
import mrs_codec               # noqa: E402
import routetest               # noqa: E402
import nodetest                # noqa: E402

VLESS = ("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&type=tcp"
         "&flow=xtls-rprx-vision&fp=chrome&pbk=PUBKEY&sid=ab12&sni=www.example.com#Singapore")


class Paths(unittest.TestCase):
    def test_base_dir_lowercase(self):
        self.assertEqual(os.path.basename(h.BASE_DIR), "hasil")

    def test_template_in_template_dir(self):
        self.assertEqual(h.TEMPLATE_DIR, os.path.join(ROOT, "template"))
        self.assertEqual(os.path.dirname(h.TEMPLATE_PATH), h.TEMPLATE_DIR)
        self.assertEqual(h.TEMPLATE_GLOB, "config_v*.yaml")
        masters = [os.path.basename(p) for p in h.list_master_templates()]
        self.assertIn("config_v0.3.yaml", masters)          # versi lama tidak ditimpa
        self.assertIn("config_v0.4.yaml", masters)          # v0.4 juga tidak ditimpa
        self.assertEqual(masters[-1], "config_v0.5.yaml")
        self.assertEqual([f for f in os.listdir(ROOT) if f.startswith("config-template")], [])


class Emoji(unittest.TestCase):
    def test_emoji_json_valid_and_matches_default(self):
        with open(os.path.join(ROOT, "emoji.json"), encoding="utf-8") as f:
            data = json.load(f)                              # harus valid (dulu trailing comma)
        self.assertEqual(data["emojis"], h.DEFAULT_EMOJIS)
        self.assertEqual(len(h.DEFAULT_EMOJIS), 22)

    def test_loaded_from_file_without_warning(self):
        cfg = h.load_emoji_cfg()
        self.assertEqual(cfg["emojis"], h.DEFAULT_EMOJIS)
        self.assertEqual(h.EMOJI_WARNING, "")

    def test_broken_json_warns_not_silent(self):
        old = h.EMOJI_PATH
        with tempfile.TemporaryDirectory() as d:
            for text, expect_list in (('{"enabled": true, "emojis": ["🦊", "🎿",]}', ["🦊", "🎿"]),
                                      ("{rusak", h.DEFAULT_EMOJIS)):
                p = os.path.join(d, "e.json")
                open(p, "w", encoding="utf-8").write(text)
                h.EMOJI_PATH = p
                try:
                    self.assertEqual(h.load_emoji_cfg()["emojis"], expect_list)
                    self.assertTrue(h.EMOJI_WARNING)
                finally:
                    h.EMOJI_PATH = old
        h.load_emoji_cfg()

    def test_no_clash_with_group_names(self):
        tpl = h.load_template_cfg()
        names = " ".join(str(g["name"]) for g in tpl["proxy-groups"]) + " " + " ".join(str(p["name"]) for p in tpl["proxies"])
        for e in h.DEFAULT_EMOJIS:
            self.assertNotIn(e, names)

    def test_apply_emoji(self):
        n = [h.convert_line(VLESS)]
        h.apply_emoji(n)
        self.assertIn(n[0]["name"].split(" ")[0], h.DEFAULT_EMOJIS)


class Template(unittest.TestCase):
    def setUp(self):
        self.tpl = h.load_template_cfg(h.list_master_templates()[-1])

    def test_latest_is_platform_neutral(self):
        for key in ("tun", "find-process-mode", "geodata-mode", "experimental", "external-ui"):
            self.assertNotIn(key, self.tpl, key)

    def test_v03_untouched(self):
        old = h.load_template_cfg(os.path.join(h.TEMPLATE_DIR, "config_v0.3.yaml"))
        self.assertIn("tun", old)

    def test_default_secret_is_hikari(self):
        self.assertEqual(self.tpl["secret"], "hikari")

    def test_group_names_match_readme(self):
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        for g in self.tpl["proxy-groups"]:
            self.assertIn(g["name"], readme, g["name"])
        for old in ("🪺 WIFI", "🍋‍🟩 PROXY LIST", "🦈 AUTO MODE"):
            self.assertNotIn(old, readme)


class Build(unittest.TestCase):
    def test_three_platforms_validate_clean(self):
        text = h.read_text(h.find_template())
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(text, plat)
            issues = h.validate_config(cfg, plat)
            self.assertEqual(issues, [], (plat, issues))
            self.assertEqual(cfg["secret"], "hikari")
        box, _ = h.build_config(text, "box")
        self.assertEqual(box["external-ui"], "./dashboard")
        self.assertIn("tun", box)
        nikki, _ = h.build_config(text, "nikki")
        for k in ("tun", "external-ui", "find-process-mode"):
            self.assertNotIn(k, nikki)
        self.assertEqual(nikki["external-controller"], "0.0.0.0:9090")

    def test_end_to_end_into_hasil(self):
        old = h.BASE_DIR
        with tempfile.TemporaryDirectory() as d:
            h.BASE_DIR = os.path.join(d, "hasil")
            try:
                node = h.convert_line(VLESS)
                for plat in h.PLATFORMS:
                    out, _, issues, error = h.setup_full_config([dict(node)], "active.yaml", plat)
                    self.assertIsNone(error)
                    self.assertEqual(issues, [], (plat, issues))
                    self.assertTrue(out.startswith(h.BASE_DIR))
                    self.assertIn("HIKARI /.CLASH", open(os.path.join(out, "config.yaml"), encoding="utf-8").read(300))
            finally:
                h.BASE_DIR = old


class Migration(unittest.TestCase):
    def test_legacy_layout_moved(self):
        oldd, oldb, oldt, oldtp = h.SCRIPT_DIR, h.BASE_DIR, h.TEMPLATE_DIR, h.TEMPLATE_PATH
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Hasil", "full_config_box"))
            open(os.path.join(d, "template.yaml"), "w").write("port: 1\n")
            h.SCRIPT_DIR = d
            h.BASE_DIR = os.path.join(d, "hasil")
            h.TEMPLATE_DIR = os.path.join(d, "template")
            h.TEMPLATE_PATH = os.path.join(h.TEMPLATE_DIR, "template.yaml")
            try:
                notes = h.migrate_legacy_layout()
                self.assertEqual(len(notes), 2, notes)
                self.assertTrue(os.path.isdir(os.path.join(d, "hasil", "full_config_box")))
                self.assertIn("hasil", os.listdir(d)); self.assertNotIn("Hasil", os.listdir(d))
                self.assertTrue(os.path.isfile(h.TEMPLATE_PATH))
                self.assertEqual(h.migrate_legacy_layout(), [])
            finally:
                h.SCRIPT_DIR, h.BASE_DIR, h.TEMPLATE_DIR, h.TEMPLATE_PATH = oldd, oldb, oldt, oldtp


class Mrs(unittest.TestCase):
    @unittest.skipUnless(mrs_codec.backend_name(), "backend zstd tidak ada")
    def test_roundtrip_real_files(self):
        for fn in ("blocker.mrs", "plus18.mrs"):
            src = os.path.join(ROOT, "ruleset", fn)
            raw = open(src, "rb").read()
            d = mrs_codec.read_mrs_bytes(raw)
            self.assertEqual(d["behavior"], "domain")
            blob, _ = mrs_codec.write_mrs_bytes("domain", d["entries"])
            self.assertEqual(mrs_codec.get_backend().decompress(blob), mrs_codec.get_backend().decompress(raw), fn)

    @unittest.skipUnless(mrs_codec.backend_name(), "backend zstd tidak ada")
    def test_convert_file_both_ways(self):
        with tempfile.TemporaryDirectory() as d:
            y = os.path.join(d, "a.yaml"); m = os.path.join(d, "a.mrs"); t = os.path.join(d, "b.txt")
            open(y, "w").write("payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,foo.test\n")
            r = mrs_codec.convert_file(y, m)
            self.assertEqual((r["direction"], r["behavior"], r["entries"]), ("text->mrs", "domain", 2))
            r2 = mrs_codec.convert_file(m, t, text_out=True)
            self.assertEqual(r2["direction"], "mrs->text")
            self.assertEqual(sorted(open(t).read().split()), ["+.example.com", "foo.test"])


class Tools(unittest.TestCase):
    def test_route_tester(self):
        cfg, _ = h.build_config(h.read_text(h.find_template()), "box")
        res = routetest.route(cfg, os.path.join(ROOT, "ruleset"), "chatgpt.com")
        self.assertTrue(res["final"])
        self.assertIn("SMART", res["final"]["group"])

    def test_node_tester_offline_local(self):
        import socket
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        try:
            r = nodetest.test_node({"name": "x", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": "u"})
            self.assertTrue(r["ok"], r)
        finally:
            srv.close()
        r = nodetest.test_node({"name": "x", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": "u"}, timeout=1)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()


class DnsMenu(unittest.TestCase):
    def test_parse_accepts_all_formats(self):
        good = {
            "1.1.1.1": "UDP", "8.8.8.8:53": "UDP", "2606:4700:4700::1111": "UDP", "[2606:4700:4700::1111]:53": "UDP",
            "https://dns.google/dns-query": "DoH", "h3://dns.google/dns-query": "DoH3", "tls://1.1.1.1": "DoT",
            "tls://dns.google:853": "DoT", "quic://dns.adguard-dns.com": "DoQ", "udp://1.1.1.1": "UDP",
            "tcp://1.1.1.1:53": "TCP", "system": "system", "dhcp://wlan0": "DHCP", "dns.google": "UDP (domain)",
            "https://1.1.1.1/dns-query#🧩 Inject": "DoH", "tls://1.1.1.1#h3=true": "DoT",
        }
        for raw, kind in good.items():
            v, k, _, e = h.parse_dns_entry(raw)
            self.assertIsNone(e, (raw, e)); self.assertEqual(k, kind, raw); self.assertEqual(v, raw)

    def test_parse_rejects_bad(self):
        for raw in ("", "ftp://x.com", "tls://", "1.1.1.1:99999", "https://", "foo/dns-query",
                    "tls://x.com/path", "a b", "dhcp://", "1.1.1.1#", "bad_host!"):
            self.assertIsNotNone(h.parse_dns_entry(raw)[3], raw)

    def test_field_rules(self):
        P = lambda *xs: [(v, k, ip) for v, k, ip, _ in (h.parse_dns_entry(x) for x in xs)]
        self.assertTrue(any(l == "ERR" for l, _ in h.check_dns_field("default-nameserver", P("dns.google"))))
        self.assertEqual(h.check_dns_field("default-nameserver", P("tls://1.1.1.1", "8.8.8.8")), [])
        self.assertTrue(h.check_dns_field("nameserver", P("1.1.1.1")))
        self.assertEqual(h.check_dns_field("nameserver", P("tls://1.1.1.1")), [])
        self.assertTrue(h.check_dns_field("proxy-server-nameserver", P("https://1.1.1.1/dns-query")))
        self.assertEqual(h.check_dns_field("proxy-server-nameserver", P("8.8.8.8")), [])

    def test_block_set_list_roundtrip_quotes_special(self):
        text = h.read_text(h.list_master_templates()[-1])
        items = ["[2606:4700:4700::1111]:53", "https://1.1.1.1/dns-query#🧩 Inject", "tls://dns.google", "system", "#x"]
        new, found = h.block_set_list(text, "dns", "nameserver", items)
        self.assertTrue(found)
        import yaml
        self.assertEqual(yaml.safe_load(new)["dns"]["nameserver"], items)
        self.assertEqual(yaml.safe_load(new)["dns"]["default-nameserver"], yaml.safe_load(text)["dns"]["default-nameserver"])

    def test_presets_all_valid_and_ip_plain(self):
        for k, p in h.DNS_PRESETS.items():
            blocks = [p] + [v[1] for v in p.get("variants", {}).values()]
            for blk in blocks:
              for proto in ("doh", "dot", "doq"):
                for x in blk.get(proto, []):
                    self.assertIsNone(h.parse_dns_entry(x)[3], x)
            for x in p["plain"]:
                self.assertTrue(h.parse_dns_entry(x)[2], x)

    def test_bebasdns_preset(self):
        p = next(v for v in h.DNS_PRESETS.values() if "BebasDNS" in v["label"])
        self.assertEqual(len(p["variants"]), 4)
        hosts = {x for _, blk in p["variants"].values() for k in ("doh", "dot") for x in blk[k]}
        self.assertIn("https://dns.bebasid.com/dns-query", hosts)
        self.assertIn("tls://family.dns.bebasid.com", hosts)
        self.assertTrue(all(".bebasid.com" in x for x in hosts))
        self.assertTrue(all("doq" not in blk for _, blk in p["variants"].values()))


class DnsLeak(unittest.TestCase):
    def setUp(self):
        self._old = h.SETTINGS_PATH
        self._tmp = tempfile.TemporaryDirectory()
        h.SETTINGS_PATH = os.path.join(self._tmp.name, "settings.json")
        self.text = h.read_text(h.list_master_templates()[-1])

    def tearDown(self):
        h.SETTINGS_PATH = self._old
        self._tmp.cleanup()

    def test_v05_defaults_bebasdns_then_cloudflare_google(self):
        import yaml
        dns = yaml.safe_load(self.text)["dns"]
        self.assertEqual(dns["nameserver"], ["https://dns.bebasid.com/dns-query"])
        self.assertEqual(dns["fallback"], ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"])
        self.assertIs(dns["fallback-filter"]["geoip"], False)
        for key in ("nameserver", "fallback", "default-nameserver", "proxy-server-nameserver", "direct-nameserver"):
            self.assertNotIn("112.215.203.254", [str(x) for x in dns[key]])    # tidak ada DNS ISP di template

    def test_default_build_has_no_leak_or_warn(self):
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(self.text, plat)
            bad = [m for lvl, m in h.dns_leak_audit(cfg, plat) if lvl in ("LEAK", "WARN")]
            self.assertEqual(bad, [], (plat, bad))
            self.assertEqual(h.validate_config(cfg, plat), [])

    def test_xl_profile_only_nikki_openclash(self):
        for plat in ("nikki", "openclash"):
            cfg, notes = h.build_config(self.text, plat, isp="xl")
            dns = cfg["dns"]
            self.assertIn("112.215.203.254", dns["default-nameserver"])
            self.assertIn("112.215.203.254", dns["proxy-server-nameserver"])
            self.assertNotIn("112.215.203.254", dns["nameserver"] + dns["fallback"])
            self.assertTrue(any("XL Axiata" in n for n in notes))
            self.assertFalse([m for l, m in h.dns_leak_audit(cfg, plat) if l == "LEAK"])
        box, _ = h.build_config(self.text, "box", isp="xl")
        self.assertNotIn("112.215.203.254", box["dns"]["default-nameserver"])

    def test_xl_in_fallback_is_flagged_as_leak(self):
        h.save_settings({"isp": "xl", "isp_fields": ["default-nameserver", "fallback"]})
        cfg, _ = h.build_config(self.text, "nikki")                # profil dari settings.json
        self.assertIn("112.215.203.254", cfg["dns"]["fallback"])
        self.assertTrue([m for l, m in h.dns_leak_audit(cfg, "nikki") if l == "LEAK"])

    def test_no_duplicate_when_already_present(self):
        h.save_settings({"isp": "xl", "isp_fields": ["default-nameserver"]})
        cfg, _ = h.build_config(self.text, "nikki")
        cfg2 = h.copy.deepcopy(cfg)
        h.apply_isp_profile(cfg2, "xl")
        self.assertEqual(cfg2["dns"]["default-nameserver"].count("112.215.203.254"), 1)

    def test_validator_flags_fallback_without_filter(self):
        cfg, _ = h.build_config(self.text, "box")
        del cfg["dns"]["fallback-filter"]
        self.assertTrue(any("fallback-filter" in m for _, m in h.validate_config(cfg, "box")))

    def test_leak_audit_catches_problems(self):
        cfg, _ = h.build_config(self.text, "nikki")
        cfg["dns"]["respect-rules"] = False
        cfg["dns"]["enhanced-mode"] = "redir-host"
        cfg["dns"]["nameserver"] = ["112.215.203.254"]
        lv = {l for l, _ in h.dns_leak_audit(cfg, "nikki")}
        self.assertIn("LEAK", lv); self.assertIn("WARN", lv)

    def test_bebasdns_is_first_preset_with_fallback(self):
        p = h.DNS_PRESETS["1"]
        self.assertIn("BebasDNS", p["label"])
        self.assertEqual(p["fallback_secure"]["doh"], ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"])
