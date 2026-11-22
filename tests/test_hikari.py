"""Tes Hikari /.CLASH — jalankan dari root project:  python3 -m unittest discover -s tests -v"""
import glob
import json
import os
import re
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
        self.assertIn("config_v0.5.yaml", masters)          # v0.5 juga tidak ditimpa
        self.assertIn("config_v0.6.yaml", masters)          # v0.6 juga tidak ditimpa
        self.assertIn("config_v0.7.yaml", masters)          # v0.7 juga tidak ditimpa
        self.assertIn("config_v0.8.yaml", masters)          # v0.8 juga tidak ditimpa
        self.assertIn("config_v0.9.yaml", masters)          # v0.9 juga tidak ditimpa
        self.assertIn("config_v1.0.yaml", masters)          # v1.0 tetap utuh
        self.assertIn("config_v1.1.yaml", masters)          # v1.1 tetap utuh
        self.assertIn("config_v1.2.yaml", masters)          # v1.2 tetap utuh
        self.assertEqual(masters[-1], "config_v1.3.yaml")
        self.assertEqual([f for f in os.listdir(ROOT) if f.startswith("config-template")], [])


class Emoji(unittest.TestCase):
    def test_emoji_json_valid_and_matches_default(self):
        with open(os.path.join(ROOT, "emoji.json"), encoding="utf-8") as f:
            data = json.load(f)                              # harus valid (dulu trailing comma)
        self.assertEqual(data["emojis"], h.DEFAULT_EMOJIS)
        self.assertEqual(len(h.DEFAULT_EMOJIS), 21)
        self.assertNotIn("🧊", h.DEFAULT_EMOJIS)             # dipakai nama group 🧊 KEYRING (v1.2)

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
        # README sudah dipecah: tabel group ada di docs/template.md, jadi baca README + semua docs/*.md
        paths = [os.path.join(ROOT, "README.md")] + sorted(glob.glob(os.path.join(ROOT, "docs", "*.md")))
        readme = "\n".join(open(p, encoding="utf-8").read() for p in paths)
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
        self.assertIn("🌳 SMART MODE", res["final"]["group"])

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

    def test_v09_defaults_match_owner_choice(self):
        import yaml
        dns = yaml.safe_load(self.text)["dns"]
        self.assertEqual(dns["nameserver"], ["https://unfiltered.dns.bebasid.com/dns-query"])
        self.assertEqual(dns["proxy-server-nameserver"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(dns["default-nameserver"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(dns["direct-nameserver"], ["9.9.9.10", "149.112.112.10"])
        self.assertEqual(dns["fallback"], ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"])
        self.assertEqual(dns["fallback-filter"], {"geoip": False})

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


class AntiBlokir(unittest.TestCase):
    def setUp(self):
        import yaml
        self.yaml = yaml
        self.v06 = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.6.yaml"))
        self.v07 = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.7.yaml"))
        self._old = h.SETTINGS_PATH
        self._tmp = tempfile.TemporaryDirectory()
        h.SETTINGS_PATH = os.path.join(self._tmp.name, "settings.json")

    def tearDown(self):
        h.SETTINGS_PATH = self._old
        self._tmp.cleanup()

    def test_v07_has_no_plain_dns_on_direct_paths(self):
        dns = self.yaml.safe_load(self.v07)["dns"]
        for key in ("proxy-server-nameserver", "direct-nameserver", "nameserver", "fallback"):
            self.assertTrue(all(str(x).startswith("https://") for x in dns[key]), key)
        self.assertEqual(dns["default-nameserver"], ["1.1.1.1", "8.8.8.8"])      # bootstrap tetap IP
        self.assertNotIn("dnscheck", " ".join(map(str, dns["fake-ip-filter"])))

    def test_v07_only_dns_differs_from_v06(self):
        a, b = self.yaml.safe_load(self.v06), self.yaml.safe_load(self.v07)
        a["dns"], b["dns"] = {}, {}
        self.assertEqual(a, b)

    def test_v06_flagged_v07_clean(self):
        c6, _ = h.build_config(self.v06, "nikki")
        c7, _ = h.build_config(self.v07, "nikki")
        self.assertTrue(any("Internet Positif" in m for _, m in h.dns_leak_audit(c6, "nikki")))
        self.assertFalse([m for l, m in h.dns_leak_audit(c7, "nikki") if l in ("LEAK", "WARN")])

    def test_xl_ip_in_proxy_server_nameserver_not_flagged(self):
        cfg, _ = h.build_config(self.v07, "nikki", isp="xl")
        self.assertIn("112.215.203.254", cfg["dns"]["proxy-server-nameserver"])
        self.assertFalse([m for l, m in h.dns_leak_audit(cfg, "nikki") if "Internet Positif" in m])

    def test_antiblokir_changes_turn_v06_into_v07_dns(self):
        dns6 = self.yaml.safe_load(self.v06)["dns"]
        ch = h.antiblokir_changes(dns6)
        self.assertEqual(set(ch), {"nameserver", "proxy-server-nameserver", "direct-nameserver"})   # fallback sudah sama
        new = self.v06
        for k, v in ch.items():
            new, found = h.block_set_list(new, "dns", k, v)
            self.assertTrue(found)
        d = self.yaml.safe_load(new)["dns"]
        d7 = self.yaml.safe_load(self.v07)["dns"]
        for k in ("nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver", "default-nameserver"):
            self.assertEqual(d[k], d7[k], k)

    def test_antiblokir_idempotent_and_option_keep_proxy_server(self):
        dns7 = self.yaml.safe_load(self.v07)["dns"]
        self.assertEqual(h.antiblokir_changes(dns7), {})
        dns6 = self.yaml.safe_load(self.v06)["dns"]
        self.assertNotIn("proxy-server-nameserver", h.antiblokir_changes(dns6, keep_proxy_server_plain=True))

    def test_all_antiblokir_entries_parse(self):
        for k, vs in h.ANTIBLOKIR_DNS.items():
            for v in vs:
                self.assertIsNone(h.parse_dns_entry(v)[3], v)

    def test_v07_validates_clean_all_platforms(self):
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(self.v07, plat)
            self.assertEqual(h.validate_config(cfg, plat), [])


class RepoLinksV08(unittest.TestCase):
    OLD = ("crispy-funicular", "Hikari-SC")
    NEW = "github.com/nexterade/hikari-clash"

    def _urls(self, cfg):
        urls = [v["url"] for v in (cfg.get("rule-providers") or {}).values() if "url" in v]
        urls += [g["icon"] for g in cfg.get("proxy-groups") or [] if g.get("icon")]
        return urls

    def test_v08_points_only_to_new_repo(self):
        import yaml
        cfg = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.8.yaml")))
        urls = self._urls(cfg)
        self.assertGreaterEqual(len(urls), 15)
        for u in urls:
            self.assertIn("nexterade/hikari-clash/refs/heads/main/", u)
            self.assertFalse(any(o in u for o in self.OLD), u)

    def test_v08_differs_from_v07_only_in_urls(self):
        import yaml
        a = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.7.yaml")))
        b = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.8.yaml")))
        norm = lambda s: re.sub(r"nexterade/(crispy-funicular|Hikari-SC|hikari-clash)/refs/heads/(main|master)/", "REPO/", s)
        self.assertEqual(norm(yaml.safe_dump(a, allow_unicode=True)), norm(yaml.safe_dump(b, allow_unicode=True)))

    def test_old_templates_untouched(self):
        t = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.7.yaml"))
        self.assertIn("crispy-funicular", t)

    def test_ruleset_files_referenced_exist_locally(self):
        import yaml
        cfg = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.8.yaml")))
        for name, v in cfg["rule-providers"].items():
            self.assertTrue(os.path.isfile(os.path.join(h.RULESET_SOURCE, v["url"].rsplit("/", 1)[1])), name)
        for g in cfg["proxy-groups"]:
            if g.get("icon"):
                self.assertTrue(os.path.isfile(os.path.join(ROOT, "icon", g["icon"].rsplit("/", 1)[1])), g["name"])

    def test_readme_clone_url_and_images(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            r = f.read()
        self.assertIn("git clone https://github.com/nexterade/hikari-clash.git", r)
        self.assertNotIn("crispy-funicular.git", r)
        for img in re.findall(r'src="(docs/img/[^"]+)"', r):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, img)), img)
        self.assertGreaterEqual(len(re.findall(r'src="docs/img/', r)), 5)


class RegenerateAndMenu(unittest.TestCase):
    def setUp(self):
        self._saved = (h.BASE_DIR, h.SETTINGS_PATH, h.TEMPLATE_DIR, h.TEMPLATE_PATH)
        self._tmp = tempfile.TemporaryDirectory()
        h.BASE_DIR = os.path.join(self._tmp.name, "hasil")
        h.SETTINGS_PATH = os.path.join(self._tmp.name, "settings.json")
        os.makedirs(h.BASE_DIR)

    def tearDown(self):
        h.BASE_DIR, h.SETTINGS_PATH, h.TEMPLATE_DIR, h.TEMPLATE_PATH = self._saved
        self._tmp.cleanup()

    def _make(self, plat="nikki", name="active.yaml"):
        _, _, _, error = h.setup_full_config([h.convert_line(VLESS)], name, plat)
        self.assertIsNone(error)

    def test_no_sources_when_nothing_generated(self):
        self.assertEqual(h.stored_node_sources(), [])

    def test_sources_listed_after_generate(self):
        self._make("nikki", "active.yaml"); self._make("box", "trial.yaml")
        labels = {s[0] for s in h.stored_node_sources()}
        self.assertEqual(labels, {"nikki/active.yaml", "box/trial.yaml"})      # file provider kosong tidak muncul

    def test_regenerate_reuses_nodes_and_picks_up_template_change(self):
        import yaml
        self._make("nikki", "active.yaml")
        src = h.stored_node_sources()[0]
        names_before = [n["name"] for n in src[4]]
        out = os.path.join(h.BASE_DIR, h.PLATFORMS["nikki"]["out"])
        cfg_path = os.path.join(out, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("# diubah manual\n")                                        # simulasi config usang
        res = h.regenerate_all(h.stored_node_sources())
        self.assertEqual([(l, e) for l, _, _, e in res], [("nikki/active.yaml", None)])
        self.assertNotIn("diubah manual", h.read_text(cfg_path))                 # config dibangun ulang
        after = h.stored_node_sources()[0][4]
        self.assertEqual([n["name"] for n in after], names_before)               # node & nama identik, tidak dobel

    def test_regenerate_is_idempotent_and_keeps_other_provider(self):
        self._make("nikki", "active.yaml")
        trial = os.path.join(h.BASE_DIR, h.PLATFORMS["nikki"]["out"], h.PLATFORMS["nikki"]["proxy_dir"], "trial.yaml")
        h.save_proxy_yaml([{"name": "T1", "type": "direct"}], trial)
        before = h.read_text(trial)
        h.regenerate_all(h.stored_node_sources()); h.regenerate_all(h.stored_node_sources())
        self.assertEqual(len(h.stored_node_sources()), 2)
        self.assertEqual([n["name"] for s in h.stored_node_sources() if s[0].endswith("active.yaml") for n in s[4]],
                         [n["name"] for n in h.load_provider_nodes(os.path.join(os.path.dirname(trial), "active.yaml"))])
        self.assertIn("T1", h.read_text(trial))
        self.assertEqual(before.count("T1"), h.read_text(trial).count("T1"))

    def test_regenerate_copies_nodes_to_other_platform(self):
        self._make("nikki", "active.yaml")
        src = h.stored_node_sources()[0]
        _, _, issues, error = h.setup_full_config([dict(n) for n in src[4]], "active.yaml", "openclash")
        self.assertIsNone(error)
        self.assertEqual({s[0] for s in h.stored_node_sources()}, {"nikki/active.yaml", "openclash/active.yaml"})

    def test_main_menu_layout(self):
        import io, contextlib
        src = h.read_text(os.path.join(ROOT, "hikari_converter.py"))
        self.assertIn('[5]{C.RESET} Miscellaneous', src)
        self.assertNotIn('[6]{C.RESET} Miscellaneous', src)
        self.assertNotIn('Tools Ruleset', src)                                    # fitur padatkan port-games dihapus
        self.assertNotIn('def feature_tools', src)
        self.assertNotIn('compact_port_payload', src)
        self.assertIn('[Q]{C.RESET} Exit', src)
        self.assertNotIn("(converter .mrs, tester config/node/route)", src)       # komentar dihapus


class TemplateV09(unittest.TestCase):
    def setUp(self):
        import yaml
        self.yaml = yaml
        self.v08 = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.8.yaml"))
        self.v09 = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.9.yaml"))

    def test_icons_and_rulesets_master(self):
        cfg = self.yaml.safe_load(self.v09)
        icons = [g["icon"] for g in cfg["proxy-groups"] if g.get("icon")]
        self.assertGreaterEqual(len(icons), 7)
        for u in icons:
            self.assertRegex(u, r"^https://raw\.githubusercontent\.com/nexterade/hikari-clash/refs/heads/master/icon/[0-9a-f]+\.png$")
        for v in cfg["rule-providers"].values():
            self.assertIn("nexterade/hikari-clash/refs/heads/master/ruleset/", v["url"])
        self.assertNotIn("refs/heads/main/", self.v09.split("proxy-groups:", 1)[1])

    def test_v09_differs_from_v08_only_in_dns_and_branch(self):
        a, b = self.yaml.safe_load(self.v08), self.yaml.safe_load(self.v09)
        a["dns"], b["dns"] = {}, {}
        norm = lambda s: s.replace("refs/heads/main/", "refs/heads/master/")
        self.assertEqual(norm(self.yaml.safe_dump(a, allow_unicode=True)), norm(self.yaml.safe_dump(b, allow_unicode=True)))

    def test_v08_untouched(self):
        self.assertIn("refs/heads/main/icon/", self.v08)

    def test_v09_builds_clean_all_platforms(self):
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(self.v09, plat)
            self.assertEqual(h.validate_config(cfg, plat), [])
            self.assertFalse([m for l, m in h.dns_leak_audit(cfg, plat) if l in ("LEAK", "WARN")])

    def test_plain_dns_only_info_and_antiblokir_still_converts(self):
        cfg, _ = h.build_config(self.v09, "nikki")
        info = [m for l, m in h.dns_leak_audit(cfg, "nikki") if l == "INFO" and "Internet Positif" in m]
        self.assertEqual(len(info), 2)                                            # direct- & proxy-server-nameserver
        ch = h.antiblokir_changes(self.yaml.safe_load(self.v09)["dns"])
        self.assertEqual(set(ch), {"nameserver", "proxy-server-nameserver", "direct-nameserver"})

    def test_port_games_compactor_removed_but_ruleset_kept(self):
        self.assertFalse(hasattr(h, "compact_port_payload"))
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "ruleset", "port-games.yaml")))
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "archive", "port-games.full.yaml")))


class StaleTemplate(unittest.TestCase):
    def test_box_only_keys_stripped_for_openwrt_even_from_old_template(self):
        old = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.3.yaml"))      # masih memuat blok Box
        for plat in ("nikki", "openclash"):
            cfg, notes = h.build_config(old, plat)
            for k in ("tun", "find-process-mode", "geodata-mode", "experimental", "external-ui"):
                self.assertNotIn(k, cfg, (plat, k))
            self.assertTrue(any("khusus Box" in n for n in notes))
        box, _ = h.build_config(old, "box")
        self.assertEqual(box["external-ui"], "./dashboard")

    def test_stale_working_copy_noted(self):
        oldd, oldp, oldb = h.TEMPLATE_DIR, h.TEMPLATE_PATH, h.BASE_DIR
        with tempfile.TemporaryDirectory() as d:
            h.TEMPLATE_DIR = os.path.join(d, "template"); os.makedirs(h.TEMPLATE_DIR)
            h.TEMPLATE_PATH = os.path.join(h.TEMPLATE_DIR, "template.yaml")
            h.BASE_DIR = os.path.join(d, "hasil")
            import shutil
            shutil.copy(os.path.join(oldd, "config_v0.3.yaml"), h.TEMPLATE_PATH)
            shutil.copy(os.path.join(oldd, "config_v0.5.yaml"), h.TEMPLATE_DIR)
            try:
                _, notes, _, error = h.setup_full_config([h.convert_line(VLESS)], "active.yaml", "nikki")
                self.assertIsNone(error)
                self.assertTrue(any("lebih tua dari master" in n for n in notes), notes)
            finally:
                h.TEMPLATE_DIR, h.TEMPLATE_PATH, h.BASE_DIR = oldd, oldp, oldb

    def test_fallback_gets_filter_automatically(self):
        import yaml
        text = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.4.yaml"))       # tanpa fallback
        new, _ = h.block_set_list(text, "dns", "fallback", ["https://1.1.1.1/dns-query"])
        new, ok_ = h.block_ensure_key_block(new, "dns", "fallback-filter", ["geoip: false"])
        d = yaml.safe_load(new)["dns"]
        self.assertTrue(ok_)
        self.assertEqual(d["fallback"], ["https://1.1.1.1/dns-query"])
        self.assertIs(d["fallback-filter"]["geoip"], False)
        again, _ = h.block_ensure_key_block(new, "dns", "fallback-filter", ["geoip: false"])
        self.assertEqual(again, new)                                               # idempoten


class StunAndLegacy(unittest.TestCase):
    def _route(self, ver, plat, target):
        cfg, _ = h.build_config(h.read_text(os.path.join(h.TEMPLATE_DIR, f"config_v{ver}.yaml")), plat)
        return routetest.route(cfg, os.path.join(ROOT, "ruleset"), target)["final"]

    def test_stun_leaked_to_gaming_in_v05_but_not_v06(self):
        self.assertIn("GAMING", self._route("0.5", "nikki", "udp://stun.l.google.com:19302")["group"])
        for plat in h.PLATFORMS:
            for t in ("udp://stun.l.google.com:19302", "udp://x.com:3478", "udp://x.com:19309"):
                self.assertIn("Inject", self._route("0.6", plat, t)["group"], (plat, t))

    def test_stun_rule_does_not_touch_other_traffic(self):
        self.assertIn("GAMING", self._route("0.6", "nikki", "udp://game.com:17500")["group"])
        self.assertIn("GAMING", self._route("0.6", "nikki", "udp://x.com:19310")["group"])
        self.assertIn("Reject", self._route("0.6", "nikki", "udp://dnscheck.tools:443")["group"])   # QUIC tetap ditolak
        self.assertNotIn("Inject", self._route("0.6", "nikki", "tcp://game.com:17500")["group"])    # STUN hanya UDP

    def test_v06_validates_clean(self):
        t = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.6.yaml"))
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(t, plat)
            self.assertEqual(h.validate_config(cfg, plat), [])

    def test_legacy_v03_template_keeps_no_box_keys_on_nikki_openclash(self):
        t = h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.3.yaml"))
        for plat in ("nikki", "openclash"):
            cfg, notes = h.build_config(t, plat)
            for k in ("tun", "find-process-mode", "geodata-mode", "experimental", "external-ui"):
                self.assertNotIn(k, cfg, (plat, k))
            self.assertTrue(any("key khusus Box dibuang" in n for n in notes))
        box, _ = h.build_config(t, "box")
        self.assertIn("external-ui", box)

    def test_routetest_inline_logic_rule(self):
        cfg = {"rules": ["AND,((NETWORK,UDP),(DST-PORT,5000-5100)),G1", "OR,((DST-PORT,80),(DST-PORT,8080)),G2", "MATCH,G3"]}
        r = lambda t: routetest.route(cfg, ROOT, t)["final"]["group"]
        self.assertEqual(r("udp://a.com:5050"), "G1")
        self.assertEqual(r("tcp://a.com:5050"), "G3")
        self.assertEqual(r("tcp://a.com:8080"), "G2")


class TemplateV12(unittest.TestCase):
    """Template v1.2: nama group kapital, 📄 FREE NODE & 📑 KEYRING (url-test hidden), ☘️ FREE NODE & 🧊 KEYRING (select)."""

    def setUp(self):
        import yaml
        self.path = os.path.join(h.TEMPLATE_DIR, "config_v1.2.yaml")
        self.text = h.read_text(self.path)
        self.cfg = yaml.safe_load(self.text)

    def _group(self, name):
        return next(g for g in self.cfg["proxy-groups"] if g["name"] == name)

    def test_version_marker(self):
        self.assertEqual(h.template_version(self.path), "1.2")

    def test_builtin_proxies(self):
        self.assertEqual({p["name"] for p in self.cfg["proxies"]}, {"🎮 DIRECT", "✂️ REJECT", "🐬 HIJACK"})

    def test_group_names(self):
        self.assertEqual([g["name"] for g in self.cfg["proxy-groups"]],
                         ["🧩 INJECT", "🗳️ PROXY LIST", "💫 AUTO MODE", "📄 FREE NODE", "📑 KEYRING", "🌳 SMART MODE",
                          "👾 GAMING", "💤 AdBlock", "💕 Plusplus", "🍪 WIFI MODE", "🧊 KEYRING", "☘️ FREE NODE"])

    def test_hidden_urltest_groups(self):
        for n, prov in (("📄 FREE NODE", "📄 Free"), ("📑 KEYRING", "📑 Keyring")):
            g = self._group(n)
            self.assertEqual((g["type"], g["use"], g.get("hidden")), ("url-test", [prov], True), n)
            self.assertNotIn("proxies", g)

    def test_select_groups_point_to_hidden_urltest(self):
        for n, hid, prov in (("☘️ FREE NODE", "📄 FREE NODE", "📄 Free"), ("🧊 KEYRING", "📑 KEYRING", "📑 Keyring")):
            g = self._group(n)
            self.assertEqual((g["type"], g["proxies"], g["use"]), ("select", [hid], [prov]), n)

    def test_inject_exposes_free_and_keyring(self):
        px = self._group("🧩 INJECT")["proxies"]
        self.assertEqual(px, ["💫 AUTO MODE", "🗳️ PROXY LIST", "☘️ FREE NODE", "🧊 KEYRING", "🎮 DIRECT"])

    def test_rules_reference_existing_targets(self):
        targets = {g["name"] for g in self.cfg["proxy-groups"]} | {p["name"] for p in self.cfg["proxies"]} | {"DIRECT", "REJECT"}
        for r in self.cfg["rules"]:
            self.assertIn(r.rsplit(",", 1)[1], targets, r)
        self.assertNotIn("HIJACT", self.text.split("\nport:", 1)[1])      # typo v1.2 dikoreksi

    def test_keyring_provider_auto_update(self):
        p = self.cfg["proxy-providers"]["📑 Keyring"]
        self.assertEqual((p["type"], p["interval"], p["proxy"]), ("http", 864000, "💫 AUTO MODE"))
        for rp in self.cfg["rule-providers"].values():
            self.assertEqual(rp["proxy"], "💫 AUTO MODE")

    def test_dns_and_rule_order_same_as_v11(self):
        import yaml
        v11 = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v1.1.yaml")))
        self.assertEqual(self.cfg["dns"], v11["dns"])
        self.assertEqual([r.rsplit(",", 1)[0] for r in self.cfg["rules"]], [r.rsplit(",", 1)[0] for r in v11["rules"]])

    def test_builds_clean_all_platforms(self):
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(self.text, plat)
            self.assertEqual(h.validate_config(cfg, plat), [], plat)

    def test_wifi_removed_on_openwrt(self):
        for plat in ("nikki", "openclash"):
            cfg, _ = h.build_config(self.text, plat)
            self.assertNotIn("🍪 WIFI MODE", {g["name"] for g in cfg["proxy-groups"]})
            self.assertFalse([r for r in cfg["rules"] if "WifiClients" in r])

    def test_no_group_name_collides_with_node_emoji(self):
        used = "".join(g["name"].split(" ")[0] for g in self.cfg["proxy-groups"])
        for e in h.DEFAULT_EMOJIS:
            self.assertNotIn(e, used)


class TemplateV11(unittest.TestCase):
    """Template v1.1: 🗺️ Public jadi grup (bukan node), provider 📄 Free & 📑 Keyring, nama 🐦 Free dibetulkan."""

    def setUp(self):
        import yaml
        self.yaml = yaml
        self.path = os.path.join(h.TEMPLATE_DIR, "config_v1.1.yaml")
        self.text = h.read_text(self.path)
        self.cfg = yaml.safe_load(self.text)
        self.v09 = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v0.9.yaml")))

    def _group(self, name):
        return next(g for g in self.cfg["proxy-groups"] if g["name"] == name)

    def test_version_marker(self):
        self.assertEqual(h.template_version(self.path), "1.1")

    def test_providers(self):
        self.assertEqual(set(self.cfg["proxy-providers"]), {"🗳️ Active", "📅 Trial", "📄 Free", "📑 Keyring"})
        self.assertEqual(self.cfg["proxy-providers"]["📑 Keyring"]["type"], "http")
        self.assertEqual(self.cfg["proxy-providers"]["📄 Free"]["type"], "file")
        self.assertEqual(self.cfg["proxy-providers"]["📄 Free"]["path"], "./proxy/free.yaml")
        self.assertEqual(self.cfg["proxy-providers"]["📑 Keyring"]["path"], "./proxy/subs.yaml")

    def test_public_is_group_not_node(self):
        self.assertEqual({p["name"] for p in self.cfg["proxies"]}, {"🎮 Direct", "✂️ Reject", "🐬 Hijack"})
        self.assertEqual(self._group("🗺️ Public")["type"], "url-test")

    def test_public_hidden_and_best_ping_over_free_and_subs(self):
        pub = self._group("🗺️ Public")
        self.assertTrue(pub.get("hidden"))
        self.assertEqual(pub["use"], ["📄 Free", "📑 Keyring"])
        self.assertNotIn("proxies", pub)

    def test_public_only_selectable_from_keyring_and_free(self):
        users = {g["name"] for g in self.cfg["proxy-groups"] if "🗺️ Public" in (g.get("proxies") or [])}
        self.assertEqual(users, {"🛠️ Keyring", "🐦 Free"})

    def test_free_and_keyring_use_providers_and_public_as_proxy(self):
        for n in ("🐦 Free", "🛠️ Keyring"):
            g = self._group(n)
            self.assertEqual(g["proxies"], ["🗺️ Public"], n)
            self.assertEqual(g["use"], ["📄 Free", "📑 Keyring"], n)

    def test_inject_exposes_free_and_keyring(self):
        inject = self._group("🧩 Inject")
        self.assertIn("🐦 Free", inject["proxies"])
        self.assertIn("🛠️ Keyring", inject["proxies"])

    def test_no_name_starts_with_invisible_selector(self):
        names = [g["name"] for g in self.cfg["proxy-groups"]] + list(self.cfg["proxy-providers"])
        for n in names:
            self.assertFalse(n.startswith("\ufe0f"), repr(n))

    def test_no_stale_names(self):
        names = {g["name"] for g in self.cfg["proxy-groups"]} | set(self.cfg["proxy-providers"])
        for old in ("🛸 AUTO MODE", "👒 PROXY LIST", "🌳 SMART ROUTING", "🪼 Gaming", "🥪 Subscription",
                    "🛹 Free node", "📖 Free node", "🍞 Subscription"):
            self.assertNotIn(old, names)
        for p in self.cfg["proxy-providers"].values():
            self.assertNotIn(p.get("proxy"), ("🛸 AUTO MODE",))

    def test_inject_and_rules_resolve(self):
        cfg_issues = h.validate_config(h.build_config(self.text, "box")[0], "box")
        self.assertEqual([i for i in cfg_issues if i[0] == "ERR"], [])

    def test_dns_and_rules_order_same_as_v09(self):
        self.assertEqual(self.cfg["dns"], self.v09["dns"])
        strip = lambda rules: [r.split(",")[0] + "," + r.split(",")[1] for r in rules]
        self.assertEqual(strip(self.cfg["rules"]), strip(self.v09["rules"]))

    def test_template_keys_not_platform_specific(self):
        for k in ("tun", "find-process-mode", "geodata-mode", "experimental", "external-ui"):
            self.assertNotIn(k, self.cfg)

    def test_v09_untouched(self):
        v09_names = {g["name"] for g in self.v09["proxy-groups"]}
        self.assertEqual(v09_names & {"🐦 Free", "🛠️ Keyring", "🗺️ Public"}, set())

    def test_builds_clean_all_platforms(self):
        for plat in h.PLATFORMS:
            cfg, _ = h.build_config(self.text, plat)
            self.assertEqual(h.validate_config(cfg, plat), [], plat)
            self.assertFalse([m for l, m in h.dns_leak_audit(cfg, plat) if l in ("LEAK", "WARN")])

    def test_generate_creates_free_and_seeds_subs(self):
        old = h.BASE_DIR
        with tempfile.TemporaryDirectory() as d:
            h.BASE_DIR = os.path.join(d, "hasil")
            try:
                node = h.convert_line(VLESS)
                for plat, P in h.PLATFORMS.items():
                    out, _, issues, error = h.setup_full_config([dict(node)], "active.yaml", plat)
                    self.assertIsNone(error)
                    self.assertEqual(issues, [], (plat, issues))
                    pdir = os.path.join(out, P["proxy_dir"])
                    self.assertEqual(sorted(os.listdir(pdir)), ["active.yaml", "free.yaml", "subs.yaml", "trial.yaml"])
                    self.assertTrue(h.load_provider_nodes(os.path.join(pdir, "subs.yaml")))     # tersemai dari subscription.yaml
                    self.assertEqual(h.load_provider_nodes(os.path.join(pdir, "free.yaml")), [])
            finally:
                h.BASE_DIR = old

    def test_regenerate_keeps_user_free_and_ignores_free_subs(self):
        old = h.BASE_DIR
        with tempfile.TemporaryDirectory() as d:
            h.BASE_DIR = os.path.join(d, "hasil")
            try:
                node = h.convert_line(VLESS)
                out, *_ = h.setup_full_config([dict(node)], "active.yaml", "box")
                free = os.path.join(out, "proxy", "free.yaml")
                open(free, "w", encoding="utf-8").write("proxies: []\n# punya pengguna\n")
                labels = [x[0] for x in h.stored_node_sources()]
                self.assertEqual(labels, ["box/active.yaml"])                        # subs.yaml berisi 100 node tapi bukan sumber
                h.setup_full_config([dict(node)], "active.yaml", "box")
                self.assertIn("punya pengguna", open(free, encoding="utf-8").read())  # tidak ditimpa
            finally:
                h.BASE_DIR = old

    def test_offline_mode_converts_proxy_providers(self):
        for plat in h.PLATFORMS:
            cfg, notes = h.build_config(self.text, plat, provider_mode="offline")
            self.assertTrue(all(p["type"] == "file" for p in cfg["proxy-providers"].values()), plat)
            self.assertTrue(all("url" not in p for p in cfg["proxy-providers"].values()))
            self.assertTrue(any("proxy-provider" in n for n in notes))

    def test_offline_generate_has_no_missing_files(self):
        old = h.BASE_DIR
        with tempfile.TemporaryDirectory() as d:
            h.BASE_DIR = os.path.join(d, "hasil")
            try:
                node = h.convert_line(VLESS)
                for plat in h.PLATFORMS:
                    _, _, issues, error = h.setup_full_config([dict(node)], "active.yaml", plat, provider_mode="offline")
                    self.assertIsNone(error)
                    self.assertEqual(issues, [], (plat, issues))
            finally:
                h.BASE_DIR = old

    def test_subscription_yaml_valid(self):
        data = self.yaml.safe_load(h.read_text(h.SUBSCRIPTION_SOURCE))
        proxies = data["proxies"]
        self.assertTrue(proxies)
        names = [p["name"] for p in proxies]
        self.assertEqual(len(names), len(set(names)))
        self.assertFalse(set(names) & {g["name"] for g in self.cfg["proxy-groups"]})
        for p in proxies:
            self.assertTrue(p.get("server") and p.get("port") and p.get("type"))


class FreeNodeSub2yaml(unittest.TestCase):
    """Integrasi sub2yaml → proxy/free.yaml (group 🛹 Free node)."""

    def setUp(self):
        import yaml
        self.yaml = yaml
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.src = os.path.join(self.d, "out.yaml")
        self.base = os.path.join(self.d, "hasil")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, proxies):
        open(self.src, "w", encoding="utf-8").write(self.yaml.safe_dump({"proxies": proxies}, allow_unicode=True))

    def _node(self, name, port=443):
        return {"name": name, "type": "trojan", "server": "1.2.3.4", "port": port, "password": "x"}

    def test_writes_all_platforms_to_right_dir(self):
        self._write([self._node("A"), self._node("B")])
        res = h.import_free_nodes(self.src, base_dir=self.base)
        self.assertEqual([(p, n, e) for p, n, _, e in res], [(p, 2, None) for p in h.PLATFORMS])
        for plat, P in h.PLATFORMS.items():
            fn = os.path.join(self.base, P["out"], P["proxy_dir"], "free.yaml")
            self.assertEqual([x["name"] for x in h.load_provider_nodes(fn)], ["A", "B"])

    def test_invalid_nodes_dropped_and_names_deduped(self):
        bad = {"name": "tanpa-server", "type": "ss", "port": 1}
        self._write([self._node("A"), self._node("A"), bad, self._node("🧩 INJECT")])    # nama bentrok dengan group template
        (plat, n, notes, error), = h.import_free_nodes(self.src, ["box"], base_dir=self.base)
        self.assertIsNone(error)
        names = [x["name"] for x in h.load_provider_nodes(h.free_node_path("box", self.base))]
        self.assertEqual(n, 3)
        self.assertEqual(len(names), len(set(names)))
        self.assertNotIn("🧩 INJECT", names)
        self.assertTrue(any("tanpa-server" in x for x in notes))

    def test_avoids_names_used_in_active(self):
        pdir = os.path.dirname(h.free_node_path("box", self.base))
        os.makedirs(pdir)
        h.save_proxy_yaml([self._node("A")], os.path.join(pdir, "active.yaml"))
        self._write([self._node("A")])
        h.import_free_nodes(self.src, ["box"], base_dir=self.base)
        self.assertEqual([x["name"] for x in h.load_provider_nodes(h.free_node_path("box", self.base))], ["A (2)"])

    def test_append_and_replace(self):
        self._write([self._node("A")])
        h.import_free_nodes(self.src, ["box"], base_dir=self.base)
        self._write([self._node("B")])
        h.import_free_nodes(self.src, ["box"], "append", base_dir=self.base)
        fn = h.free_node_path("box", self.base)
        self.assertEqual([x["name"] for x in h.load_provider_nodes(fn)], ["A", "B"])
        h.import_free_nodes(self.src, ["box"], "replace", base_dir=self.base)
        self.assertEqual([x["name"] for x in h.load_provider_nodes(fn)], ["B"])
        self.assertTrue(os.path.exists(fn + ".bak"))

    def test_bad_source(self):
        open(self.src, "w").write("bukan: yaml-proxies\n")
        (_, n, _, error), = h.import_free_nodes(self.src, base_dir=self.base)
        self.assertEqual(n, 0); self.assertTrue(error)
        (_, _, _, error), = h.import_free_nodes(os.path.join(self.d, "nope.yaml"), base_dir=self.base)
        self.assertTrue(error)

    def test_generated_config_stays_valid_after_import(self):
        old = h.BASE_DIR
        h.BASE_DIR = self.base
        try:
            node = h.convert_line(VLESS)
            self._write([self._node("F1")])
            for plat in h.PLATFORMS:
                h.setup_full_config([dict(node)], "active.yaml", plat)
            h.import_free_nodes(self.src, base_dir=self.base)
            for plat in h.PLATFORMS:                    # regenerate tidak menimpa free.yaml hasil import
                _, _, issues, error = h.setup_full_config([dict(node)], "active.yaml", plat)
                self.assertIsNone(error); self.assertEqual(issues, [])
                self.assertEqual([x["name"] for x in h.load_provider_nodes(h.free_node_path(plat, self.base))], ["F1"])
        finally:
            h.BASE_DIR = old

    def test_run_sub2yaml(self):
        script = os.path.join(self.d, "sub2yaml.py")
        out = os.path.join(self.d, "hasil", "proxy")
        write = ("import sys, os\nd = sys.argv[sys.argv.index('-o')+1]\nos.makedirs(d, exist_ok=True)\n"
                 "open(os.path.join(d, 'free.yaml'), 'w').write('proxies: []\\n')\n")
        open(script, "w").write(write)
        ok_, msg = h.run_sub2yaml(script=script, out_dir=out)
        self.assertTrue(ok_, msg); self.assertTrue(os.path.isfile(h.sub2yaml_free_path(out)))
        ok_, msg = h.run_sub2yaml(script=os.path.join(self.d, "hilang.py"), out_dir=out)
        self.assertFalse(ok_)
        open(script, "w").write("import sys; sys.exit(3)\n")                  # gagal (kode keluar != 0)
        self.assertFalse(h.run_sub2yaml(script=script, out_dir=out)[0])
        open(script, "w").write("pass\n")                                     # selesai tapi free.yaml tidak diperbarui
        self.assertFalse(h.run_sub2yaml(script=script, out_dir=out)[0])



class ValidatorReferences(unittest.TestCase):
    """Regresi bug v1.1 asli: grup di blok proxies:, provider di proxies:/grup di use:, proxy provider yang sudah tidak ada."""

    def setUp(self):
        import yaml
        self.yaml = yaml
        self.base = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v1.1.yaml")))

    def _errs(self, cfg):
        return [m for l, m in h.validate_config(cfg, "box") if l == "ERR"]

    def _copy(self):
        return self.yaml.safe_load(self.yaml.safe_dump(self.base, allow_unicode=True))

    def test_base_is_clean(self):
        self.assertEqual(self._errs(self._copy()), [])

    def test_group_type_in_proxies_flagged(self):
        cfg = self._copy()
        cfg["proxies"].append({"name": "🗺️ Public", "type": "url-test", "use": ["📄 Free"], "url": "http://x"})
        self.assertTrue(any("bertipe grup" in m for m in self._errs(cfg)))

    def test_provider_in_group_proxies_flagged(self):
        cfg = self._copy()
        g = next(g for g in cfg["proxy-groups"] if g["name"] == "🛠️ Keyring")
        g["proxies"] = ["📄 Free"]
        self.assertTrue(any("menaruh proxy-provider '📄 Free' di proxies:" in m for m in self._errs(cfg)))

    def test_group_in_use_flagged(self):
        cfg = self._copy()
        g = next(g for g in cfg["proxy-groups"] if g["name"] == "🐦 Free")
        g["use"] = ["🗺️ Public"]
        self.assertTrue(any("memakai proxy-group '🗺️ Public' di use:" in m for m in self._errs(cfg)))

    def test_provider_proxy_to_missing_group_flagged(self):
        cfg = self._copy()
        cfg["proxy-providers"]["📑 Keyring"]["proxy"] = "🛸 AUTO MODE"
        self.assertTrue(any("'📑 Keyring' memakai proxy '🛸 AUTO MODE'" in m for m in self._errs(cfg)))

    def test_stray_selector_name_flagged(self):
        cfg = self._copy()
        g = next(g for g in cfg["proxy-groups"] if g["name"] == "🐦 Free")
        g["name"] = "\ufe0f🐦 Free"
        self.assertTrue(any("'🐦 Free' yang tidak ada" in m for m in self._errs(cfg)))


class TemplateV13(unittest.TestCase):
    """Template v1.3: 💫 FALLBACK, 🗃️ UPDATER (jalur download provider), URL test gstatic, AUTO MODE hidden."""
    URL = "http://www.gstatic.com/generate_204"

    def setUp(self):
        import yaml
        self.path = os.path.join(h.TEMPLATE_DIR, "config_v1.3.yaml")
        self.text = h.read_text(self.path)
        self.cfg = yaml.safe_load(self.text)
        self.groups = {g["name"]: g for g in self.cfg["proxy-groups"]}

    def test_version_marker(self):
        self.assertEqual(h.template_version(self.path), "1.3")

    def test_group_names(self):
        self.assertEqual(list(self.groups),
                         ["🧩 INJECT", "🗳️ PROXY LIST", "💫 AUTO MODE", "💫 FALLBACK", "🌳 SMART MODE", "👾 GAMING",
                          "💤 AdBlock", "💕 Plusplus", "🍪 WIFI MODE", "🧊 KEYRING", "☘️ FREE NODE", "🗃️ UPDATER",
                          "📄 FREE NODE", "📑 KEYRING"])

    def test_fallback_group(self):
        g = self.groups["💫 FALLBACK"]
        self.assertEqual((g["type"], g["use"], g["hidden"], g["expected-status"], g["url"]),
                         ("fallback", ["🗳️ Active", "📅 Trial"], True, 204, self.URL))
        self.assertNotIn("tolerance", g)                       # tolerance hanya dikenal url-test
        for n in ("🧩 INJECT", "🌳 SMART MODE", "👾 GAMING", "💕 Plusplus"):
            self.assertIn("💫 FALLBACK", self.groups[n]["proxies"], n)

    def test_auto_mode_hidden(self):
        self.assertIs(self.groups["💫 AUTO MODE"]["hidden"], True)

    def test_updater_falls_back_to_direct(self):
        g = self.groups["🗃️ UPDATER"]
        self.assertEqual((g["type"], g["proxies"], g["hidden"]), ("fallback", ["💫 AUTO MODE", "🎮 DIRECT"], True))
        self.assertNotIn("use", g)

    def test_downloads_go_through_updater(self):
        for name, rp in self.cfg["rule-providers"].items():
            self.assertEqual(rp["proxy"], "🗃️ UPDATER", name)
        for name, pp in self.cfg["proxy-providers"].items():
            if pp["type"] == "http":
                self.assertEqual(pp["proxy"], "🗃️ UPDATER", name)

    def test_updater_has_no_dependency_cycle(self):
        """Provider http -> UPDATER -> AUTO MODE -> provider file saja (tidak boleh kembali ke provider http)."""
        def providers(gname, seen=()):
            g = self.groups.get(gname)
            if not g or gname in seen:
                return set()
            out = set(g.get("use", []))
            for m in g.get("proxies", []):
                out |= providers(m, seen + (gname,))
            return out
        http = {n for n, p in self.cfg["proxy-providers"].items() if p["type"] == "http"}
        self.assertEqual(providers("🗃️ UPDATER") & http, set())

    def test_all_test_urls_are_gstatic_204(self):
        urls = {g["url"] for g in self.cfg["proxy-groups"] if "url" in g}
        urls |= {p["health-check"]["url"] for p in self.cfg["proxy-providers"].values() if "health-check" in p}
        self.assertEqual(urls, {self.URL})
        for g in self.cfg["proxy-groups"]:
            if "url" in g:
                self.assertEqual(g.get("expected-status"), 204, g["name"])

    def test_dns_and_rules_same_as_v12(self):
        import yaml
        v12 = yaml.safe_load(h.read_text(os.path.join(h.TEMPLATE_DIR, "config_v1.2.yaml")))
        self.assertEqual(self.cfg["dns"], v12["dns"])
        self.assertEqual(self.cfg["rules"], v12["rules"])

    def test_emoji_not_used_by_node_names(self):
        self.assertNotIn("🗃", "".join(h.DEFAULT_EMOJIS))      # dipakai nama group 🗃️ UPDATER

    def test_generates_clean_on_all_platforms_and_modes(self):
        for plat in h.PLATFORMS:
            for mode in ("template", "offline"):
                cfg, _ = h.build_config(self.text, plat, provider_mode=mode, isp="none")
                self.assertEqual([m for l, m in h.validate_config(cfg, plat) if l == "ERR"], [], (plat, mode))


class MasterTemplatesClean(unittest.TestCase):
    """Semua template master (v0.3 s/d v1.3) harus lolos validator tanpa ERR untuk ketiga platform."""

    def test_all_masters_no_errors(self):
        for path in h.list_master_templates():
            text = h.read_text(path)
            for plat in h.PLATFORMS:
                cfg, _ = h.build_config(text, plat, isp="none")
                errs = [m for l, m in h.validate_config(cfg, plat) if l == "ERR"]
                self.assertEqual(errs, [], (os.path.basename(path), plat))



class SkipCertVerifySniCustom(unittest.TestCase):
    """Regresi: link dengan allowInsecure=0/insecure=0 + SNI bug menghasilkan skip-cert-verify: false
    -> handshake TLS gagal -> semua node timeout. SNI custom harus selalu true."""
    GRPC = ("vless://a65c25f3-e050-4488-a968-76cdba48ea3d@id.vpnstore28.my.id:443?mode=gun&security=tls&encryption=none&insecure=0"
            "&type=grpc&serviceName=vless&allowInsecure=0&sni=test-gateway.instagram.com#HIKARI%20GRPC")
    WS = ("vless://a65c25f3-e050-4488-a968-76cdba48ea3d@id.vpnstore28.my.id:443?path=%2Fvless&security=tls&encryption=none&insecure=0"
          "&host=id.vpnstore28.my.id&type=ws&allowInsecure=0&sni=instagram.com#HIKARI")
    PLAIN = ("vless://a65c25f3-e050-4488-a968-76cdba48ea3d@id.vpnstore28.my.id:443?security=tls&insecure=0&allowInsecure=0&type=ws"
             "&host=id.vpnstore28.my.id&path=%2Fvless&sni=id.vpnstore28.my.id#PLAIN")

    def test_sni_bug_forced_true_even_if_link_says_zero(self):
        for uri in (self.GRPC, self.WS):
            self.assertIs(h.parse_vless(uri)["skip-cert-verify"], True, uri)

    def test_sni_equal_to_host_still_honors_zero(self):
        self.assertIs(h.parse_vless(self.PLAIN)["skip-cert-verify"], False)

    def test_trojan_sni_bug(self):
        n = h.parse_trojan("trojan://pw@id.vpnstore28.my.id:443?allowInsecure=0&sni=instagram.com#T")
        self.assertIs(n["skip-cert-verify"], True)
        n = h.parse_trojan("trojan://pw@id.vpnstore28.my.id:443?allowInsecure=0#T")
        self.assertIs(n["skip-cert-verify"], False)

    def test_fix_skip_verify_on_stored_node(self):
        old = {"name": "x", "type": "vless", "server": "a.example.com", "port": 443, "tls": True,
                "servername": "instagram.com", "skip-cert-verify": False, "network": "ws",
                "ws-opts": {"path": "/", "headers": {"Host": "a.example.com"}}}
        self.assertTrue(h.fix_skip_verify(old))
        self.assertIs(old["skip-cert-verify"], True)
        self.assertFalse(h.fix_skip_verify(old))             # idempoten

    def test_no_tls_untouched(self):
        n = {"type": "vless", "server": "a.com", "tls": False, "servername": "b.com"}
        self.assertFalse(h.fix_skip_verify(n))
        self.assertNotIn("skip-cert-verify", n)

    def test_load_provider_nodes_repairs_old_active_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "active.yaml")
            with open(p, "w", encoding="utf-8") as f:
                f.write("proxies:\n  - name: HIKARI\n    type: vless\n    server: id.vpnstore28.my.id\n"
                        "    port: 443\n    uuid: a65c25f3-e050-4488-a968-76cdba48ea3d\n    tls: true\n    servername: instagram.com\n"
                        "    skip-cert-verify: false\n    network: ws\n")
            self.assertIs(h.load_provider_nodes(p)[0]["skip-cert-verify"], True)
