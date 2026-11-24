"""Tes menu Miscellaneous > Sniffer Only — python3 -m unittest discover -s tests -v"""
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

import yaml                        # noqa: E402
import hikari_converter as h       # noqa: E402
import sniffer as sn               # noqa: E402

CONN = {
    "id": "abc",
    "metadata": {"network": "tcp", "type": "TProxy", "sourceIP": "192.168.1.5", "sourcePort": "51234",
                 "destinationIP": "104.18.2.3", "destinationPort": "443", "host": "", "sniffHost": "cdn.img.shopee.co.id",
                 "destinationGeoIP": ["US"], "destinationIPASN": "AS13335 Cloudflare, Inc.",
                 "process": "com.shopee.id", "uid": 10123},
    "upload": 2048, "download": 1048576, "chains": ["DIRECT", "🔶 Cloudflare"],
    "rule": "IPCIDR", "rulePayload": "104.16.0.0/13",
}


class SnifferTemplate(unittest.TestCase):
    def setUp(self):
        self.tpl = h.read_text(h.SNIFFER_TEMPLATE)
        self.cfg = yaml.safe_load(self.tpl)

    def test_not_picked_up_as_main_template(self):
        self.assertNotIn("sniffer_only.yaml", [os.path.basename(p) for p in h.list_master_templates()])
        self.assertNotEqual(os.path.basename(h.find_template() or ""), "sniffer_only.yaml")

    def test_no_node_no_provider_all_direct(self):
        for key in ("proxies", "proxy-providers", "rule-providers"):
            self.assertNotIn(key, self.cfg)
        for g in self.cfg["proxy-groups"]:
            self.assertEqual(g["proxies"], ["DIRECT"], g["name"])
            self.assertNotIn("use", g)
        self.assertEqual(self.cfg["rules"][-1], "MATCH,🔍 Lainnya")

    def test_sniffer_keeps_real_ip_and_host_separate(self):
        sn_cfg = self.cfg["sniffer"]
        self.assertTrue(sn_cfg["enable"])
        self.assertIs(sn_cfg["override-destination"], False)
        self.assertIs(sn_cfg["sniff"]["HTTP"]["override-destination"], False)
        self.assertTrue(sn_cfg["parse-pure-ip"])
        self.assertEqual(set(sn_cfg["sniff"]), {"TLS", "HTTP", "QUIC"})
        self.assertEqual(self.cfg["dns"]["enhanced-mode"], "redir-host")     # bukan fake-ip: destinationIP harus asli
        self.assertNotIn("geodata-mode", self.cfg)                           # GeoIP metadata hanya terisi di mode mmdb

    def test_geoip_probe_is_first_and_never_matches_real_country(self):
        self.assertEqual(self.cfg["rules"][0], "GEOIP,ZZ,DIRECT")

    def test_cloudflare_rules_match_builtin_list(self):
        v4 = [r.split(",")[1] for r in self.cfg["rules"] if r.startswith("IP-CIDR,")]
        v6 = [r.split(",")[1] for r in self.cfg["rules"] if r.startswith("IP-CIDR6,")]
        self.assertEqual(tuple(v4), sn.CLOUDFLARE_V4)
        self.assertEqual(tuple(v6), sn.CLOUDFLARE_V6)
        for r in self.cfg["rules"]:
            if r.startswith(("IP-CIDR,", "IP-CIDR6,")):
                self.assertNotIn("no-resolve", r)        # domain-only conn harus di-resolve supaya bisa cocok

    def test_wifi_mode_label_and_rule_order(self):
        """Mode WiFi: label 📶 WIFI untuk client LAN, di bawah rule CDN/DNS/LAN dan tepat sebelum MATCH."""
        rules = self.cfg["rules"]
        self.assertEqual(rules[-2:], ["SRC-IP-CIDR,192.168.0.0/16,📶 WIFI", "MATCH,🔍 Lainnya"])
        self.assertIn("📶 WIFI", [g["name"] for g in self.cfg["proxy-groups"]])
        wifi = rules.index("SRC-IP-CIDR,192.168.0.0/16,📶 WIFI")
        for r in rules:
            if r.endswith(("🔶 Cloudflare", "🟧 CloudFront", "🏠 LAN", "🧭 DNS")):
                self.assertLess(rules.index(r), wifi, r)        # label CDN/DNS/LAN tidak boleh tertutup WIFI
        self.assertIn("# template-version: sniffer-1.2", self.tpl)

    def test_wifi_label_survives_on_all_platforms(self):
        for plat in h.PLATFORMS:
            cfg, _ = h.build_sniffer_config(plat)
            self.assertIn("SRC-IP-CIDR,192.168.0.0/16,📶 WIFI", cfg["rules"], plat)
            self.assertEqual(h.validate_config(cfg, plat), [], plat)

    def test_no_isp_dns_and_no_proxy_dns(self):
        dns = self.cfg["dns"]
        self.assertNotIn("proxy-server-nameserver", dns)
        self.assertNotIn("112.215.203.254", self.tpl)
        self.assertFalse(dns["respect-rules"])


class SnifferDnsDetect(unittest.TestCase):
    SAMPLE = (
        "NetworkAgentInfo{ LinkProperties{InterfaceName: rmnet_data2 LinkAddresses: [ 10.1.2.3/30 ] "
        "DnsAddresses: [ /112.215.203.254,/112.215.198.254,/2404:8000::1 ] Domains: null MTU: 1500} }\n"
        "NetworkAgentInfo{ LinkProperties{InterfaceName: wlan0 LinkAddresses: [ 192.168.1.5/24 ] "
        "DnsAddresses: [ /192.168.1.1,/8.8.8.8 ] Domains: null} }\n"
        "NetworkAgentInfo{ LinkProperties{InterfaceName: ccmni1 DnsAddresses: [ /10.20.30.40 ] Domains: null} }\n")

    def test_parse_keeps_ipv4_and_private_only_on_mobile(self):
        got = dict(h.parse_dns_addresses(self.SAMPLE))
        self.assertEqual(got["rmnet_data2"], ["112.215.203.254", "112.215.198.254"])   # IPv6 dibuang
        self.assertEqual(got["wlan0"], ["8.8.8.8"])                                    # DNS router (privat) dibuang
        self.assertEqual(got["ccmni1"], ["10.20.30.40"])                               # DNS internal operator dipertahankan
        self.assertEqual(h.parse_dns_addresses(""), [])
        self.assertEqual(h.parse_dns_addresses(None), [])

    def test_detect_prefers_mobile_and_falls_back_without_root(self):
        class R:
            def __init__(self, rc, out): self.returncode, self.stdout = rc, out
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd[0])
            return R(1, "") if cmd[0] == "su" else R(0, self.SAMPLE)               # su gagal -> dumpsys biasa
        res = h.detect_system_dns(fake)
        self.assertEqual(calls, ["su", "dumpsys"])
        self.assertTrue(res[0][0].startswith(("rmnet", "ccmni")))

    def test_detect_returns_empty_when_unreadable(self):
        def boom(cmd, **kw): raise OSError("tidak ada")
        self.assertEqual(h.detect_system_dns(boom), [])

    def test_only_xl_preset_has_verified_ips(self):
        verified = {pid: ips for pid, _, ips, ok in h.OPERATOR_DNS_PRESETS if ok}
        self.assertEqual(verified, {"xl": h.ISP_PROFILES["xl"]["ips"]})
        for pid, _, ips, ok in h.OPERATOR_DNS_PRESETS:
            if not ok:
                self.assertEqual(ips, [], pid)                                         # tidak boleh menebak IP operator lain


class SnifferOperatorIpFlag(unittest.TestCase):
    def test_operator_hosted_hosts_flagged_and_listed(self):
        base = {"network": "TCP", "dst_port": "443", "host": "", "base_domain": "scdn.co", "geoip": "id", "cdn": "-",
                "chains": "L > DIRECT", "process": "com.spotify.music", "upload": 10, "download": 5000}
        rows = [dict(base, dst_ip="112.215.212.72", sniff_host="i.scdn.co", asn="24203 PT XL Axiata"),
                dict(base, dst_ip="199.232.114.251", sniff_host="open.spotifycdn.com", asn="54113 Fastly, Inc.")]
        md = sn.render_markdown(rows)
        self.assertIn("IP operator (cache lokal?)", md)
        blk = md.split("### Host di IP milik operator")[1].split("```")[1]
        self.assertIn("i.scdn.co", blk)
        self.assertNotIn("open.spotifycdn.com", blk)
        self.assertNotIn("Host di IP milik operator", sn.render_markdown(rows[1:]))


class SnifferMarkdown(unittest.TestCase):
    def _row(self, **kw):
        base = {"no": 1, "network": "TCP", "source": "10.0.0.2:1", "dst_ip": "1.1.1.1", "dst_port": "443", "host": "",
                "sniff_host": "a.example.com", "subdomain": "a", "base_domain": "example.com", "geoip": "sg",
                "asn": "1 Foo", "cdn": "-", "chains": "L > DIRECT", "process": "com.app", "uid": 1,
                "upload": 100, "download": 1000}
        base.update(kw)
        return base

    def test_merge_similar_and_drop_zero_download(self):
        rows = [self._row(dst_ip="1.1.1.1", upload=100, download=1000),
                self._row(dst_ip="1.1.1.2", upload=50, download=500),
                self._row(dst_ip="1.1.1.3", upload=999, download=0),           # tidak ada balasan -> dibuang
                self._row(sniff_host="b.example.com", download=2048)]
        groups, total, dropped = sn.aggregate_ok(rows)
        self.assertEqual((total, dropped, len(groups)), (4, 1, 2))
        a = next(g for g in groups if g["name"] == "a.example.com")
        self.assertEqual((a["conns"], a["up"], a["down"]), (2, 150, 1500))
        self.assertEqual(a["ips"], ["1.1.1.1", "1.1.1.2"])
        self.assertEqual(groups[0]["name"], "b.example.com")                   # urut trafik terbesar

    def test_separate_by_protocol_port_chain_and_app(self):
        rows = [self._row(), self._row(network="UDP"), self._row(dst_port="8443"), self._row(chains="X > DIRECT"),
                self._row(process="com.other")]
        self.assertEqual(len(sn.aggregate_ok(rows)[0]), 5)
        self.assertIn("UDP/QUIC", {g["proto"] for g in sn.aggregate_ok(rows)[0]})

    def test_render_has_tables_candidates_and_notes(self):
        rows = [self._row(), self._row(sniff_host="", host="dns.example.com", download=10),
                self._row(sniff_host="", host="", dst_ip="9.9.9.9", dst_port="80", download=5),
                self._row(sniff_host="x|y.example.com", download=0)]
        md = sn.render_markdown(rows, source="uji.json")
        self.assertIn("menerima data: **3**", md)
        self.assertIn("| # | Host (SNI) |", md)
        self.assertIn("## Aplikasi: `com.app`", md)
        self.assertIn("a.example.com:443", md)
        self.assertIn("+.example.com", md)
        self.assertIn("tanpa SNI", md)
        self.assertIn("host dari DNS, bukan SNI", md)
        self.assertIn("HTTP polos", md)
        sni_block = md.split("### SNI")[1].split("```")[1]
        self.assertIn("a.example.com", sni_block)
        self.assertNotIn("dns.example.com", sni_block)                          # host DNS bukan SNI
        self.assertNotIn("x|y", md)                                             # baris download 0 tidak ikut

    def test_pipe_in_host_is_escaped_and_empty_report(self):
        md = sn.render_markdown([self._row(sniff_host="a|b.example.com")])
        self.assertIn("a\\|b.example.com", md)
        empty = sn.render_markdown([self._row(download=0)])
        self.assertIn("Tidak ada koneksi yang menerima data", empty)

    def test_export_cli_roundtrip_json_and_csv(self):
        rows = [self._row(), self._row(sniff_host="zero.example.com", download=0)]
        with tempfile.TemporaryDirectory() as d:
            pj = sn.export_json(rows, os.path.join(d, "k.json"))
            pc = sn.export_csv(rows, os.path.join(d, "k.csv"))
            for src in (pj, pc):
                out = os.path.join(d, os.path.basename(src) + ".md")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(sn.main(["laporan", src, out]), 0)
                md = open(out, encoding="utf-8").read()
                self.assertIn("a.example.com", md)
                self.assertNotIn("zero.example.com", md)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(sn.main([]), 2)
                self.assertEqual(sn.main(["laporan", os.path.join(d, "tidak-ada.json")]), 1)


class SnifferOperatorDns(unittest.TestCase):
    """Aplikasi provider macet saat Box aktif (hipotesis DNS): domain provider boleh diarahkan ke DNS operator."""

    def test_default_has_no_policy(self):
        cfg, _ = h.build_sniffer_config("box")
        self.assertNotIn("nameserver-policy", cfg["dns"])
        self.assertEqual(cfg["dns"]["enhanced-mode"], "redir-host")

    def test_operator_dns_adds_policy_for_provider_domains(self):
        for plat in h.PLATFORMS:
            cfg, notes = h.build_sniffer_config(plat, operator_dns=["112.215.203.254", "118.98.44.10"])
            pol = cfg["dns"]["nameserver-policy"]
            self.assertEqual(set(pol), {"+." + d for d in h.OPERATOR_DOMAINS}, plat)
            for v in pol.values():
                self.assertEqual(v, ["112.215.203.254", "118.98.44.10"])
            self.assertTrue(any("DNS operator" in n for n in notes), plat)
            self.assertEqual(h.validate_config(cfg, plat), [], plat)
            self.assertEqual(cfg["dns"]["nameserver"], ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"])

    def test_operator_scope_all_replaces_doh_for_every_domain(self):
        for plat in h.PLATFORMS:
            cfg, notes = h.build_sniffer_config(plat, operator_dns=["112.215.203.254"], operator_scope="all")
            self.assertEqual(cfg["dns"]["nameserver"], ["112.215.203.254"], plat)
            self.assertNotIn("nameserver-policy", cfg["dns"], plat)
            self.assertEqual(cfg["dns"]["enhanced-mode"], "redir-host", plat)
            self.assertTrue(any("SEMUA domain" in n for n in notes), plat)
            # satu-satunya peringatan yang wajar: DNS polos ke ISP (memang itu tujuannya)
            issues = h.validate_config(cfg, plat)
            self.assertEqual([lvl for lvl, _ in issues], ["WARN"], plat)
            self.assertIn("112.215.203.254", issues[0][1], plat)
        cfg, _ = h.build_sniffer_config("box", operator_scope="all")            # tanpa IP: tidak ada yang berubah
        self.assertEqual(cfg["dns"]["nameserver"], ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"])

    def test_parse_operator_dns(self):
        good, bad = h.parse_operator_dns("112.215.203.254, 118.98.44.10;foo 112.215.203.254")
        self.assertEqual(good, ["112.215.203.254", "118.98.44.10"])
        self.assertEqual(bad, ["foo"])
        self.assertEqual(h.parse_operator_dns(""), ([], []))

    def test_written_yaml_roundtrips(self):
        with tempfile.TemporaryDirectory() as d:
            path, issues, _ = h.write_sniffer_config("box", out_root=d, operator_dns=["112.215.203.254"])
            self.assertEqual(issues, [])
            cfg = yaml.safe_load(h.read_text(path))
            self.assertEqual(cfg["dns"]["nameserver-policy"]["+.byu.id"], ["112.215.203.254"])


class SnifferBuild(unittest.TestCase):
    def test_all_platforms_validate_clean(self):
        for plat in h.PLATFORMS:
            with tempfile.TemporaryDirectory() as d:
                path, issues, _ = h.write_sniffer_config(plat, out_root=d)
                self.assertEqual(issues, [], plat)
                cfg = yaml.safe_load(h.read_text(path))
                self.assertIs(cfg["geodata-mode"], False, plat)
                for key in ("proxies", "proxy-providers", "rule-providers"):
                    self.assertNotIn(key, cfg)

    def test_platform_differences(self):
        box, _ = h.build_sniffer_config("box")
        nik, _ = h.build_sniffer_config("nikki")
        self.assertEqual(box["external-controller"], "127.0.0.1:9090")
        self.assertIn("tun", box)
        self.assertEqual(box["find-process-mode"], "always")       # nama app tampil di inspector
        self.assertIs(box["geodata-mode"], False)                  # BOX_TOP_LEVEL menaruh True: harus ditimpa
        self.assertEqual(nik["external-controller"], "0.0.0.0:9090")
        self.assertNotIn("tun", nik)

    def test_isp_profile_not_injected(self):
        with mock.patch.object(h, "load_settings", return_value={"isp": "xl", "isp_fields": ["default-nameserver"]}):
            cfg, _ = h.build_sniffer_config("nikki")
        self.assertNotIn("112.215.203.254", json.dumps(cfg))

    def test_asn_option(self):
        off, _ = h.build_sniffer_config("openclash")
        on, notes = h.build_sniffer_config("openclash", with_asn=True)
        self.assertNotIn("asn", off["geox-url"])
        self.assertEqual(on["rules"][:2], ["GEOIP,ZZ,DIRECT", "IP-ASN,0,DIRECT"])
        self.assertTrue(on["geox-url"]["asn"].endswith("GeoLite2-ASN.mmdb"))
        self.assertTrue(any("ASN" in n for n in notes))

    def test_random_secret(self):
        cfg, _ = h.build_sniffer_config("box", secret_mode="random")
        self.assertNotEqual(cfg["secret"], "hikari")

    def test_rewrite_makes_backup(self):
        with tempfile.TemporaryDirectory() as d:
            path, _, _ = h.write_sniffer_config("box", out_root=d)
            h.write_sniffer_config("box", out_root=d)
            self.assertTrue(os.path.isfile(path + ".bak"))

    def test_misc_menu_has_sniffer_entry(self):
        calls = []
        answers = iter(["5", "0", "0"])
        with mock.patch.object(h, "ask", side_effect=lambda *_: next(answers)), \
             mock.patch.object(h, "clear_screen"), \
             mock.patch.object(h, "feature_misc_sniffer", side_effect=lambda: calls.append(1)), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            h.feature_misc_menu()
        self.assertEqual(calls, [1])
        self.assertIn("Sniffer Only", out.getvalue())
        self.assertIn("Info Lingkungan", out.getvalue())


class HostSplit(unittest.TestCase):
    def test_split(self):
        cases = {
            "cdn.img.shopee.co.id": ("cdn.img", "shopee.co.id"),
            "shopee.co.id": ("", "shopee.co.id"),
            "api.example.com": ("api", "example.com"),
            "a.b.c.example.com.": ("a.b.c", "example.com"),
            "example.com": ("", "example.com"),
            "localhost": ("", "localhost"),
            "104.18.2.3": ("", "104.18.2.3"),
            "2606:4700::1": ("", "2606:4700::1"),
            "": ("", ""),
            "d111111abcdef8.cloudfront.net": ("d111111abcdef8", "cloudfront.net"),
        }
        for host, want in cases.items():
            self.assertEqual(sn.split_host(host), want, host)


class CdnDetection(unittest.TestCase):
    def test_builtin_cloudflare(self):
        r = sn.CdnRanges(None)
        self.assertEqual(r.lookup("104.18.2.3"), "Cloudflare")
        self.assertEqual(r.lookup("2606:4700::6810:1"), "Cloudflare")
        self.assertIsNone(r.lookup("8.8.8.8"))
        self.assertIsNone(r.lookup("bukan-ip"))
        self.assertEqual(r.cloudfront, [])

    def test_cache_dir_overrides_and_adds_cloudfront(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, sn.CLOUDFRONT_FILE), "w") as f:
                f.write("# x\n13.32.0.0/15\n2600:9000::/28\nsampah\n")
            r = sn.CdnRanges(d)
            self.assertEqual(r.lookup("13.32.1.1"), "CloudFront")
            self.assertEqual(r.lookup("2600:9000::1"), "CloudFront")
            self.assertEqual(r.lookup("104.18.2.3"), "Cloudflare")        # Cloudflare tetap dari daftar bawaan

    def test_basis_order(self):
        r = sn.CdnRanges(None)
        self.assertEqual(sn.detect_cdn(["DIRECT", "🔶 Cloudflare"], "8.8.8.8", "x.com", r), ("Cloudflare", "rule"))
        self.assertEqual(sn.detect_cdn(["DIRECT", "🟧 CloudFront"], "", "", r), ("CloudFront", "rule"))
        self.assertEqual(sn.detect_cdn(["DIRECT"], "104.18.2.3", "x.com", r), ("Cloudflare", "ip"))
        self.assertEqual(sn.detect_cdn(["DIRECT"], "", "abc.cloudfront.net", r), ("CloudFront", "host"))
        self.assertEqual(sn.detect_cdn(["DIRECT"], "", "app.workers.dev", r), ("Cloudflare", "host"))
        self.assertEqual(sn.detect_cdn(["DIRECT"], "8.8.8.8", "google.com", r), ("-", ""))
        self.assertEqual(sn.detect_cdn(["DIRECT"], "", "notcloudfront.net", r), ("-", ""))   # bukan subdomain cloudfront.net


class Rows(unittest.TestCase):
    def test_build_row_detail(self):
        row = sn.build_row(CONN, sn.CdnRanges(None), no=7)
        self.assertEqual((row["dst_ip"], row["dst_port"]), ("104.18.2.3", "443"))
        self.assertEqual((row["subdomain"], row["base_domain"]), ("cdn.img", "shopee.co.id"))
        self.assertEqual(row["host_source"], "sniff (SNI/Host)")
        self.assertEqual((row["cdn"], row["cdn_basis"]), ("Cloudflare", "rule"))
        self.assertEqual(row["geoip"], "US")
        self.assertEqual(row["source"], "192.168.1.5:51234")
        self.assertEqual(row["chains"], "🔶 Cloudflare > DIRECT")
        self.assertEqual(row["process"], "com.shopee.id")
        self.assertEqual(row["network"], "TCP")

    def test_pure_ip_connection_and_remote_destination(self):
        conn = {"id": "z", "metadata": {"network": "udp", "remoteDestination": "[2606:4700::1]:443"}, "chains": ["DIRECT"]}
        row = sn.build_row(conn, sn.CdnRanges(None))
        self.assertEqual((row["dst_ip"], row["dst_port"]), ("2606:4700::1", "443"))
        self.assertEqual(row["host_source"], "tanpa host (IP murni)")
        self.assertEqual(row["cdn"], "Cloudflare")
        self.assertEqual(row["geoip"], "")
        self.assertIn("-", "\n".join(sn.fmt_detail(row)))

    def test_missing_fields_do_not_crash(self):
        row = sn.build_row({}, None)
        self.assertEqual(row["cdn"], "-")
        sn.fmt_compact(row), sn.fmt_detail(row)

    def test_tracker_dedupes_and_updates_traffic(self):
        t = sn.Tracker(sn.CdnRanges(None))
        self.assertEqual(len(t.update([CONN])), 1)
        later = dict(CONN, download=9999999)
        self.assertEqual(t.update([later]), [])
        self.assertEqual(t.all()[0]["download"], 9999999)
        # koneksi yang sudah tertutup tetap tersimpan
        other = dict(CONN, id="def")
        self.assertEqual([r["no"] for r in t.update([other])], [2])
        t.update([])
        self.assertEqual(len(t.all()), 2)

    def test_summary_and_export(self):
        t = sn.Tracker(sn.CdnRanges(None))
        t.update([CONN, dict(CONN, id="2", metadata=dict(CONN["metadata"], sniffHost="", host=""))])
        s = sn.summarize(t.all())
        self.assertEqual((s["total"], s["sniffed"], s["no_host"]), (2, 1, 1))
        self.assertEqual(s["cdn"]["Cloudflare"], 2)
        self.assertEqual(s["base"]["shopee.co.id"], 1)
        self.assertTrue(sn.summary_lines(t.all()))
        with tempfile.TemporaryDirectory() as d:
            p = sn.export_csv(t.all(), os.path.join(d, "x", "k.csv"))
            self.assertIn("shopee.co.id", h.read_text(p))
            pj = sn.export_json(t.all(), os.path.join(d, "k.json"))
            self.assertEqual(len(json.loads(h.read_text(pj))), 2)

    def test_human_bytes(self):
        self.assertEqual(sn.human_bytes(512), "512 B")
        self.assertEqual(sn.human_bytes(1048576), "1.0 MB")


class Controller(unittest.TestCase):
    def test_controller_url(self):
        cases = {"0.0.0.0:9090": "http://127.0.0.1:9090", "127.0.0.1:9090": "http://127.0.0.1:9090",
                 ":9191": "http://127.0.0.1:9191", "[::]:9090": "http://127.0.0.1:9090",
                 "192.168.1.1:9090": "http://192.168.1.1:9090", "http://10.0.0.2:9090/": "http://10.0.0.2:9090"}
        for raw, want in cases.items():
            self.assertEqual(sn.controller_url(raw), want, raw)

    def _serve(self, secret):
        class H(BaseHTTPRequestHandler):
            def do_GET(self_):
                if self_.path != "/connections":
                    self_.send_response(404); self_.end_headers(); return
                if secret and self_.headers.get("Authorization") != f"Bearer {secret}":
                    self_.send_response(401); self_.end_headers(); return
                body = json.dumps({"connections": [CONN]}).encode()
                self_.send_response(200); self_.send_header("Content-Length", str(len(body))); self_.end_headers()
                self_.wfile.write(body)

            def log_message(self_, *a):
                pass
        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def test_fetch_ok_and_secret(self):
        base = self._serve("rahasia")
        self.assertEqual(sn.fetch_connections(base, "rahasia")[0]["id"], "abc")
        with self.assertRaises(sn.SnifferError) as e:
            sn.fetch_connections(base, "salah")
        self.assertIn("401", str(e.exception))

    def test_fetch_unreachable(self):
        with self.assertRaises(sn.SnifferError) as e:
            sn.fetch_connections("http://127.0.0.1:1", "", timeout=1)
        self.assertIn("tidak terjangkau", str(e.exception))

    def test_fetch_not_json(self):
        base = self._serve("")
        with self.assertRaises(sn.SnifferError):
            sn.fetch_connections(base + "/bukan-api", "")      # 404


class CidrUpdate(unittest.TestCase):
    AWS = json.dumps({"prefixes": [
        {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
        {"ip_prefix": "3.5.0.0/19", "service": "S3"},
        {"ip_prefix": "15.158.0.0/16", "service": "CLOUDFRONT_ORIGIN_FACING"}],
        "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"}]})

    def test_parse_aws(self):
        self.assertEqual(sn.parse_aws_cloudfront(self.AWS), ["13.32.0.0/15", "2600:9000::/28"])

    def test_update_writes_cache_and_is_used(self):
        def fake(url):
            if "ips-v4" in url:
                return "173.245.48.0/20\n103.21.244.0/22\n"
            if "ips-v6" in url:
                return "2400:cb00::/32\n"
            return self.AWS
        with tempfile.TemporaryDirectory() as d:
            res = sn.update_cdn_ranges(d, fetch=fake)
            self.assertEqual(res, [("Cloudflare", 3, None), ("CloudFront", 2, None)])
            r = sn.CdnRanges(d)
            self.assertTrue(r.cloudflare_from_cache)
            self.assertEqual(r.lookup("13.32.5.5"), "CloudFront")

    def test_one_source_failing_keeps_the_other(self):
        def fake(url):
            if "amazonaws" in url:
                raise OSError("jaringan putus")
            return "173.245.48.0/20\n"
        with tempfile.TemporaryDirectory() as d:
            res = sn.update_cdn_ranges(d, fetch=fake)
            self.assertIsNone(res[0][2])
            self.assertIn("jaringan putus", res[1][2])
            self.assertFalse(os.path.exists(os.path.join(d, sn.CLOUDFRONT_FILE)))

    def test_garbage_does_not_overwrite_good_cache(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, sn.CLOUDFLARE_FILE)
            with open(good, "w") as f:
                f.write("173.245.48.0/20\n")
            res = sn.update_cdn_ranges(d, fetch=lambda url: "<html>blocked</html>")
            self.assertTrue(all(r[2] for r in res))
            self.assertEqual(h.read_text(good), "173.245.48.0/20\n")


if __name__ == "__main__":
    unittest.main()
