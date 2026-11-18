#!/usr/bin/env python3
"""
Hikari /.CLASH — route tester: "domain/IP ini kena rule apa dan masuk group mana?" (offline, tanpa core).

Mengevaluasi `rules:` sebuah config terhadap isi rule-provider (file lokal di folder ruleset/, .yaml & .mrs).
Batasan (disengaja): tidak melakukan DNS lookup (IP-CIDR hanya dicek kalau input berupa IP), tidak mengerti
GEOIP/GEOSITE/PROCESS-NAME/SRC-*; rule seperti itu ditandai "tidak bisa dievaluasi", bukan ditebak.
"""

import ipaddress
import os
import re

import mrs_codec

UNEVALUABLE = {"GEOIP", "GEOSITE", "PROCESS-NAME", "PROCESS-PATH", "SRC-IP-CIDR", "SRC-PORT", "IN-PORT",
               "IN-TYPE", "IN-USER", "IN-NAME", "UID", "DSCP", "SRC-GEOIP", "IP-ASN", "SRC-IP-ASN",
               "IP-SUFFIX", "SRC-IP-SUFFIX", "RULE-SET-NESTED"}


def parse_target(text):
    """'example.com', 'example.com:443', '1.2.3.4:5228', 'udp://example.com:443' -> (host, port|None, 'tcp'|'udp')"""
    t = text.strip().lower()
    proto = "tcp"
    m = re.match(r"^(tcp|udp)://(.*)$", t)
    if m:
        proto, t = m.group(1), m.group(2)
    t = re.sub(r"^[a-z]+://", "", t).split("/")[0]
    port = None
    m = re.match(r"^\[([0-9a-f:]+)\](?::(\d+))?$", t)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else None, proto
    if t.count(":") == 1:
        t, p = t.split(":")
        if p.isdigit():
            port = int(p)
    return t.strip("."), port, proto


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _port_match(spec, port):
    if port is None:
        return False
    for part in re.split(r"[/,]", spec):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit() and int(a) <= port <= int(b):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


class RuleSet:
    """Isi satu rule-provider siap dicocokkan."""

    def __init__(self, name, behavior, entries):
        self.name, self.behavior = name, behavior
        self.exact, self.plus, self.dot, self.star = set(), set(), set(), set()
        self.classical, self.nets = [], []
        self.unevaluable = 0
        if behavior == "domain":
            for e in entries:
                e = e.lower()
                if e.startswith("+."):
                    self.plus.add(e[2:])
                elif e.startswith("*."):
                    self.star.add(e[2:])
                elif e.startswith("."):
                    self.dot.add(e[1:])
                else:
                    self.exact.add(e)
        elif behavior == "ipcidr":
            for e in entries:
                try:
                    self.nets.append(ipaddress.ip_network(e, strict=False))
                except ValueError:
                    pass
        else:
            for e in entries:
                parts = [p.strip() for p in str(e).split(",")]
                if parts and parts[0].upper() in UNEVALUABLE:
                    self.unevaluable += 1
                self.classical.append(parts)

    def __len__(self):
        return (len(self.exact) + len(self.plus) + len(self.dot) + len(self.star)
                + len(self.nets) + len(self.classical))

    def _domain_hit(self, host):
        if host in self.exact or host in self.plus:
            return f"domain {host}"
        labels = host.split(".")
        for i in range(1, len(labels)):
            parent = ".".join(labels[i:])
            if parent in self.plus:
                return f"+.{parent}"
            if parent in self.dot:
                return f".{parent}"
            if i == 1 and parent in self.star:
                return f"*.{parent}"
        return None

    def match(self, host, port, proto):
        """Return teks entri yang cocok, atau None."""
        ip = _is_ip(host)
        if self.behavior == "domain":
            return None if ip else self._domain_hit(host)
        if self.behavior == "ipcidr":
            if ip:
                addr = ipaddress.ip_address(host)
                for n in self.nets:
                    if addr.version == n.version and addr in n:
                        return str(n)
            return None
        for parts in self.classical:
            hit = _classical_match(parts, host, port, proto, ip)
            if hit:
                return hit
        return None


def _classical_match(parts, host, port, proto, host_is_ip):
    typ = parts[0].upper()
    val = parts[1] if len(parts) > 1 else ""
    v = val.lower()
    if typ == "DOMAIN":
        return f"DOMAIN,{val}" if not host_is_ip and host == v else None
    if typ == "DOMAIN-SUFFIX":
        return f"DOMAIN-SUFFIX,{val}" if not host_is_ip and (host == v or host.endswith("." + v)) else None
    if typ == "DOMAIN-KEYWORD":
        return f"DOMAIN-KEYWORD,{val}" if not host_is_ip and v in host else None
    if typ == "DOMAIN-REGEX":
        try:
            return f"DOMAIN-REGEX,{val}" if not host_is_ip and re.search(val, host) else None
        except re.error:
            return None
    if typ in ("IP-CIDR", "IP-CIDR6"):
        if host_is_ip:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(val, strict=False):
                    return f"{typ},{val}"
            except ValueError:
                pass
        return None
    if typ == "DST-PORT":
        return f"DST-PORT,{val}" if _port_match(val, port) else None
    if typ == "NETWORK":
        return f"NETWORK,{val}" if v == proto else None
    if typ in ("AND", "OR", "NOT"):
        return _logic_match(parts, host, port, proto, host_is_ip)
    return None


def _split_logic(expr):
    """'((NETWORK,UDP),(DST-PORT,5000-5221))' -> [['NETWORK','UDP'], ['DST-PORT','5000-5221']] (level atas)."""
    expr = expr.strip()
    if expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1]
    out, depth, cur = [], 0, ""
    for ch in expr:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur); cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return [[p.strip() for p in o.strip()[1:-1].split(",")] if o.strip().startswith("(") else [o.strip()]
            for o in out]


def _logic_match(parts, host, port, proto, host_is_ip):
    op = parts[0].upper()
    try:
        subs = _split_logic(",".join(parts[1:]))
    except Exception:
        return None
    res = [bool(_classical_match(s, host, port, proto, host_is_ip)) for s in subs if s and s[0].upper() not in UNEVALUABLE]
    if not res:
        return None
    ok = all(res) if op == "AND" else (any(res) if op == "OR" else not res[0])
    return ",".join(parts) if ok else None


def load_ruleset(name, provider, ruleset_dir):
    """rule-provider (dict dari config) -> RuleSet, atau (None, alasan). File dicari di ruleset_dir lewat nama berkas."""
    path = os.path.join(ruleset_dir, os.path.basename(str(provider.get("path", ""))))
    if not os.path.isfile(path):
        return None, f"file '{os.path.basename(path)}' tidak ada di {ruleset_dir}"
    behavior = provider.get("behavior", "classical")
    try:
        if str(provider.get("format", "yaml")).lower() == "mrs" or path.lower().endswith(".mrs"):
            d = mrs_codec.read_mrs_bytes(open(path, "rb").read())
            return RuleSet(name, d["behavior"], d["entries"]), None
        with open(path, "r", encoding="utf-8") as f:
            entries = mrs_codec.parse_rule_text(f.read())
        return RuleSet(name, behavior, entries), None
    except Exception as e:
        return None, str(e)


def route(cfg, ruleset_dir, target, max_shadow=5):
    """Evaluasi `rules` untuk `target`. Return dict(host, port, proto, final{rule,group,detail}|None,
    shadowed[...], skipped[...], load_errors{...})."""
    host, port, proto = parse_target(target)
    providers, load_errors, cache = cfg.get("rule-providers") or {}, {}, {}
    matches, skipped = [], []

    def get(name):
        if name not in cache:
            prov = providers.get(name)
            if prov is None:
                cache[name] = None
                load_errors[name] = "rule-provider tidak ada di config"
            else:
                rs, why = load_ruleset(name, prov, ruleset_dir)
                cache[name] = rs
                if why:
                    load_errors[name] = why
        return cache[name]

    for r in cfg.get("rules") or []:
        parts = [p.strip() for p in str(r).split(",")]
        typ = parts[0].upper()
        if typ == "MATCH":
            matches.append((str(r), parts[1] if len(parts) > 1 else "", "MATCH"))
            continue
        if typ == "RULE-SET" and len(parts) >= 3:
            rs = get(parts[1])
            if rs is None:
                skipped.append(f"{r}  (provider tidak bisa dibaca)")
                continue
            hit = rs.match(host, port, proto)
            if hit:
                matches.append((str(r), parts[2], f"{rs.name}: {hit}"))
            elif rs.unevaluable:
                skipped.append(f"{r}  ({rs.unevaluable} entri tipe GEOIP/PROCESS/SRC-* tidak bisa dievaluasi)")
            continue
        if typ in UNEVALUABLE:
            skipped.append(f"{r}  (tipe tidak bisa dievaluasi)")
            continue
        if typ in ("AND", "OR", "NOT"):
            # rule logika inline: AND,((NETWORK,UDP),(DST-PORT,443)),GROUP — grup = sisa setelah kurung penutup
            body = str(r).strip()[len(parts[0]) + 1:]
            depth, end = 0, -1
            for i, ch in enumerate(body):
                depth += (ch == "(") - (ch == ")")
                if depth == 0 and i > 0:
                    end = i
                    break
            group = body[end + 1:].lstrip().lstrip(",").split(",")[0].strip() if end > 0 else ""
            if group:
                hit = _logic_match([typ, body[:end + 1]], host, port, proto, _is_ip(host))
                if hit:
                    matches.append((str(r), group, hit))
            continue
        if len(parts) >= 3:
            hit = _classical_match(parts[:2], host, port, proto, _is_ip(host))
            if hit:
                matches.append((str(r), parts[2], hit))
    first = matches[0] if matches else None
    return {
        "host": host, "port": port, "proto": proto,
        "final": {"rule": first[0], "group": first[1], "detail": first[2]} if first else None,
        "shadowed": [{"rule": m[0], "group": m[1], "detail": m[2]} for m in matches[1:1 + max_shadow]],
        "skipped": skipped, "load_errors": load_errors,
    }
