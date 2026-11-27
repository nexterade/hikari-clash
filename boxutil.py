#!/usr/bin/env python3
"""
Hikari /.CLASH — logika Box Utilities (tanpa UI; menunya ada di hikari_converter.py).

Mengendalikan modul Box for Root (BFR, taamarin/box_for_magisk) lewat `su`:
  start / stop / restart / status, pasang config hasil generate, ganti config aktif (name_clash_config di settings.ini),
  lihat & daftar config, buka dashboard, log, dan box.tool (geox, subs, upkernel, upxui).

Dasar (dari settings.ini BFR yang diunggah pemilik repo + README BFR):
  box_dir=/data/adb/box, clash_config=${box_dir}/clash/${name_clash_config}, clash_provide_path=${box_dir}/clash/proxy,
  box_pid=${box_dir}/run/box.pid, log=${box_dir}/run/runs.log, bin_log=${box_dir}/run/${bin_name}.log.
  Perintah: `box.service start|stop|restart|status`, `box.iptables enable|disable`, `box.tool geox|subs|upkernel|upxui`.

Semua perintah root lewat satu pintu (`run_root`) supaya bisa dites tanpa root (RUNNER diganti `sh -c` lokal).
Yang BELUM terbukti di perangkat: format keluaran `status`, arti `box.pid`, akses root ke /storage/emulated/0.
"""

import os
import re
import shlex
import shutil
import subprocess

BOX_DIR = os.environ.get("HIKARI_BOX_DIR", "/data/adb/box")
CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.ya?ml$")
TOOL_CMDS = {"geox": "Update GeoIP/GeoSite (geox)", "subs": "Update subscription (subs)",
             "upkernel": "Update kernel/core (upkernel)", "upxui": "Pasang/Update dashboard UI (upxui)"}
RUNNER = None          # tes: fungsi (cmd:str, timeout:int) -> (rc, output)


def settings_path():
    return f"{BOX_DIR}/settings.ini"


def su_available():
    return RUNNER is not None or shutil.which("su") is not None


def is_android():
    return os.path.exists("/system/build.prop") or "ANDROID_ROOT" in os.environ


def can_use_root():
    """Menu/tawaran Box hanya relevan di Android yang punya `su` (atau saat tes memasang RUNNER)."""
    return RUNNER is not None or (shutil.which("su") is not None and is_android())


def run_root(cmd, timeout=60):
    """Jalankan `cmd` sebagai root (su -c). Return (returncode, output gabungan stdout+stderr). Tidak pernah raise."""
    if RUNNER is not None:
        return RUNNER(cmd, timeout)
    if not shutil.which("su"):
        return 127, "su tidak ditemukan (perangkat belum root / bukan Termux di Android)"
    try:
        r = subprocess.run(["su", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout {timeout} detik"
    except OSError as e:
        return 126, str(e)


def run_local(cmd, timeout=60):
    """Dipakai tes: jalankan `sh -c` biasa (tanpa su) terhadap folder 'perangkat' tiruan."""
    try:
        r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout {timeout} detik"


q = shlex.quote


def root_path(path):
    """Path untuk root: /storage/emulated/0 dan /sdcard dipetakan ke /data/media/0 (lokasi aslinya; tidak bergantung mount namespace)."""
    path = os.path.abspath(path)
    for pre in ("/storage/emulated/0", "/sdcard"):
        if path == pre or path.startswith(pre + "/"):
            return "/data/media/0" + path[len(pre):]
    return path


# ---------------------------------------------------------------- settings.ini
_ASSIGN = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$')


def parse_settings(text):
    """Ambil assignment sederhana `kunci="nilai"` / `kunci=nilai` (tanpa array/`$(...)`), dengan ${var} diperluas."""
    out = {}
    for raw in text.splitlines():
        m = _ASSIGN.match(raw.rstrip())
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if val.startswith("(") or "$(" in val:
            continue
        if val[:1] in "\"'":
            end = val.find(val[0], 1)
            val = val[1:end] if end > 0 else val[1:]
        else:
            val = val.split("#", 1)[0].strip()
        val = re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda mm: out.get(mm.group(1) or mm.group(2), mm.group(0)), val)
        out[key] = val
    return out


def box_info():
    """Baca settings.ini lewat root → dict info Box, atau {"error": "..."}."""
    rc, text = run_root(f"cat {q(settings_path())}")
    if rc != 0 or "name_clash_config" not in text and "box_dir" not in text:
        return {"error": f"settings.ini tidak terbaca ({settings_path()}): {text or 'rc=' + str(rc)}"}
    s = parse_settings(text)
    box_dir = s.get("box_dir", BOX_DIR)
    name = s.get("name_clash_config", "config.yaml")
    clash_dir = os.path.dirname(s.get("clash_config", f"{box_dir}/clash/{name}")) or f"{box_dir}/clash"
    return {"box_dir": box_dir, "clash_dir": clash_dir, "config_name": name,
            "config_path": f"{clash_dir}/{name}", "provide_path": s.get("clash_provide_path", f"{clash_dir}/proxy"),
            "bin_name": s.get("bin_name", "clash"), "xclash": s.get("xclash_option", ""),
            "network_mode": s.get("network_mode", ""), "tproxy_port": s.get("tproxy_port", ""),
            "redir_port": s.get("redir_port", ""), "run_dir": s.get("box_run", f"{box_dir}/run"),
            "pid_file": s.get("box_pid", f"{box_dir}/run/box.pid"),
            "log": s.get("box_log", f"{box_dir}/run/runs.log"), "bin_log": s.get("bin_log", f"{box_dir}/run/{s.get('bin_name', 'clash')}.log"),
            "has_name_key": "name_clash_config" in s}


# ---------------------------------------------------------------- service
def _svc(info, name):
    return f"{info['box_dir']}/scripts/{name}"


def start_cmds(info):
    return [f"{_svc(info, 'box.service')} start", f"{_svc(info, 'box.iptables')} enable"]


def stop_cmds(info):
    return [f"{_svc(info, 'box.iptables')} disable", f"{_svc(info, 'box.service')} stop"]


def run_steps(cmds, timeout=90):
    """Jalankan perintah berurutan, berhenti di kegagalan pertama. Return (ok, [(cmd, rc, out)])."""
    log = []
    for c in cmds:
        rc, out = run_root(c, timeout)
        log.append((c, rc, out))
        if rc != 0:
            return False, log
    return True, log


def is_running(info):
    """(berjalan, pid). Dari box.pid (+ cek /proc); cadangan: pidof <bin_name>. Dugaan: arti box.pid belum diverifikasi."""
    script = (f'p=$(cat {q(info["pid_file"])} 2>/dev/null); '
              f'if [ -n "$p" ] && [ -d "/proc/$p" ]; then echo "$p"; else pidof {q(info["bin_name"])} 2>/dev/null | cut -d" " -f1; fi')
    rc, out = run_root(script, 15)
    pid = out.strip().splitlines()[-1].strip() if out.strip() else ""
    return (pid.isdigit(), pid if pid.isdigit() else "")


def service_status_text(info):
    return run_root(f"{_svc(info, 'box.service')} status", 20)


# ---------------------------------------------------------------- config di perangkat
def valid_config_name(name):
    return bool(CONFIG_NAME_RE.match(name or ""))


def list_configs(info):
    """[{name,size,active}] untuk *.yaml/*.yml di folder clash (tanpa subfolder)."""
    rc, out = run_root(f'for f in {q(info["clash_dir"])}/*.yaml {q(info["clash_dir"])}/*.yml; do '
                       f'[ -f "$f" ] && echo "$(wc -c < "$f") $(basename "$f")"; done', 20)
    res = []
    for line in out.splitlines():
        size, _, name = line.strip().partition(" ")
        if size.isdigit() and valid_config_name(name):
            res.append({"name": name, "size": int(size), "active": name == info["config_name"]})
    return sorted(res, key=lambda d: (not d["active"], d["name"]))


def read_remote(path, timeout=20):
    rc, out = run_root(f"cat {q(path)}", timeout)
    return out if rc == 0 else None


def config_summary(text):
    """Ringkasan config Clash (dict). Raise ValueError bila bukan YAML mapping."""
    import yaml
    cfg = yaml.safe_load(text)
    if not isinstance(cfg, dict):
        raise ValueError("bukan YAML Clash (harus berupa mapping)")
    provs = cfg.get("proxy-providers") or {}
    return {"mixed-port": cfg.get("mixed-port") or cfg.get("port"), "redir-port": cfg.get("redir-port"),
            "tproxy-port": cfg.get("tproxy-port"), "external-controller": cfg.get("external-controller"),
            "secret": cfg.get("secret"), "external-ui": cfg.get("external-ui"),
            "dns": (cfg.get("dns") or {}).get("listen"), "mode": cfg.get("mode"),
            "providers": {k: (v or {}).get("path") for k, v in provs.items()},
            "groups": len(cfg.get("proxy-groups") or []), "rules": len(cfg.get("rules") or [])}


# ---------------------------------------------------------------- rencana pasang / aktifkan
def plan_install(src_dir, operator, info):
    """Perintah root untuk memasang hasil generate Box (<src_dir>/<operator>.yaml, proxy/<operator>/, ruleset/).
    free.yaml & subs.yaml hanya disalin bila belum ada di perangkat (tidak menimpa hasil update subs)."""
    src = root_path(src_dir)
    cfg_name = f"{operator}.yaml"
    clash, prov = info["clash_dir"], info["provide_path"]
    cmds = [f"mkdir -p {q(clash)} {q(prov + '/' + operator)} {q(clash + '/ruleset')}"]
    cmds.append(f'[ ! -f {q(clash + "/" + cfg_name)} ] || cp -f {q(clash + "/" + cfg_name)} {q(clash + "/" + cfg_name + ".bak")}')
    cmds.append(f"cp -f {q(src + '/' + cfg_name)} {q(clash + '/' + cfg_name)}")
    cmds.append(f"cp -rf {q(src + '/proxy/' + operator)}/. {q(prov + '/' + operator)}/")
    for shared in ("free.yaml", "subs.yaml"):
        cmds.append(f'[ ! -f {q(src + "/proxy/" + shared)} ] || [ -f {q(prov + "/" + shared)} ] || '
                    f'cp -f {q(src + "/proxy/" + shared)} {q(prov + "/" + shared)}')
    cmds.append(f"cp -rf {q(src + '/ruleset')}/. {q(clash + '/ruleset')}/")
    return cmds


def plan_activate(name, info):
    """Ubah name_clash_config di settings.ini (cadangan .hikari.bak dulu), lalu cek hasilnya."""
    if not valid_config_name(name):
        raise ValueError(f"nama config tidak valid: {name!r}")
    sp = settings_path()
    expr = f's|^name_clash_config=.*|name_clash_config="{name}"|'
    return [f"cp -f {q(sp)} {q(sp + '.hikari.bak')}", f"sed -i {q(expr)} {q(sp)}"]


def verify_active(name, info):
    rc, text = run_root(f"cat {q(settings_path())}", 15)
    return rc == 0 and parse_settings(text).get("name_clash_config") == name


def port_warnings(cfg_summary, info):
    """Peringatan bila port tproxy/redir di config beda dengan settings.ini."""
    out = []
    for key, sk in (("tproxy-port", "tproxy_port"), ("redir-port", "redir_port")):
        a, b = str(cfg_summary.get(key) or ""), str(info.get(sk) or "")
        if a and b and a != b:
            out.append(f"{key} di config = {a}, tapi settings.ini {sk} = {b}")
    return out


# ---------------------------------------------------------------- dashboard
def dashboard_url(summary):
    """URL dashboard dari external-controller (0.0.0.0/kosong → 127.0.0.1). Path /ui dipakai Mihomo untuk external-ui."""
    ec = str(summary.get("external-controller") or "127.0.0.1:9090")
    host, _, port = ec.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"
    return f"http://{host}:{port or '9090'}/ui/"


def open_url_cmd(url):
    """Perintah (tanpa root) membuka URL di browser Android. None bila tak ada cara."""
    if shutil.which("termux-open-url"):
        return ["termux-open-url", url]
    if shutil.which("am"):
        return ["am", "start", "--user", "0", "-a", "android.intent.action.VIEW", "-d", url]
    return None


def tail_cmd(path, n=40):
    return f"tail -n {int(n)} {q(path)}"
