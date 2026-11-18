<div align="center">

# 🌸 HIKARI /.CLASH

**Toolkit CLI offline untuk convert & generate config Mihomo (Clash Meta)**
satu template → siap pakai di **Box for Root**, **Nikki**, dan **OpenClash**

<sub>Sebelumnya bernama *Hikari Subclash* / Hikari-SC.</sub>

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Core](https://img.shields.io/badge/Core-Mihomo%20%E2%89%A5%201.19-7c3aed)
![Platform](https://img.shields.io/badge/Platform-Box%20%7C%20Nikki%20%7C%20OpenClash-ec4899)
![Mode](https://img.shields.io/badge/Mode-Offline%20%2F%20Termux-22c55e)

</div>

---

## 📖 Daftar Isi

- [Kenapa Hikari?](#-kenapa-hikari)
- [Fitur](#-fitur)
- [Cara Kerja](#-cara-kerja)
- [Instalasi](#-instalasi)
- [Struktur Folder](#-struktur-folder)
- [Cara Pakai](#-cara-pakai)
- [Miscellaneous (Menu 7)](#-miscellaneous-menu-7)
- [Memasang Hasil ke Perangkat](#-memasang-hasil-ke-perangkat)
- [Perbedaan Output per Platform](#-perbedaan-output-per-platform)
- [Isi Template & Group](#-isi-template--group)
- [Ruleset](#-ruleset)
- [Tips & Trik](#-tips--trik)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Roadmap](#-roadmap)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 💡 Kenapa Hikari?

Ngatur config Mihomo di tiga platform itu ribet: port beda, path beda, fitur Android (tun, per-app) bentrok dengan OpenWrt, dan hampir semua tool convert butuh internet. Hikari /.CLASH menyelesaikannya dengan:

- **Satu template netral**, bagian yang beda per platform disuntik otomatis.
- **Offline**: tempel link, jadi config. Tanpa subscription converter online.
- **Validator bawaan**: salah referensi group/rule/provider ketahuan *sebelum* config dipasang.

---

## ✨ Fitur

| | |
|---|---|
| 🔄 **Dua arah** | `vless://` `vmess://` `trojan://` ⇄ YAML Clash. Support WS, gRPC, HTTPUpgrade, H2, TLS, **Reality + flow/fingerprint**, ALPN, `allowInsecure`, IPv6 |
| 🎯 **Preview & edit** | Tabel preview, hapus/tambah node, baris gagal ditampilkan **lengkap dengan alasannya** |
| 🧬 **Anti duplikat** | Nama node kembar otomatis jadi `Nama (2)`, `Nama (3)` |
| 🦊 **Emoji otomatis** | Tiap node diawali emoji acak: `Singapore` → `🦊 Singapore`. Daftar emoji bisa diedit di menu |
| 🛠️ **Auto-patch platform** | Port, DNS listen, `tun`, path provider, controller, rule WIFI disesuaikan per platform |
| ✅ **Validator** | Cek group/rule/provider, file provider, port bentrok, controller tanpa secret, DNS rawan, dll |
| 🔌 **Mode Offline** | Ubah semua rule-provider `http` → `file` (tanpa update GitHub) |
| ➕ **Replace / Append** | Timpa atau tambah node ke provider yang sudah ada |
| 🌐 **Menu DNS** | Preset (Cloudflare+Google, Quad9, NextDNS, AdGuard, [BebasDNS](https://github.com/bebasid/bebasdns)) dengan pilihan **DoH / DoT / DoQ**, atau **custom manual** (IP, DoH, DoH3, DoT, DoQ, UDP/TCP, `system`, `dhcp://`, akhiran `#proxy`) per field — divalidasi, ada preview diff, format & komentar template dijaga |
| 🧰 **Tools ruleset** | Padatkan `port-games.yaml` (23.366 baris → 87 range, perilaku identik) |
| 🧪 **Miscellaneous** | Converter rule-provider `.mrs` ⇄ `.yaml`/`.txt`, tester config (+ `mihomo -t`), tester node (offline / via core), tester route — lihat [menu 7](#-miscellaneous-menu-7) |
| 🛡️ **Aman** | Auto-backup `.bak`, input divalidasi, `PermissionError` ditangani, pilihan secret dashboard (default `hikari` / acak) |

---

## 🧠 Cara Kerja

```mermaid
flowchart LR
    A[Link URI<br/>vless / vmess / trojan] --> B[hikari_converter.py]
    T[template/config_v0.5.yaml<br/>template netral] --> B
    R[ruleset/] --> B
    B --> P{Pilih platform}
    P --> X[📱 Box<br/>hasil/full_config_box/]
    P --> Y[🐧 Nikki<br/>hasil/full_config_nikki/]
    P --> Z[🐧 OpenClash<br/>hasil/full_config_openclash/]
    X --> V[✅ Validator]
    Y --> V
    Z --> V
```

Pipeline: `template → parse YAML → patch per platform → validasi → tulis config.yaml`.

---

## 📦 Instalasi

**Termux (Android):**

```bash
pkg update && pkg install python git -y
pip install pyyaml
termux-setup-storage          # izinkan akses penyimpanan
```

**Linux / OpenWrt / PC:**

```bash
pip install pyyaml            # butuh Python 3.8+
```

**Opsional — konversi `.mrs`** (menu 7 → 1) butuh kompresi zstd. Python 3.14+ sudah bawaan; selain itu pasang salah satu: `pkg install zstd` (Termux), `pip install zstandard`, atau `opkg install libzstd zstd` (OpenWrt). Cek statusnya di menu `7 → 5`.

**Ambil project:**

```bash
git clone https://github.com/nexterade/crispy-funicular.git hikari-clash
cd hikari-clash
```

> Di Termux, taruh foldernya di `/storage/emulated/0/Documents/hikari-clash` — **jangan** di `~` biar tidak kena `PermissionError` dan gampang diakses file manager.

---

## 📂 Struktur Folder

```text
hikari-clash/
├── hikari_converter.py          # Script utama (menu & generator)
├── banner.py                    # Banner Hikari /.CLASH
├── mrs_codec.py                 # Codec rule-set .mrs ⇄ .yaml/.txt   (menu 7)
├── nodetest.py                  # Tester node proxy                  (menu 7)
├── routetest.py                 # Tester route domain/IP             (menu 7)
├── template/
│   ├── config_v0.5.yaml         # Template master terbaru (netral platform, DNS BebasDNS)
│   ├── config_v0.4.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.3.yaml         # Template master lama (dibiarkan utuh)
│   └── template.yaml            # (otomatis) salinan kerja, dibuat saat kamu edit lewat menu
├── emoji.json                   # Daftar emoji nama node (edit lewat menu atau langsung di file)
├── settings.json                # (otomatis, tidak di-commit) pengaturan pengguna: profil ISP
├── ruleset/                     # Ruleset (WAJIB): *.yaml & *.mrs
├── archive/                     # Template lama v0.1/v0.2 + port-games versi penuh
├── tests/                       # Tes otomatis: python3 -m unittest discover -s tests
├── AUDIT.md                     # Perbandingan template, temuan audit, saran
└── hasil/                       # (otomatis) hasil generate
    ├── full_config_box/
    ├── full_config_nikki/
    ├── full_config_openclash/
    └── rules/                   # hasil Rule-Provider Converter (menu 7)
```

Template yang dipakai: **`template/template.yaml`** bila ada, kalau tidak **`template/config_v*.yaml` terbaru**. Edit lewat menu selalu mengubah `template/template.yaml`; template master tidak pernah disentuh. Template baru ditambahkan sebagai file baru (`config_v0.5.yaml`, dst.), versi lama tidak ditimpa.

> Upgrade dari layout lama? Saat dijalankan, script otomatis memindahkan `Hasil/` → `hasil/` dan `template.yaml` (root) → `template/template.yaml`.

---

## 🚀 Cara Pakai

```bash
cd /storage/emulated/0/Documents/hikari-clash
python hikari_converter.py
```

### Menu utama

```text
[1] Convert                 ← link ⇄ Clash YAML
[2] Edit Configuration      ← port & secret, ganti template, DNS, emoji node
[3] Check Status            ← template, provider, config yang sudah jadi
[4] Validasi / Audit Config ← cek template untuk ketiga platform
[5] Tools Ruleset           ← padatkan port-games.yaml
[6] Exit
[7] Miscellaneous         ← converter .mrs, tester config / node / route
```

### Alur Convert (URI ➜ Clash)

1. **Paste** link (`vless://` / `vmess://` / `trojan://`), satu per baris. Enter 2× untuk selesai.
2. **Preview**: lihat daftar node. Aksi: `[T]` tambah · `[H]` hapus (mis. `1,3`) · `[L]` lanjut · `[B]` batal.
   Baris yang gagal ditampilkan beserta alasannya (UUID kosong, transport belum didukung, dll).
3. **Pilih platform**: `B` Box · `N` Nikki · `O` OpenClash.
4. **Pilih provider**: `active.yaml` atau `trial.yaml`. Jika sudah berisi node, pilih **Ganti** atau **Tambahkan**.
5. **Mode rule-provider**: ikuti template (auto-update GitHub) atau **Offline** (file lokal saja).
6. **Secret dashboard**: `[1]` ikuti template (default: `hikari`) atau `[2]` acak.
7. Selesai. Script menampilkan lokasi hasil, hasil validasi, dan secret yang dipakai.

### Convert Clash ➜ URI

Menu `1 → 2`: paste YAML, atau pilih file provider hasil generate. Hasil bisa disimpan ke `hasil/URI_<tanggal>.txt`.

### Edit Configuration

- **Port & Secret**: ketik `acak` pada Secret untuk generate otomatis. Port divalidasi 1–65535.
- **Ganti Template**: pilih dari `template/config_v*.yaml` yang ada, atau path file sendiri (divalidasi sebelum dipakai).
- **DNS & Nameserver** (`2 → 3`): lihat isi tiap field beserta jenisnya (`[DoH]`, `[DoT]`, `[UDP]`, …), lalu:
  - **Preset** — urutan: **BebasDNS (default)**, Cloudflare+Google, Quad9, NextDNS, AdGuard. Pilih provider + protokol (DoH/DoT/DoQ; DoQ hanya di provider yang menyediakannya). **BebasDNS** punya 4 varian: Bawaan, Security (anti-malware), Unfiltered, Family — hanya DoH/DoT, dan karena BebasDNS tidak punya IP polos publik, field IP-nya diisi 1.1.1.1 & 8.8.8.8. Memilih BebasDNS otomatis mengisi `nameserver` = BebasDNS dan `fallback` = Cloudflare + Google. `nameserver`/`fallback` diisi alamat terenkripsi, sedangkan `default-`/`proxy-server-`/`direct-nameserver` diisi IP polos dari provider yang sama.
  - **Custom manual** — pilih field target (boleh beberapa, mis. `1,3`), lalu ketik entri bebas format, satu per baris atau pisah koma. Contoh: `1.1.1.1`, `8.8.8.8:53`, `https://dns.google/dns-query`, `tls://1.1.1.1`, `quic://dns.adguard-dns.com`, `tcp://1.1.1.1`, `system`, `dhcp://wlan0`, `https://1.1.1.1/dns-query#NamaGroup`. Mode **Ganti** atau **Tambahkan**.
  - **Kembalikan ke master** — salin nilai DNS dari template master terbaru.
  - **Profil ISP** — lihat [DNS leak & provider XL Axiata](#-tips--trik).
  - Aturan per field: `default-nameserver` **harus IP** (ditolak kalau bukan); `nameserver`/`fallback` diperingatkan kalau tidak terenkripsi; `proxy-server-nameserver` diperingatkan kalau terenkripsi semua. Selalu ada preview `-`/`+` dan konfirmasi sebelum menulis, plus backup `.bak`.
- **Emoji Node**: lihat daftar emoji, `[A]` tambah, `[H]` hapus (nomor), `[T]` nyalakan/matikan, `[R]` reset ke bawaan. Tersimpan di `emoji.json`.

---

## 🧪 Miscellaneous (Menu 7)

Kumpulan tools tambahan. Semuanya offline; yang butuh sesuatu dari luar (core Mihomo, zstd) bilang jelas kalau belum ada.

| Submenu | Fungsi | Catatan |
|---|---|---|
| **1. Rule-Provider Converter** | `.mrs` ⇄ `.yaml` / `.txt`. Arah otomatis dari ekstensi; ada mode batch (semua `.mrs` di `ruleset/` → YAML) dan info `.mrs` | Hasil di `hasil/rules/`. Perlu backend zstd (lihat [Instalasi](#-instalasi)). `domain` sudah diuji: hasil tulis identik (setelah dekompresi) dengan `blocker.mrs` & `plus18.mrs`; `ipcidr` belum diuji dengan file asli → cek dengan core sebelum dipakai |
| **2. Config Tester** | Validator internal untuk config hasil generate + `mihomo -t` kalau core ketemu (PATH, lokasi umum Box/OpenClash, atau env `HIKARI_MIHOMO`) | Juga menjalankan **audit DNS leak statis** (DNS ISP / tak terenkripsi di nameserver & fallback, respect-rules, fake-ip, IPv6). Tes core untuk Nikki dilewati di luar perangkat Nikki (path-nya absolut `/etc/nikki/run`) |
| **3. Proxy Node Tester** | **Offline**: DNS → TCP → TLS ke server node. **Via core**: delay sungguhan lewat `external-controller` | Offline hanya menjawab "server terjangkau dari jaringan ini?", bukan "proxy tembus ke internet?". Node UDP (hysteria/tuic) dilewati. Node hidup bisa disimpan ke `hasil/nodes_ok_*.yaml` |
| **4. Route Tester** | Ketik domain/IP (`chatgpt.com`, `1.1.1.1:443`, `udp://x.com:443`) → rule & group yang kena | Tanpa DNS lookup; rule `GEOIP`/`SRC-*`/`PROCESS-*` ditandai "tidak bisa dievaluasi", tidak ditebak |
| **5. Info Lingkungan** | Versi Python/PyYAML, backend zstd, lokasi core, template aktif | Berguna untuk debugging |

---

## 📲 Memasang Hasil ke Perangkat

Semua hasil ada di folder `hasil/`.

### 📱 Box for Root → `hasil/full_config_box/`

Salin **semua isi folder** ke:

```text
/data/adb/box/clash/
```

### 🐧 Nikki → `hasil/full_config_nikki/`

| Salin | Ke |
|---|---|
| `config.yaml` | `/etc/nikki/profiles/` |
| folder `proxy/` dan `ruleset/` | `/etc/nikki/run/` |

*Jangan dibalik — Nikki memisahkan profile dan file yang berjalan.*

### 🐧 OpenClash → `hasil/full_config_openclash/`

| Salin | Ke |
|---|---|
| `config.yaml` | `/etc/openclash/config/` |
| folder `proxy_provider/` dan `rule_provider/` | `/etc/openclash/` |

Pindahkan file ke OpenWrt pakai SFTP/WinSCP/scp, atau file manager yang punya akses root.

> ⚠️ **Nikki & OpenClash** umumnya menimpa port, DNS, TUN, controller, dan secret dari pengaturan LuCI-nya sendiri. Kalau dashboard minta secret, pakai yang diset di LuCI.

---

## 🔀 Perbedaan Output per Platform

| | 📱 Box | 🐧 Nikki | 🐧 OpenClash |
|---|---|---|---|
| Port | 7890 / 7891 / 7892 / **9797** / **9898** | dari template | dari template |
| DNS listen | **1053** | dari template | dari template |
| Blok `tun` | ada (off, dikelola Box) | dibuang | dibuang |
| `find-process-mode`, `geodata-mode`, `experimental`, `external-ui` | disuntik (`always`, `./dashboard`) | – | – |
| Group & rule **WIFI** | ada | **dibuang** | **dibuang** |
| Path provider | `./proxy`, `./ruleset` | `/etc/nikki/run/proxy`, `/etc/nikki/run/ruleset` | `./proxy_provider`, `./rule_provider` |
| `external-controller` | `127.0.0.1:9090` | `0.0.0.0:9090` | `0.0.0.0:9090` |

**Kenapa WIFI dibuang di OpenWrt?** Rule itu mencocokkan IP sumber `192.168.0.0/16`. Di router, *semua* client LAN punya IP itu, jadi seluruh trafik akan jatuh ke group WIFI (default Direct) dan proxy tidak pernah jalan.

---

## 🧩 Isi Template & Group

Urutan rule = prioritas (atas ke bawah):

| # | Rule-set | Group tujuan | Fungsi |
|---|---|---|---|
| 1 | `Direct` | DIRECT | LAN, `.local`, `.lan` |
| 2 | `DnsHijack` | 🐬 Hijack | DNS port 53 |
| 3 | `Reject` | ✂️ Reject | DoT (853) & QUIC (UDP 443) |
| 4 | `WifiClients` | 🍪 WIFI | Client WiFi/hotspot *(Box saja)* |
| 5 | `Blocker` | 💤 BLOCKER | Blokir iklan |
| 6 | `Plusplus` | 💕 PLUSPLUS | Unblock konten +18 |
| 7 | `Portgames` | 🪼 GAMING | Port game (default Direct) |
| 8 | `Inject` | 🧩 Inject | Google, Bing, DuckDuckGo |
| 9 | `SmartMode` | 🌳 SMART ROUTING | AI, game launcher, sosmed, ISP |
| – | `MATCH` | 🧩 Inject | Sisanya |

Group node: **🧩 Inject** (pusat), **🛸 AUTO MODE** (url-test), **👒 PROXY LIST** (pilih manual). Semua memakai provider `Active` + `Trial`. Nama group di tabel ini identik dengan `template/config_v0.5.yaml` — kalau kamu mengganti nama di template, ganti juga di `rules:` dan `proxies:` group yang mengacu ke nama itu.

---

## 📚 Ruleset

| File | Isi |
|---|---|
| `blocker.mrs` | Daftar iklan (domain, format mrs) |
| `plus18.mrs` | Daftar +18 (domain, format mrs) |
| `smartmode.yaml` | Domain/CIDR untuk SMART ROUTING |
| `inject.yaml` | Domain yang selalu lewat Inject |
| `direct.yaml` / `reject.yaml` / `dns-hijack.yaml` | Aturan dasar |
| `wifi.yaml` | Client WiFi (SRC-IP) |
| `port-games.yaml` | 87 range port game (versi penuh ada di `archive/`) |
| `fakeip-filter.yaml` | Domain yang di-resolve IP asli |
| `skip-sniff.yaml` / `force-sniff.yaml` | Daftar sniffer |

Rule-provider di template bertipe `http` (update tiap 24 jam dari GitHub); file di `ruleset/` dipakai sebagai cache awal. Mau 100% offline? Pilih **Mode Offline** saat generate.

---

## 🎒 Tips & Trik

**🔖 Alias Termux** — cukup ketik `hikari`:

```bash
echo 'alias hikari="cd /storage/emulated/0/Documents/hikari-clash && python hikari_converter.py"' >> ~/.bashrc
source ~/.bashrc
```

**📦 Active vs Trial** — `active.yaml` untuk node harian, `trial.yaml` untuk node yang lagi dicoba. Keduanya otomatis masuk **AUTO MODE** dan **PROXY LIST**.

**🦊 Emoji nama node** — tiap link yang di-convert dapat emoji acak (tidak berulang dalam satu batch selama daftarnya cukup). Edit lewat `2 → 4`, atau ubah langsung `emoji.json`. Nama yang sudah berawalan emoji (apa pun, mis. `🪟 Rekayasa` atau `🇸🇬 Singapore`) dibiarkan apa adanya, tidak jadi dobel, jadi aman dipakai bareng Append. Tambah emoji dengan spasi/koma sebagai pemisah, mis. `🦊 🐼 🐯`.

**➕ Pakai Append** — tambah node baru tanpa menghapus yang lama. Nama otomatis dijaga unik.

**🌐 Tips DNS (penting!)**

- **Default v0.5 (target: lolos dnsleak):** `nameserver` = **BebasDNS** (DoH), `fallback` = **Cloudflare + Google** (DoH), `fallback-filter.geoip: false`. Dengan `respect-rules` + `fake-ip`, query DNS keluar lewat proxy, jadi dnsleak test seharusnya hanya menampilkan resolver BebasDNS/Cloudflare/Google, bukan DNS ISP. Menu `7 → 2` memeriksa ini secara statis; verifikasi akhir tetap lewat dnsleaktest.com / bash.ws dari perangkat. (Catatan: Mihomo meng-query `fallback` bersamaan dengan `nameserver`, jadi **semua** isi keduanya harus non-ISP.)
- `fallback-filter.geoip: false` dipasang karena filter bawaan Mihomo (geoip CN) tidak relevan di Indonesia. Perilaku persisnya belum diuji di core asli; validator memperingatkan kalau `fallback` dipakai tanpa itu.
- **XL Axiata:** di jaringan XL, tunneling Nikki/OpenClash butuh DNS `112.215.203.254`. Pilih **Profil ISP → XL Axiata** (menu `2 → 3 → 4`, atau saat generate untuk Nikki/OpenClash). Script menyuntikkannya ke `default-nameserver` dan `proxy-server-nameserver` — hanya me-resolve host DoH & domain server proxy, **bukan** domain yang kamu buka, sehingga dnsleak tetap bersih. Template v0.2 dulu menaruhnya juga di `fallback`; kalau tunneling masih gagal, tambahkan `fallback` lewat menu yang sama — tapi DNS XL lalu akan terlihat di dnsleak (audit menandainya `LEAK`). Pengaturan tersimpan di `settings.json`; Box tidak diubah.
- `nameserver` (DoH) lewat proxy → aman dari reset ISP.
- `proxy-server-nameserver` & `direct-nameserver` sengaja **DNS polos** (`8.8.8.8`, `1.1.1.1`). Banyak ISP/modem **me-reset DoH** ke IP publik port 443; kalau itu dipakai untuk resolve domain server proxy, **semua node timeout**.
- Kalau `8.8.8.8` ikut diblok di jaringanmu, ganti ke DNS ISP lewat menu *DNS → Custom manual* (field `proxy-server-nameserver`) atau edit `template/template.yaml`.
- Preset hanya mengisi `proxy-server-nameserver` dengan IP polos; kalau kamu isi dengan DoH/DoT lewat Custom, menu dan validator akan memperingatkan.
- **BebasDNS** (`dns.bebasid.com`, MIT): kalau ISP/WiFi-mu memakai DPI dan memblokir domain DoH/DoT-nya, hubungi `dukungan@bebasid.com` untuk domain alternatif, lalu masukkan lewat *Custom manual*.
- Host DoH/DoT/DoQ berupa domain (mis. `dns.google`) di-resolve lewat `default-nameserver`, makanya field itu wajib IP.

**🔌 Mode Offline** — pilih saat generate kalau tidak mau ruleset berubah sendiri, atau GitHub raw sedang lambat/terblokir.

**🧪 Validasi dulu sebelum pasang** — menu `4` mengecek template untuk Box, Nikki, dan OpenClash sekaligus; menu `7 → 2` mengecek config hasil generate (dan menjalankan `mihomo -t` otomatis kalau core ada). Manual:

```bash
mihomo -t -d hasil/full_config_box -f hasil/full_config_box/config.yaml
```

**🔐 Secret dashboard** — default template: **`hikari`**. Setiap generate script menanyakan: ikuti template (`hikari`) atau acak. Mau secret tetap lain? Isi lewat menu `2 → 1` (ketik `acak` atau secret sendiri), tersimpan di `template/template.yaml`. ⚠️ `hikari` adalah secret yang mudah ditebak: di Box aman karena controller hanya `127.0.0.1`, tetapi di Nikki/OpenClash controller dibuka ke `0.0.0.0` — pakai secret acak/sendiri kalau jaringanmu dipakai orang lain. Di Nikki/OpenClash yang berlaku biasanya secret dari LuCI.

**🪵 Debug** — ubah `log-level: warning` jadi `debug` di `template/template.yaml`, generate ulang, lalu lihat tab *Logs* di dashboard.

**🧯 Backup** — setiap edit lewat menu membuat `template/template.yaml.bak`. Template master & `archive/` aman untuk rollback.

**🎮 Rule GAMING** — `port-games.yaml` mencocokkan port TCP+UDP. Kalau ingin hanya UDP, ubah entri jadi `AND,((NETWORK,UDP),(DST-PORT,5000-5221))`.

**🗜️ Padatkan port-games** — menu `5 → 1`. File 395 KB jadi ±2 KB dengan hasil routing identik.

---

## 🔧 Troubleshooting

| Gejala | Penyebab | Solusi |
|---|---|---|
| Semua node *timed out*; log: `dns resolve failed ... connection reset by peer` | DoH ke 8.8.8.8 / 1.1.1.1 :443 di-reset ISP, domain server proxy tidak ter-resolve | `proxy-server-nameserver` pakai DNS polos (default template sekarang). Cek: `nslookup domain-server-mu 8.8.8.8` |
| Di OpenWrt semua trafik Direct | Rule WIFI ikut ke router | Pakai script v3 / template v0.3+ (WIFI otomatis dibuang) |
| Node Reality/Vision tidak konek | Parser lama membuang `flow` & `fp` | Script v3 membawa `flow`, `client-fingerprint`, `pbk`, `sid` |
| `PermissionError` | Folder di `~` Termux | Pindah ke `/storage/emulated/0/...` setelah `termux-setup-storage` |
| `PyYAML belum terpasang` | Library belum ada | `pip install pyyaml` |
| Dashboard minta secret | Secret default `hikari`, acak, atau dari LuCI | Lihat ringkasan setelah generate; di Nikki/OpenClash pakai secret dari LuCI |
| Emoji node tidak sesuai `emoji.json` | JSON rusak (mis. koma berlebih di akhir) | Script sekarang memberi peringatan saat start & di Check Status; perbaiki filenya atau Reset lewat menu `2 → 4 → R` |
| Port bentrok / core gagal start | Dua port sama | Menu `4` (Validasi) menunjukkan port ganda |
| Rule-provider gagal download | GitHub raw lambat/terblokir | Mode Offline, atau pakai `proxy:` pada provider |
| `transport 'xhttp' belum didukung` | Transport belum ada di parser | Pakai node dengan ws/grpc/tcp, atau tambahkan manual di YAML |
| Provider kosong bikin error di core tertentu | `trial.yaml` berisi `proxies: []` | Isi minimal 1 node |

---

## ❓ FAQ

**Apa bedanya `template/template.yaml` dan `template/config_v0.5.yaml`?**
Yang kedua master. `template.yaml` salinan kerja yang dibuat otomatis saat kamu edit lewat menu. Kalau `template.yaml` ada, dialah yang dipakai — jadi setelah ada master baru, ganti lewat `2 → 2` (Check Status akan memberi tahu kalau salinan kerjamu tertinggal).

**Apa bedanya template v0.5 dengan v0.4?**
Hanya DNS: `nameserver` jadi BebasDNS, `fallback` Cloudflare+Google dengan `fallback-filter.geoip: false`, supaya lolos dnsleak. Profil ISP (XL Axiata) disuntik script, bukan ditaruh di template. v0.4 tetap ada. *Catatan: `template/template.yaml` salinan kerjamu tidak ikut berubah — pakai `2 → 2` untuk pindah ke v0.5 atau `2 → 3 → 3` untuk menyalin DNS-nya saja.*

**Apa bedanya template v0.4 dengan v0.3?**
Isinya sama, tetapi v0.4 benar-benar netral: blok khusus Box (`tun`, `find-process-mode`, `geodata-mode`, `experimental`, `external-ui`) dipindah dari template ke overlay Box di `hikari_converter.py`. v0.3 tetap ada untuk rollback.

**Kenapa nama proyeknya berubah?**
Rebranding dari *Hikari Subclash* / Hikari-SC menjadi **Hikari /.CLASH**. Nama file script (`hikari_converter.py`) dan URL GitHub (icon/ruleset) sengaja tidak diubah supaya config lama tidak rusak.

**Komentar di config hasil generate kok hilang?**
Hasil generate adalah dump YAML. Komentar tetap ada di template sumber.

**Bisa dipakai untuk protokol lain (SS, Hysteria2, TUIC)?**
Belum; lihat [Roadmap](#-roadmap). Edit manual di file provider tetap valid.

**Port Box harus sama dengan `settings.ini`?**
Ya. Default 9797 (redir), 9898 (tproxy), dns 1053 mengikuti varian Box yang dipakai di v0.1. Sesuaikan jika Box-mu berbeda.

**Kenapa `skip-cert-verify` selalu `true`?**
Kebanyakan node memakai bug-host/SNI custom sehingga sertifikat tidak cocok. Kalau link mengandung `allowInsecure=0`, nilainya dihormati.

**Mau tahu apa saja yang diubah dari v0.1/v0.2?**
Lihat [`AUDIT.md`](AUDIT.md): perbandingan, daftar temuan, dan koreksi.

---

## 🗺️ Roadmap

- [x] Tester config + `mihomo -t` lokal (menu 7 → 2) · [ ] Uji otomatis dengan core asli di CI
- [ ] Overlay platform sebagai file (`platforms/*.yaml`), bukan di dalam kode
- [ ] Protokol: `ss://`, `hy2://`, TUIC, `xhttp`
- [ ] Mode non-interaktif (`--platform nikki --input nodes.txt --offline`)
- [ ] Impor subscription URL + filter/rename node + group per negara
- [ ] Mirror CDN untuk rule-provider
- [ ] Rule GAMING khusus UDP & dipecah per game

Detail dan alasannya ada di bagian *Saran Pengembangan* pada [`AUDIT.md`](AUDIT.md).

---

## ⚠️ Disclaimer

Proyek ini dibuat untuk mempermudah pengelolaan konfigurasi pribadi. Pastikan penggunaanmu mematuhi hukum dan peraturan yang berlaku di wilayahmu terkait jaringan proxy/VPN. Penulis tidak bertanggung jawab atas penyalahgunaan.

*Don't be stupid, use it wisely.* 🫰

<div align="center">

Hikari /.CLASH · Made with 🌸 for Box · Nikki · OpenClash

</div>
