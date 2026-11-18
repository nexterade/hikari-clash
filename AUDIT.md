# HIKARI /.CLASH — Perbandingan, Audit & Saran (v0.1 → v0.2 → v0.3 → v0.4)

> Dulu bernama Hikari Subclash / Hikari-SC. Bagian 1–5 ditulis sebelum rebranding dan tetap memakai istilah lama; ringkasan perubahan terbaru ada di **bagian 6**.

Tanggal audit: 2026-11-16. Scope: `config-template-v0.1`, `config-template-v0.2`, `hikari_converter.py`, folder `ruleset/`.

> **Batasan verifikasi.** Sandbox tidak punya core `mihomo`, jadi config **belum dijalankan di core/perangkat nyata**. Yang sudah diuji: parsing & round-trip URI, build 3 platform, validator, edit menu, dan kesetaraan hasil pemadatan port. Poin yang bergantung pada perilaku Nikki/OpenClash di perangkat ditandai **[perlu cek]**.

---

## 1. Perbandingan Template v0.1 vs v0.2

| Aspek | v0.1 (varian Box/BFR) | v0.2 |
|---|---|---|
| Target | Box for Root saja | Generik (port & DNS = default OpenClash: 7890–7895, dns 7874) |
| Port | 7890/7891/7892, redir 9797, tproxy 9898 | 7890/7891/7892/7893/7895 |
| Controller | `127.0.0.1:9090` + secret `hikari` + `external-ui` | **`0.0.0.0:9090`, secret kosong**, tanpa UI |
| Log | `warning` | `silent` |
| DNS | DoH-only, `respect-rules`, `proxy-server-nameserver`, `use-hosts`, tanpa fallback | UDP polos (8.8.8.8, 1.0.0.1), `fallback`, **IP DNS ISP `112.215.203.254`**, tanpa `respect-rules` |
| Blok Android | `tun` (off), `find-process-mode: always`, `geodata-*`, `experimental`, `geox-url` | semua dihapus |
| Rule-provider | `type: file` (lokal), Blocker dari zxc-rv | **semua `type: http`** ke repo `nexterade/crispy-funicular` |
| Group | 7 | 8 (+ **🪼 GAMING**) |
| Rule | tanpa game | + `Portgames` (rule-set 23.366 `DST-PORT`) |
| Nama group | 🔥 AUTO MODE, 👻 PROXY LIST, ✨, 🛑, 🔞, 📶 | 🦈, 🍋‍🟩, 🌳, 💤, 💕, 🪺 |
| Marker `AUTO-PROXIES` | ada | hilang (script memang tidak memakainya) |

**Kesimpulan:** v0.2 bergerak ke template generik + auto-update, tapi **menjatuhkan** hampir semua yang membuat v0.1 aman di Android (controller loopback+secret, DoH-only, tun/find-process) dan membawa tiga regresi (lihat temuan T1–T3).

---

## 2. Temuan Audit

### Template (v0.2)

| # | Sev. | Temuan | Dampak | Status v0.3 |
|---|---|---|---|---|
| T1 | 🔴 | `external-controller: 0.0.0.0:9090` + `secret: ''` | API terbuka tanpa auth ke LAN/hotspot (bisa ganti node, baca koneksi) | Default `127.0.0.1`; script membuka `0.0.0.0` hanya di OpenWrt; secret default `hikari` (bisa diganti lewat menu atau dipilih acak saat generate) — validator memberi peringatan bila terbuka ke LAN tanpa secret. *Lihat bagian 6: keputusan default secret.* |
| T2 | 🔴 | Rule `WifiClients` (`SRC-IP-CIDR,192.168.0.0/16`) ada di semua platform | Di OpenWrt **semua** client LAN ber-IP 192.168.x.x → seluruh trafik jatuh ke group WIFI (default Direct) → proxy/blocker/inject tidak pernah jalan. `wifi.yaml` sendiri menulis "khusus Box mode tproxy" | Script membuang rule+group+provider WIFI untuk Nikki/OpenClash |
| T3 | 🟠 | DNS: UDP:53 polos, `fallback` tanpa `fallback-filter`, IP DNS ISP, `respect-rules` hilang | Kebocoran DNS ke ISP, tidak portable (IP ISP tertentu), mundur dari klaim "DoH only / Anti-Leak" di v0.1 | DoH-only + `respect-rules` + `proxy-server-nameserver`; bootstrap IP polos hanya untuk resolve host DoH |
| T4 | 🟠 | Template dipakai "apa adanya" di Box, padahal port-nya bukan port Box (redir 7892/tproxy 7895 vs 9797/9898; dns 7874 vs 1053) | Iptables/tproxy Box tidak menemukan port yang diharapkan **[perlu cek: tergantung `settings.ini` Box-mu]** | Overlay Box menyuntik port 9797/9898, dns 1053, blok tun, `find-process-mode` |
| T5 | 🟠 | `Portgames`: 23.366 baris `DST-PORT` satuan (395 KB), memuat 5228 (Google Play/FCM), 8888, 5432, 5353 dan range 50000–65535 | 23 ribu rule harus di-parse tiap start di HP/router kecil (bobot belum diukur di perangkat), 395 KB file untuk isi yang setara 87 range | Dipadatkan jadi **87 range / 2 KB**, port set identik (diverifikasi). Lihat saran S3 untuk isi range-nya |
| T6 | 🟡 | 11 provider `http` tanpa `interval`; `Portgames` tanpa `format` | Tidak pernah auto-update walau type `http` | Semua `interval: 86400`, `format: yaml` |
| T7 | 🟡 | `type: http` menimpa file lokal dari GitHub; klaim "OFFLINE" tidak benar jika repo berubah/terblokir | Ruleset bisa berbeda dari yang di-copy script | Opsi **Mode Offline** (http → file) di menu |
| T8 | 🟡 | `log-level: silent` | Susah troubleshooting | `warning` |
| T9 | ⚪ | Emoji `🍋‍🟩` adalah urutan ZWJ (Unicode 15.1) | Bisa tampil `🍋`+`🟩` di Android/terminal lama | Tidak diubah (kosmetik) — opsional ganti `🍋` |

### Script `hikari_converter.py` (v1)

| # | Sev. | Temuan (semua direproduksi) | Status v2 |
|---|---|---|---|
| S1 | 🔴 | Parser VLESS **membuang `flow` & `fp`** → node Reality/Vision tidak bisa konek | `flow`, `client-fingerprint`, `alpn`, `allowInsecure` dibaca; Reality default fp `chrome`, wajib `pbk` |
| S2 | 🔴 | Patch OpenWrt "enable tun" pakai regex rapuh dan **tidak bekerja** pada v0.2 (tidak ada blok `tun`); di tempat lain bila aktif justru bentrok dengan firewall Nikki/OpenClash; juga membuang `redir/tproxy` tanpa alasan kuat | Pipeline berbasis YAML: tun dibuang di OpenWrt, port dibiarkan |
| S3 | 🔴 | Rule WIFI ikut ke OpenWrt (lihat T2) | Dibuang otomatis + divalidasi |
| S4 | 🟠 | `Hasil/proxy` tidak pernah terisi → menu *Clash→URI dari file* & *Status* **selalu kosong** | Memindai `Hasil/full_config_*/proxy*/` |
| S5 | 🟠 | Nama node duplikat lolos → core menolak/menimpa | `dedupe_names` (`Nama (2)`), juga terhadap nama bawaan template |
| S6 | 🟠 | Password trojan tetap ter-encode (`%40`); `:` di password memotong | `unquote` pada userinfo; di sisi URI di-`quote` |
| S7 | 🟠 | Menu DNS: `default-nameserver` **selalu ditimpa** walau jawab "n" (prompt bootstrap tak berfungsi); preset "Quad9 Unsecured" sebenarnya `dns.quad9.net` (secured/filtered); preset AdGuard dicampur Google (memecah filter) | Bootstrap hanya berubah jika "y"; `dns10.quad9.net`; AdGuard murni |
| S8 | 🟠 | Path relatif ke cwd (`template.yaml`) tapi output relatif ke script; README menjanjikan anti-`PermissionError` tapi tidak ada penanganannya | Semua path relatif ke script; `PermissionError` ditangani dengan pesan |
| S9 | 🟡 | Input tidak valid ditelan diam-diam (`except: pass`) | Ditampilkan per baris + alasan |
| S10 | 🟡 | Edit port tanpa validasi (bisa menulis `abc`); secret dengan `'` merusak YAML | Validasi 1–65535, quote aman, backup `.bak`, YAML dicek sebelum simpan |
| S11 | 🟡 | `vless` memuat `cipher: auto` (tidak valid); `host=` selalu ditambah di URI walau TCP; vmess grpc/h2 tidak dibangun; IPv6 tanpa `[ ]` | Dirapikan; round-trip diuji termasuk IPv6 |
| S12 | 🟡 | Transport tak dikenal (mis. `xhttp`) menghasilkan node rusak diam-diam | Error jelas: "transport 'xhttp' belum didukung" |
| S13 | ⚪ | `skip-cert-verify: true` hard-coded | Tetap default `True` (bug-host/SNI custom lazim) tapi `allowInsecure=0` dihormati; konstanta `DEFAULT_SKIP_CERT_VERIFY` |

---

## 3. Perubahan di v0.3

- `config-template-v0.3.yaml`: template netral (basis v0.2 + perbaikan T1, T3, T6, T7, T8; fitur v0.1 yang tetap berguna: `respect-rules`, `tcp-concurrent`, `geox-url`, dll.).
- `hikari_converter.py` v2: pipeline `template → YAML → patch platform → validasi → dump`; semua temuan S1–S12.
- `ruleset/port-games.yaml`: dipadatkan (asli di `archive/port-games.full.yaml`).
- Menu baru: **Validasi/Audit**, **Tools Ruleset**, mode **Offline**, **Replace/Append**.

**Trade-off yang perlu kamu tahu**
1. Config hasil generate adalah dump YAML → **komentar template tidak ikut** (diganti header). Template sumber tetap utuh dengan komentar.
2. DNS default kembali DoH-only. Kalau kamu sengaja memakai DNS ISP demi latensi, set lewat menu DNS → Custom (atau edit `template.yaml`).
3. Boot pertama dengan `respect-rules` butuh proxy hidup untuk query DoH domain non-direct; resolve host server proxy lewat `proxy-server-nameserver` (langsung), sama seperti v0.1.

**Asumsi [perlu cek di perangkat]**
- Nikki & OpenClash menimpa `port/socks/redir/tproxy/mixed`, `dns.listen`, `tun`, `external-controller`, `secret` dari setting LuCI. Karena itu port di template dibiarkan dan `tun` dibuang. Dokumentasi Nikki yang bisa kubaca hanya mengonfirmasi mixin untuk `dns/sniff/hosts` dan "berbagai port"; detail `tun`/controller belum terverifikasi.
- Path Nikki `/etc/nikki/run/{proxy,ruleset}` & OpenClash `./proxy_provider`, `./rule_provider` dipertahankan dari script lama.
- Range di `DST-PORT` (`5000-5221`) didukung mihomo — terkonfirmasi di [wiki MetaCubeX](https://wiki.metacubex.one/en/handbook/syntax) (Port Ranges: `-`, pemisah `/` atau `,`).
- Port Box 9797/9898/1053 diambil dari v0.1; samakan dengan `settings.ini` Box-mu.
- Provider kosong `proxies: []` (file `trial.yaml` saat belum diisi) dipertahankan dari v1; kalau core-mu menolak, isi minimal 1 node.

---

## 4. Saran Pengembangan (urut manfaat/biaya)

1. **Uji dengan core asli di CI.** GitHub Action: `mihomo -t -d . -f config.yaml` untuk 3 output platform + `pytest` round-trip parser. Menangkap regresi sebelum sampai ke HP/router. Core juga punya `mihomo convert-ruleset` untuk meng-generate `.mrs` dari yaml otomatis saat rilis ruleset.
2. **Overlay platform sebagai file, bukan kode.** Pindahkan `BOX_TOP_LEVEL`, `BOX_TUN`, dll. ke `platforms/box.yaml`, `nikki.yaml`, `openclash.yaml` — bisa diedit tanpa menyentuh Python dan mudah ditambah platform baru (mis. Mihomo Party, Clash Verge, Sing-box-converter).
3. **Rapikan `Portgames`.** (a) batasi ke UDP: `AND,((NETWORK,UDP),(DST-PORT,5000-5221))` agar TCP 5228 (FCM/Google Play) tidak ikut ke GAMING; (b) tinjau range 50000–65535 — terlalu lebar, menangkap port acak; (c) pecah per game agar bisa on/off.
4. **Mode non-interaktif.** `argparse`: `--platform nikki --input nodes.txt --target active --offline --out DIR` + `--check`. Memungkinkan cron/CI dan integrasi dengan skrip lain.
5. **Protokol tambahan:** Shadowsocks (`ss://`), Hysteria2 (`hy2://`, bagus untuk game UDP), TUIC, dan `xhttp` bila core stabil. Parser sekarang sengaja menolak yang belum didukung.
6. **Impor subscription.** Fetch URL (saat online) → parse base64/Clash → merge ke provider; plus rename/filter node (regex negara), dedupe berdasar `server+port+uuid`, dan group otomatis per negara (`filter:` pada proxy-group).
7. **Mirror rule-provider.** Tambah fallback CDN (mis. jsDelivr) untuk URL GitHub raw yang kadang lambat/terblokir di beberapa ISP, atau `proxy:` seragam untuk semua provider http.
8. **Versi & migrasi template.** Tambah `# template-version: 0.3` + pengecekan di script ("template.yaml lebih tua dari master — merge?") agar edit lokal tidak ketinggalan.
9. **Keamanan Box.** ~~Hindari secret default yang bisa ditebak (`hikari`)~~ — *diputuskan tetap `hikari` sebagai default (lihat bagian 6)*; bundel dashboard (zashboard/metacubexd) per platform di folder `ui/` masih terbuka.
10. **Pengecekan konflik ruleset.** Validator tingkat lanjut: entri `Skip-Sniff` vs `Force-Sniff` yang saling tumpang tindih, entri `IP-CIDR` tanpa `no-resolve`, domain tidak valid di rule-set `behavior: domain`.

---

## 5. Koreksi pasca-uji lapangan (2026-11-16)

**Gejala:** semua node timeout ("0 succeeded, 4 timed out"); log: `dns resolve failed ... https://dns.google:443/dns-query ... connection reset by peer` saat resolve domain server proxy.
**Penyebab:** v0.3 awal memakai DoH untuk `proxy-server-nameserver`. Jaringan/ISP me-reset DoH ke 8.8.8.8 & 1.1.1.1 :443 → domain server proxy tak bisa di-resolve. Ini kesalahan audit: DNS polos di v0.2 ternyata punya alasan.
**Perbaikan:** `proxy-server-nameserver` dan `direct-nameserver` = DNS polos (8.8.8.8, 1.1.1.1); `nameserver` tetap DoH (lewat proxy). Validator kini memberi peringatan bila `proxy-server-nameserver` DoH semua. Menu DNS tidak lagi menerapkan DoH ke `proxy-server-nameserver` secara default.

**Update:** auto-generate secret dihapus. Setelah input URI, script menanyakan secret dashboard: ikuti template (default `hikari`) atau acak.

---

## 6. Update v0.4 / script v3 (2026-11-17)

Tindak lanjut temuan audit + permintaan pemilik proyek.

| Item | Status | Keterangan |
|---|---|---|
| `emoji.json` invalid (trailing comma) → daftar 22 emoji tidak pernah terpakai | ✅ Selesai | File diperbaiki; `DEFAULT_EMOJIS` di script kini **identik** dengan isi `emoji.json` (22 emoji; tes memastikan keduanya sinkron). Loader tidak lagi diam-diam: koma berlebih ditoleransi dan JSON rusak memunculkan peringatan saat start & di Check Status |
| Secret tidak sesuai dokumentasi | ✅ Disinkronkan | **Keputusan: default tetap `hikari`.** README/AUDIT diperbarui (sebelumnya tertulis "kosong"); prompt secret saat generate menampilkan nilai template. **Risiko yang diterima:** di Nikki/OpenClash controller dibuka `0.0.0.0:9090`, dan `hikari` mudah ditebak. Validator sengaja tidak memberi peringatan untuk secret default (supaya hasil validasi tetap bersih sesuai keputusan); pakai opsi "Acak" bila jaringan dipakai orang lain |
| Template "netral" tapi berisi blok Box | ✅ Template **v0.4** | `tun`, `find-process-mode`, `geodata-mode`, `experimental`, `external-ui` dipindah ke overlay Box di script. `external-ui` kini tidak ikut ke Nikki/OpenClash. v0.3 **tidak ditimpa** (`template/config_v0.3.yaml`) |
| Lokasi template di root | ✅ Dipindah | `template/config_v*.yaml` (master) dan `template/template.yaml` (salinan kerja). Layout lama dimigrasi otomatis saat script dijalankan |
| `Hasil/` → `hasil/` | ✅ Selesai | Termasuk `.gitignore`, dokumentasi, dan migrasi otomatis. Catatan: di filesystem case-sensitive (Android/Linux) kedua nama dianggap berbeda — jika dua-duanya ada, script memakai `hasil/` dan memberi peringatan |
| Nama group README ≠ template | ✅ Selesai | README mengikuti template (🍪 WIFI, 👒 PROXY LIST, 🛸 AUTO MODE); komentar `smartmode.yaml` & `wifi.yaml` ikut dibetulkan; tes otomatis menjaga sinkronisasi ini |
| `.gitignore` kurang | ✅ Selesai | `hasil/`, `template/template.yaml`, `*.bak` |
| Menu 7 Miscellaneous | ✅ Baru | Rule-Provider Converter, Config Tester, Proxy Node Tester, Route Tester, Info Lingkungan (modul `mrs_codec.py`, `nodetest.py`, `routetest.py`) |
| Banner & rebranding | ✅ Selesai | `banner.py` dipakai untuk semua layar; nama tampilan "Hikari /.CLASH". Nama file `hikari_converter.py` dan URL GitHub tidak diubah |
| Tes otomatis | ✅ Awal | `tests/test_hikari.py` (stdlib `unittest`) — 18 tes: emoji, path, netralitas template, 3 platform bersih di validator, migrasi, round-trip `.mrs`, route & node tester |

**Masih terbuka (butuh keputusan pemilik):**
1. **URL rule-provider vs repo.** Semua rule-provider `type: http` menunjuk `nexterade/crispy-funicular` (branch `main`), sedangkan icon menunjuk `nexterade/Hikari-SC` (branch `master`). Perubahan ruleset yang hanya di-commit ke Hikari-SC **tidak** sampai ke perangkat. Belum diubah karena menentukan repo mana yang jadi sumber kebenaran.
2. **`Portgames`** masih memuat `50000-65535` dan `5224-5241` (menangkap TCP 5228/FCM) — lihat saran 3.
3. **Core asli belum diuji di lingkungan ini** (tidak ada binary `mihomo`). Menu 6 → 2 menjalankan `mihomo -t` otomatis bila core ada di mesinmu; hasilnya belum pernah diverifikasi terhadap Nikki/OpenClash sungguhan. `.mrs` bertipe `ipcidr` juga belum diuji dengan file asli (domain sudah).
4. Saran 2 (overlay platform sebagai file), 4 (mode non-interaktif), dan CI belum dikerjakan.

**Susulan (2026-11-18) — menu DNS & Nameserver.** Opsi "Custom manual" dulu hanya menerima URL DoH dan hanya menulis ke `nameserver`. Sekarang: preset dengan pilihan DoH/DoT/DoQ, custom bebas format (IP, DoH, DoH3, DoT, DoQ, UDP/TCP, `system`, `dhcp://`, akhiran `#…`) dengan validasi per entri, pilihan field target (`nameserver`, `proxy-server-nameserver`, `default-nameserver`, `direct-nameserver`, `fallback` bila ada), mode ganti/tambah, preview diff, verifikasi baca-ulang, dan reset ke master. `default-nameserver` non-IP ditolak. Aturan "harus IP" dan "DoH/DoT semua di proxy-server-nameserver berisiko" bersumber dari temuan di bagian 5 dan perilaku Mihomo yang diketahui; belum diuji di core asli.

**Preset BebasDNS (2026-11-18).** Ditambahkan dari <https://github.com/bebasid/bebasdns> (4 varian, DoH+DoT; endpoint diambil dari README repo tersebut). Tidak ada DoQ dan tidak ada IP polos publik (plain DNS hanya untuk range IP terdaftar), sehingga field berbasis IP memakai 1.1.1.1/8.8.8.8. Endpoint belum diuji koneksinya dari sandbox ini.

**Target lolos dnsleak + profil ISP (2026-11-18, template v0.5).**
- DNS default: `nameserver` BebasDNS (DoH), `fallback` Cloudflare + Google (DoH), `fallback-filter.geoip: false`. v0.4 tidak ditimpa.
- Dasar: dokumentasi Mihomo menyebut `fallback` di-query bersamaan dengan `nameserver`, sehingga semua resolver di kedua list harus non-ISP. Perilaku `geoip: false` **tidak terdokumentasi di sumber yang bisa saya baca** (default `geoip: true`, kode `CN`); dipakai karena filter CN tidak relevan di Indonesia — **belum diuji di core asli**.
- **XL Axiata:** `112.215.203.254` disuntik script (bukan di template) ke `default-nameserver` + `proxy-server-nameserver` hanya untuk Nikki/OpenClash, atas permintaan pemilik proyek. Pilihan field ini adalah **asumsi saya**: template v0.2 menaruhnya di `default-nameserver` dan `fallback`, tapi `fallback` ikut menjawab query domain biasa, jadi di v0.5 dikecualikan secara default agar dnsleak bersih. Kalau di lapangan tunneling XL ternyata butuh `fallback`, aktifkan lewat menu (konsekuensi: DNS XL terlihat di dnsleak).
- Alat baru: audit DNS leak statis (`dns_leak_audit`) di Misc → Config Tester; validator memperingatkan `fallback` tanpa `fallback-filter`. Ini analisis config, **bukan** pengganti dnsleaktest.com dari perangkat.
- Nikki/OpenClash umumnya menimpa DNS dari setting LuCI; config ini hanya default.

**Susulan (2026-11-18) — hasil dnscheck.tools & template v0.6.**
- Temuan dari tes nyata di Nikki (XL): daftar resolver DNS bersih (tidak ada resolver XL), tabel DNSSEC FAIL semua (diharapkan — Mihomo tidak memvalidasi DNSSEC dan `fake-ip` selalu menjawab; analisis, bukan diuji di core), **tetapi IP XL asli ikut muncul di "Your IP addresses"**.
- Kandidat penyebab yang ditemukan di config: UDP port STUN (`19302`) cocok `Portgames` (16999-20100) → 🪼 GAMING → pilihan pertama 🎮 Direct. **Belum dikonfirmasi** sebagai satu-satunya jalur; pemilik perlu memeriksa koneksi DIRECT di dashboard saat tes.
- Perbaikan: **template v0.6** (v0.5 tidak ditimpa) menambah dua rule inline STUN/TURN → 🧩 Inject sebelum `Portgames`. Konsekuensi: WebRTC/panggilan via STUN lewat proxy, butuh node dengan dukungan UDP.
- Bug Route Tester diperbaiki: rule logika inline (`AND/OR/NOT,(...),GROUP`) dulu tidak pernah dievaluasi, sehingga hasilnya menyesatkan untuk rule di `rules:` (hanya yang di dalam rule-set yang dievaluasi). Rule STUN baru memang ketahuan lewat ini.
- Config Nikki yang dikirim masih memuat `geodata-mode`, `experimental`, `external-ui` karena dibuat dari salinan kerja turunan v0.3 oleh zip sebelumnya; build Nikki/OpenClash kini membuang key khusus Box itu dari template mana pun dan memberi catatan. Saat generate, script juga memberi peringatan bila `template.yaml` lebih tua dari master. Menu DNS bisa membuat `fallback` + `fallback-filter` bila belum ada di template.
- Tes: 40 (stdlib `unittest`).

**Susulan (2026-11-18) — template v0.7 & Mode Anti-Blokir.**
- Tujuan pemilik: menembus Internet Positif. Config Nikki yang diuji pemilik (nameserver Cloudflare DoH + `+.dnscheck.tools` di fake-ip-filter) membuat DNSSEC P-384/Ed25519 PASS; P-256 ERR dan MLDSA44 FAIL* (tidak dipakai sebagai ukuran, DNSSEC bukan soal sensor).
- Celah yang ditemukan di config: `proxy-server-nameserver` dan `direct-nameserver` berisi UDP polos port 53 lewat jalur DIRECT — bisa dibelokkan ISP (hipotesis; **belum diuji di jaringan XL**). **Template v0.7** (v0.6 tidak ditimpa) mengubahnya jadi DoH berbasis IP, `nameserver` jadi Cloudflare DoH, tanpa entri dnscheck. Menu DNS `[5] Mode Anti-Blokir` menerapkan hal yang sama ke template kerja; `dns_leak_audit` kini memberi WARN untuk DNS polos di dua field itu (IP XL yang disuntik dikecualikan) dan INFO untuk risiko DoH-only pada `proxy-server-nameserver`. Peringatan validator lama untuk `proxy-server-nameserver` DoH-semua dipindah menjadi INFO karena sekarang disengaja.
- **Risiko:** kalau ISP me-reset DoH ke 1.1.1.1/8.8.8.8, resolve host server node gagal (hanya relevan bila node memakai domain). Jalan keluar tercatat di template, README, dan menu.
- **Temuan tes lapangan yang v0.7 TIDAK memperbaiki:** `pornhub.com` → Rule `Plusplus` → 💕 PLUSPLUS → 🧩 Inject → node `karin instagram`, hasilnya `ERR_CONNECTION_CLOSED`, UL 1,92 kB / DL 0 B, *Remote address* `124.158.117.211`. Rutenya benar (lewat proxy, bukan DIRECT). Dugaan saya (belum diverifikasi): *Remote address* itu IP server node, dan berada di Indonesia, sehingga server node yang menutup koneksi (resolve/egress di sisi server). Cara memastikan: pilih node di luar negeri untuk grup yang sama dan ulangi; atau periksa lokasi IP tersebut.
- Tes: 48 (stdlib `unittest`); alur menu `2 → 3 → 5` diuji end-to-end lewat stdin pada salinan kerja turunan v0.6.

**Susulan (2026-11-19) — v0.8, Regenerate, menu, screenshot.**
- **Link repo:** template **v0.8** memindahkan semua URL rule-provider (dulu `nexterade/crispy-funicular`, `main`) dan icon (dulu `nexterade/Hikari-SC`, `master`) ke `nexterade/hikari-clash`, branch `main`. Ini sekaligus menutup temuan #1 di atas (dua repo berbeda sebagai sumber). **Belum diverifikasi:** nama branch (`main` adalah asumsi) dan keberadaan folder `ruleset/` & `icon/` di repo baru — akses jaringan sesi ini ke GitHub dibatasi. Kalau salah, rule-provider tidak terunduh dan icon kosong. v0.3–v0.7 dan `archive/` tidak diubah (masih repo lama).
- **Regenerate (`1 → 3`):** membangun ulang config dari `proxy/active.yaml`/`trial.yaml` yang sudah ada (satu sumber atau semua). Alur pilih-platform/target dari Convert diekstrak jadi `_generate_and_report` dan dipakai bersama. Catatan: opsi `[A]` memakai pilihan baku (rule-provider/secret ikut template, ISP dari `settings.json`) — pilihan non-baku sebelumnya (Offline, secret acak) tidak diingat.
- **Menu utama:** Miscellaneous jadi `[6]` (komentar dihapus), Exit pindah ke baris terpisah dengan `[Q]`; `6`/`7` lama tidak lagi berarti Exit/Misc. README dan referensi "menu 7" disesuaikan.
- **Screenshot** di `docs/img/` (5 gambar). IP server node dan kolom Server disensor sebelum masuk repo. Keterangan hasil (ad-block 96%, DNSSEC) hanya berlaku untuk satu perangkat/jaringan.
- Pengamatan dari screenshot: resolver yang tampil di dnscheck.tools adalah `ns3.nusa.net.id` (Indonesia), konsisten dengan dugaan bahwa jalur keluar node berada di Indonesia — **belum diverifikasi**.
