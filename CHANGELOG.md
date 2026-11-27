# Changelog

Versi aplikasi mengikuti [Semantic Versioning](https://semver.org/lang/id/); aturan bump ada di [CLAUDE.md](CLAUDE.md).
Penomoran template (`config_v*.yaml`) terpisah — lihat [docs/template-changelog.md](docs/template-changelog.md).

## [0.11.3] - 2026-11-27

### Diubah
- README: panduan instalasi disederhanakan jadi satu blok perintah per platform (tanpa komentar `#`), memakai `pip install -r requirements.txt`, plus perintah pembuat shortcut `hikari-clash`.

## [0.11.2] - 2026-11-27

### Diubah
- Panduan instalasi: di Termux, `git clone` langsung ke `/storage/emulated/0/Project/hikari-clash` (tanpa memindah manual dari `Documents`), plus catatan `cd` harus memakai `/` di depan dan solusi *dubious ownership*. Path contoh di `docs/usage.md` dan shortcut di `docs/tips.md` ikut disesuaikan.

## [0.11.1] - 2026-11-27

### Diubah
- README: banner `docs/img/banner.png` dipasang di bagian atas (menggantikan judul teks).
- README: bagian "📸 Tampilan" kini bisa dilipat (collapse), tertutup secara default.

## [0.11.0] - 2026-11-27

### Ditambahkan
- **Menu 6: Box Utilities** (Android berroot + Box for Root, lewat `su`): Start, Stop, Restart, Status rinci, Pasang config hasil generate,
  Ganti config aktif, Lihat/daftar config, Buka dashboard, Log, dan Update (`box.tool geox` / `subs` / `upkernel` / `upxui`).
  Setiap perubahan menampilkan perintah root-nya dan meminta persetujuan (default tidak). Dokumentasi: `docs/box.md`.
- **Pasang ke Box langsung dari hasil generate**: salin `<operator>.yaml`, `proxy/<operator>/`, dan `ruleset/` ke `/data/adb/box/clash/`
  (cadangan `.bak`; `free.yaml`/`subs.yaml` perangkat tidak ditimpa), lalu opsional jadikan aktif dan restart. Ditawarkan otomatis di akhir
  Convert/Regenerate untuk platform Box (hanya di Android dengan `su`).
- **Nama config bebas di Box**: config aktif dipilih lewat `name_clash_config` di `/data/adb/box/settings.ini` (diubah dengan cadangan
  `settings.ini.hikari.bak` dan diverifikasi ulang), jadi `xl.yaml` tidak perlu diganti jadi `config.yaml`.
- Peringatan bila `tproxy-port`/`redir-port` config beda dengan `settings.ini`.
- File baru: `boxutil.py`, `tests/test_box.py` (31 tes dengan "perangkat" tiruan), `tests/fixtures/box_settings.ini`.

### Diubah
- Petunjuk pasang Box di akhir generate dan `docs/platforms.md` mengarah ke Box Utilities (tidak lagi menyuruh mengganti nama jadi `config.yaml`).

### Batasan
- Belum diuji di perangkat/Box asli. Belum terbukti: format keluaran `box.service status`, arti `box.pid` untuk deteksi "berjalan",
  akses `su` ke `/data/media/0` (path `/storage/emulated/0` dipetakan ke sana), dan perilaku `termux-open-url`/`am start`.
- Folder tujuan memakai `/data/adb/box/clash/` (sesuai `clash_config` di settings.ini), bukan `/data/adb/clash/`.

## [0.10.0] - 2026-11-27

### Ditambahkan
- **Operator/ISP saat generate** (Convert & Regenerate): setelah memilih platform dan provider, kamu ditanya operator
  (xl, axis, smartfren, telkomsel, byu, indosat, three, atau nama sendiri). Config disimpan sebagai `<operator>.yaml`
  (`xl.yaml`, `byu.yaml`, …) — tidak lagi selalu `config.yaml`, jadi generate berikutnya tidak saling menimpa. Enter = operator
  terakhir (disimpan di `settings.json`).
- **Nama config sniffer**: Generate Config (Sniffer Only) menanyakan nama; `three` → `sniffer-three.yaml`, kosong → `config.yaml`.
- **Nama hasil sniffer**: sebelum menyimpan, Inspector Live dan Penangkap Path menanyakan nama; `instagram` →
  `instagram_<tanggal>_<jam>.csv/.json/.md` (log path: `instagram_path_<tanggal>_<jam>.*`). Kosong → `koneksi_…` / `path_…` seperti sebelumnya.
- **Daftar file hasil sniffer di Uji Bug** (Mode Lazy dan field biasa): tiap prompt kandidat menampilkan file di
  `hasil/sniffer/` yang bisa dipilih (boleh beberapa) dan digabung dengan kandidat yang ditempel. Hanya koneksi yang menerima data
  yang diambil (domain, IP, port, path sesuai field).
- **Emoji per metode node** menggantikan emoji acak: 🌠 asli, 🌌 CloudFront asli, 🎬 bug-sni, 💭 bug-addr, 🐬 ip-edge, ☕ sni-ip,
  🏞️ bug-addr-sni, 🏖️ ip-bug-sni, 🏙️ wildcard, 🌇 wildcard-sni, 🌁 host-bug, 🪲 host-bug-sni, 🧸 ganti-path. Metode dibaca dari tag
  nama varian Uji Bug. Menu Emoji Node kini mengubah emoji per metode.

### Diubah
- **Folder provider per operator**: `proxy/<operator>/active.yaml` dan `trial.yaml` (OpenClash: `proxy_provider/<operator>/`); path
  `proxy-providers` di dalam config ikut (`/proxy/xl/`, `/proxy/axis/`, …). `free.yaml` dan `subs.yaml` tetap bersama di `proxy/`.
  Layout lama (`proxy/active.yaml` + `config.yaml`) tetap terbaca dan bisa di-regenerate.
- **Profil ISP** pada alur generate digantikan pertanyaan operator: `xl` memasang DNS ISP XL (Nikki/OpenClash), operator lain tanpa DNS ISP.
- **Laporan Uji Bug** kini `report.json` (JSON berindent, kunci Indonesia, terbaca manusia) — menggantikan `report.txt`.
- **Regenerate** kini juga memberi emoji pada node yang belum berawalan emoji (mis. varian baru dari Uji Bug).
- `emoji.json` berformat `{"enabled", "methods"}`; format lama (`emojis: [...]`) diabaikan dengan peringatan.
- Status Full Config dan Config Tester menampilkan semua `<operator>.yaml`.

### Diperbaiki
- **Input asal tidak lagi diproses diam-diam** (mis. `x`, `e`, `g` pada Mode Rule-Provider/Secret/ISP dulu dianggap Enter): pilihan
  di alur generate, Regenerate, Uji Bug (node/field/mode/timeout/port), Sniffer, DNS, Rule-Provider Converter, dan konfirmasi y/n kini
  menolak jawaban di luar pilihan dan bertanya ulang.
- `[T]` Tambah node di Preview Convert menimpa daftar varian Uji Bug dengan teks sehingga bisa crash saat lanjut.
- Tes `test_operator_pref_overrides_detected_sim` (sysinfo) salah menganggap "XL Axiata" tidak boleh muncul di mana pun, padahal baris
  Lokasi memuat ISP dari lookup IP publik; kini hanya memeriksa baris Jaringan.

### Batasan
- Mapping emoji untuk metode yang tidak ada di daftar pemilik adalah dugaan: `wildcard-ip` → 🌇, `host-ip` → ☕, `http-*` mengikuti
  metode induknya, semua `path-*` → 🧸; tag `[port:…]`/`[alpn:…]`/`[fp:…]`/`[combo]` dianggap node asli. Metode `wildcard-sni` belum ada di
  Mode Lazy (hanya `wildcard` dan `wildcard-ip`). Semua bisa diubah di `emoji.json` / `EMOJI_METHOD_ALIAS`.
- Box membaca `config.yaml`? Tidak diverifikasi di perangkat; kalau ya, ganti nama `<operator>.yaml` saat memasang.
- Belum diuji di perangkat/core nyata; yang teruji: tes otomatis (alur menu dengan input terskrip).

## [0.9.0] - 2026-11-26

### Diperbaiki
- **Info Banner: operator salah di HP dual SIM** (mis. tampil `XL Axiata` padahal data memakai by.U). Sebelumnya hanya SIM slot
  pertama yang dibaca; sekarang semua SIM ditampilkan (`XL Axiata / by.U`).

### Ditambahkan
- Pengaturan **Operator** di `Misc > Info Banner` (juga env `HIKARI_OPERATOR`) untuk menetapkan nama operator secara manual.
  Pratinjau pindah ke `[8]`.

### Batasan
- Android tanpa root tidak memberi tahu SIM mana yang dipakai untuk data, jadi pilihan otomatis untuk dual SIM tidak mungkin
  pasti. Belum diuji di perangkat dual SIM sungguhan; yang teruji: tes dengan keluaran `getprop` tiruan.

## [0.8.0] - 2026-11-26

### Ditambahkan
- **Info pengguna di bawah banner** (`sysinfo.py`): IP (lokal + publik), lokasi + ISP, jaringan **WiFi / Data** (nama
  interface, operator), **status core** (`Status: Box Aktif` / `Nikki Aktif` / `OpenClash Aktif` / `... Tidak Aktif`),
  usage (hari ini dari NetStat; kalau NetStat tidak jalan: sesi core, lalu counter interface) dan info lain (versi core,
  mode, jumlah koneksi, uptime perangkat, ping). Menu utama menampilkan panel penuh; layar lain satu baris ringkas.
- Status core dibaca dari `external-controller` (lokal `127.0.0.1:9090`, lalu router di gateway `:9090` untuk kasus
  Termux di HP + Nikki di router), secret otomatis dari template. Tidak memakai `su`, jadi tidak memicu popup root.
- **Misc > [7] Info Banner**: ubah tampilan (full/compact/off), **sensor IP** (aman untuk screenshot), matikan lookup
  IP publik, paksa platform, alamat/secret controller. Env: `HIKARI_INFO`, `HIKARI_INFO_MASK`, `HIKARI_INFO_LOOKUP`,
  `HIKARI_PLATFORM`, `HIKARI_API`, `HIKARI_SECRET`, `HIKARI_STATS`. Lihat [docs/usage.md](docs/usage.md#info-di-bawah-banner).
- `python3 sysinfo.py` menampilkan panelnya saja (untuk uji cepat).

### Diubah
- `save_settings` tidak lagi menghapus kunci lain di `settings.json` (diperlukan agar pengaturan Info Banner dan profil ISP
  hidup berdampingan).
- Info banner mati otomatis kalau output bukan terminal (pipe, tes) kecuali `HIKARI_INFO` diisi.

### Batasan
- IP publik & lokasi memerlukan internet dan menghubungi `ipwho.is` (cadangan `ipinfo.io`); kalau Box aktif yang tampil
  adalah IP keluar (node). Matikan di Info Banner bila tidak mau.
- Label **Nikki/OpenClash untuk core di router** memakai heuristik halaman LuCI; kalau tidak yakin tampil `Mihomo Aktif`
  (atur Platform di Info Banner untuk memastikan). Belum diuji di perangkat Box/Nikki/OpenClash sungguhan; yang teruji:
  tes lokal dengan controller & NetStat tiruan. Di Android tanpa root sebagian sumber (`/proc`) bisa tidak terbaca →
  nilai tampil `-`.

## [0.7.0] - 2026-11-26

### Ditambahkan
- **Penangkap path HTTP** (`httpcatch.py`, "bug catcher"): proxy lokal yang mencatat **URL path**, metode, Host, User-Agent,
  status, **redirect (`Location`)**, Content-Type/Server dan petunjuk CDN dari HTTP polos, lalu meneruskan byte apa adanya
  (CONNECT maupun URL absolut; keep-alive; handshake TLS hanya dicatat SNI-nya). Mihomo sendiri tidak pernah melihat path.
  Menu baru **Sniffer Only > [4] Penangkap Path**, juga bisa dijalankan sendiri: `python3 httpcatch.py`.
- **Sniffer Only > Generate Config**: opsi *penangkap path* menambahkan proxy `🪤 Catcher` (http), group `🪤 HTTP Catcher`
  dan rule port HTTP polos (80, 8080, 8880, 2052, 2082, 2086, 2095) sebelum rule CDN, sehingga trafik Cloudflare/CloudFront
  ikut tertangkap.
- **Inspector Live** dapat menjalankan penangkap sekaligus; laporan `koneksi_<waktu>.md` mendapat bagian *Path HTTP tertangkap*
  dan **Kandidat bug berpath** (`host/path`) yang bisa langsung ditempel ke Uji Bug > Lazy. Rekaman mentah: `path_<waktu>.jsonl`.
  Lihat [docs/sniffer.md](docs/sniffer.md).

### Batasan
- Path HTTPS **tidak** ditangkap (tanpa MITM/sertifikat palsu); hanya host:port dan SNI. Config dan penangkap belum diuji
  dengan Box/Nikki/OpenClash di perangkat; yang teruji: tes lokal dengan origin tiruan.

## [0.6.0] - 2026-11-26

### Ditambahkan
- **Uji Bug (Lazy) — bug berpath**: bug yang ditulis dengan path (mis. `www.line.me/en`, `xlsmart.co.id/id`) otomatis
  memicu metode **ganti path** (node ws/h2/http): path node jadi awalan bug + path asli (`/en` + `/vless` → `/en/vless`;
  path `/` → `/en`). Metode baru: `path-bug-addr`, `path-bug-addr-sni`, `path-host-bug`, `path-host-bug-sni`, plus
  `http-path-bug-addr` dan `http-path-host-bug` untuk port tanpa TLS. Metode biasa tetap dicoba memakai domain bug-nya.
  Lihat [docs/bugtest.md](docs/bugtest.md).

### Diubah
- Input bug mode Lazy sekarang mempertahankan path (sebelumnya path dibuang). Scheme, port, query dan fragment tetap dibuang.
- Hasil Lazy menampilkan `path` pada kombinasi yang lolos; transport tanpa path (tcp/grpc) melewati metode ganti path dengan alasan.

## [0.5.0] - 2026-11-25

### Ditambahkan
- **Uji Bug — mode Lazy** (`[L]` di menu *Yang mau diuji*): isi bug saja, hikari-clash mencoba semua metode
  address / port / host / SNI otomatis (termasuk bug sebagai address, IP edge CDN, SNI/Host berupa IP, wildcard,
  injeksi Host; port 443 dan 80 secara bawaan) lalu menampilkan metode mana yang cocok. IP edge diambil dari node,
  hasil resolve domain server, dan input tambahan. Keluaran baru: `custom-lazy.yaml` dan bagian *Ringkasan metode Lazy*
  di `report.txt`. Lihat [docs/bugtest.md](docs/bugtest.md).
- **Uji Bug — field Phantom** (PhantomNG): kandidat bug diuji dengan SNI = bug dan Host = domain server, sertifikat
  diverifikasi terhadap domain server (mode TCP/TLS, dan V2Ray/Xray lewat `verifyPeerCertByName`). Link
  `sni=phantom:<server>:<bug>[:rand|:auto]` yang di-paste dinormalkan otomatis. Keluaran baru: `custom-phantom.yaml`
  dan `bug-ok-phantom-uri.txt`.
- `CHANGELOG.md`, `CLAUDE.md` (aturan version bump semantik), dan `tests/test_version.py` yang menegakkannya.

### Diubah
- Uji Bug: `phantom_verify` (opsi `test_variants`) dapat mematikan verifikasi sertifikat varian Phantom.

## [0.4.0]

Versi dasar sebelum changelog ini dibuat (tanpa catatan rinci).
