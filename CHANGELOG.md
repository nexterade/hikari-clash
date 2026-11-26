# Changelog

Versi aplikasi mengikuti [Semantic Versioning](https://semver.org/lang/id/); aturan bump ada di [CLAUDE.md](CLAUDE.md).
Penomoran template (`config_v*.yaml`) terpisah — lihat [docs/template-changelog.md](docs/template-changelog.md).

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
