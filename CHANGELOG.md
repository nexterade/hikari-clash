# Changelog

Versi aplikasi mengikuti [Semantic Versioning](https://semver.org/lang/id/); aturan bump ada di [CLAUDE.md](CLAUDE.md).
Penomoran template (`config_v*.yaml`) terpisah — lihat [docs/template-changelog.md](docs/template-changelog.md).

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
