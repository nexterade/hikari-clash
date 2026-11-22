# ❓ FAQ

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

**Apa bedanya `template/template.yaml` dan `template/config_v1.3.yaml`?**
Yang kedua master. `template.yaml` salinan kerja yang dibuat otomatis saat kamu edit lewat menu. Kalau `template.yaml` ada, dialah yang dipakai — jadi setelah ada master baru, ganti lewat `2 → 2` (Check Status akan memberi tahu kalau salinan kerjamu tertinggal).

**Apa bedanya antar versi template (v0.3 sampai v1.3)?**
Rinciannya ada di [template-changelog.md](template-changelog.md).

**Kenapa nama proyeknya berubah?**
Rebranding dari *Hikari Subclash* / Hikari-SC menjadi **Hikari /.CLASH**. Nama file script (`hikari_converter.py`) tidak diubah. Repo sumber (icon/ruleset) pindah ke `nexterade/hikari-clash` mulai template v0.8; config lama yang dibuat dari v0.3–v0.7 tetap berjalan selama repo lamanya masih ada.

**Komentar di config hasil generate kok hilang?**
Hasil generate adalah dump YAML. Komentar tetap ada di template sumber.

**Bisa dipakai untuk protokol lain (SS, Hysteria2, TUIC)?**
Belum; lihat [Roadmap](../README.md#-roadmap). Edit manual di file provider tetap valid.

**Port Box harus sama dengan `settings.ini`?**
Ya. Default 9797 (redir), 9898 (tproxy), dns 1053 mengikuti varian Box yang dipakai di v0.1. Sesuaikan jika Box-mu berbeda.

**Kenapa `skip-cert-verify` selalu `true`?**
Kebanyakan node memakai bug-host/SNI custom sehingga sertifikat tidak cocok. Aturannya:
- Link tanpa `allowInsecure`/`insecure` → `true`.
- Link dengan `allowInsecure=1` → `true`.
- Link dengan `allowInsecure=0` / `insecure=0` → `false`, **kecuali** node memakai **SNI custom** (SNI beda dari `server` *dan* dari header `Host`/`host` ws-h2). Untuk node seperti itu tetap dipaksa `true`, karena sertifikat server memang tidak mungkin cocok dengan SNI bug, dan dengan `false` handshake TLS gagal sehingga node cuma timeout. Panel/generator link sering menulis `allowInsecure=0` secara default tanpa peduli SNI-nya.
- Node dengan SNI = server atau = Host (tanpa SNI bug) tetap menghormati `allowInsecure=0` (verifikasi sertifikat normal).

Aturan yang sama berlaku di `hikari_converter.py` dan `sub2yaml.py`, juga saat memuat ulang `active.yaml`/`trial.yaml` lama (regenerate): node lama dengan `skip-cert-verify: false` + SNI custom diperbaiki otomatis.

Catatan: heuristik ini juga membuat node CDN-fronting yang sertifikatnya sebenarnya valid untuk SNI-nya (server = IP, SNI = domain sendiri, dan Host berbeda) ikut dipaksa `true`. Kalau ingin verifikasi ketat untuk node tertentu, ubah manual di YAML hasil generate (jangan regenerate dari file lama, karena akan diperbaiki lagi).

**Mau tahu apa saja yang diubah dari v0.1/v0.2?**
Lihat [`AUDIT.md`](../AUDIT.md): perbandingan, daftar temuan, dan koreksi.
