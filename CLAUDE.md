# Aturan kerja untuk Claude (dan kontributor) di repo ini

File ini dibaca otomatis oleh Claude Code. Aturan di bawah **wajib** diikuti pada setiap perubahan.

## Version bump semantik (WAJIB, setiap perubahan)

Versi aplikasi memakai [Semantic Versioning](https://semver.org/lang/id/) `MAJOR.MINOR.PATCH`.
Sumber kebenarannya dua file: **`VERSION`** (satu baris, mis. `0.5.0`) dan **`CHANGELOG.md`**.

> Penomoran **template** (`template/config_v0.3.yaml` … `config_v1.3.yaml`, `docs/template-changelog.md`) adalah
> hal terpisah dan **tidak** ikut `VERSION`. Jangan dicampur.

### Pilih level bump

Selama masih `0.y.z` (belum rilis stabil), pakai konvensi pra-1.0:

| Level | Kapan | Contoh |
|---|---|---|
| **MINOR** `0.Y.0` (PATCH jadi 0) | Fitur baru, menu/opsi baru, file keluaran baru, perubahan perilaku yang terlihat pengguna, **atau perubahan yang tidak kompatibel** | mode Lazy, field Phantom, format YAML keluaran berubah |
| **PATCH** `0.y.Z` | Perbaikan bug, perbaikan teks/typo, perubahan dokumentasi atau tes saja, refaktor tanpa perubahan perilaku | memperbaiki crash parser, menambah tes |
| **MAJOR** `X.0.0` | Hanya saat pemilik repo menyatakan rilis stabil `1.0.0`. **Jangan** menaikkan MAJOR atas inisiatif sendiri | — |

Setelah `1.0.0` berlaku SemVer penuh: perubahan tidak kompatibel → MAJOR, fitur kompatibel → MINOR, perbaikan → PATCH.

Aturan pilih level:
- Satu rangkaian perubahan = **satu bump**. Ambil level tertinggi yang berlaku, lalu nol-kan angka di bawahnya
  (`0.4.3` + fitur → `0.5.0`, bukan `0.4.4`).
- **Tidak ada perubahan yang dikirim tanpa bump**, termasuk yang hanya dokumentasi atau tes (itu PATCH).
- Jangan pernah memakai ulang nomor yang sudah dirilis, dan jangan mengubah entri lama di `CHANGELOG.md`.
- Ragu antara MINOR dan PATCH → tanya pemilik repo, atau pilih MINOR kalau pengguna akan melihat bedanya.

### Langkah (urut)

1. Tentukan level bump dari tabel di atas.
2. Ubah **`VERSION`** (satu baris, tanpa awalan `v`).
3. Tambahkan entri baru **di paling atas** `CHANGELOG.md` (di bawah judul), format
   `## [X.Y.Z] - YYYY-MM-DD`, dengan subjudul `### Ditambahkan` / `### Diubah` / `### Diperbaiki` / `### Dihapus`
   (hanya yang dipakai). Tulis dari sudut pandang pengguna, bukan daftar file.
4. Perbarui dokumen yang tersentuh (`README.md`, `docs/*.md`, `docs/structure.md` bila ada file baru).
5. Jalankan tes: `python3 -m unittest discover -s tests`. `tests/test_version.py` gagal bila `VERSION`
   bukan SemVer valid atau tidak sama dengan entri teratas `CHANGELOG.md`.
6. Di balasan ke pengguna, sebut versi baru (mis. `0.4.0 → 0.5.0`) dan alasan levelnya. Kalau membuat zip, sertakan
   versi di pesan; folder dalam zip tetap `hikari-clash-master/`.

## Lain-lain

- Jalankan semua tes sebelum menyerahkan hasil; jangan menyerahkan kode yang tesnya merah.
- Bahasa dokumentasi dan pesan UI: Indonesia, ringkas.
- Jangan menaruh `__pycache__/`, `hasil/`, atau `template/template.yaml` ke dalam zip.
