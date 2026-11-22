# ☘️ Free Node & sub2yaml

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

## Free node dari sub2yaml (☘️ FREE NODE)

Menu `1 → 4`. Mengisi `proxy/free.yaml` — provider `📄 Free` yang dipakai group **☘️ FREE NODE** — dari keluaran `sub2yaml`.

1. **Sumber**: pilih `[1]` untuk menjalankan `sub2yaml.py` langsung (menu & tampilannya sama dengan Hikari), atau `[2]` untuk memilih/mengetik path file YAML hasilnya (mis. `hasil/proxy/free.yaml`). `subscription.yaml` repo juga bisa dipilih sebagai contoh.
2. **Platform**: `B` Box · `N` Nikki · `O` OpenClash · `A` semua (default). Nama folder mengikuti platform: `proxy/` untuk Box & Nikki, `proxy_provider/` untuk OpenClash.
3. **Mode**: **Ganti** isi `free.yaml` (yang lama dibackup `.bak`) atau **Tambahkan**.
4. Node divalidasi: wajib punya `name`, `type`, `server`, `port` (yang tidak lengkap dibuang dan dilaporkan); nama yang bentrok dengan group template atau node di `active.yaml`/`trial.yaml` otomatis jadi `Nama (2)`. Emoji acak **tidak** ditambahkan (nama dari sub2yaml dipakai apa adanya).
5. `config.yaml` tidak perlu di-generate ulang. Restart core (atau update provider dari dashboard) supaya node baru terbaca. Generate/Regenerate berikutnya tidak menimpa `free.yaml`.

### sub2yaml.py

Bisa juga dijalankan sendiri: `python3 sub2yaml.py` (menu interaktif) atau lewat argumen (lihat `--help`).

```text
[1] Pilih source (file)                  ← pilih file di src/ (boleh gabungan)
[2] URL custom (base64)
[3] Tambah URL (gabungkan beberapa sumber)
[4] Ubah jumlah node free.yaml (0 = semua yang berhasil)
[5] Ubah folder output
[6] Ganti urutan (negara / ping)
[7] Edit config (SNI / Host / Address / dll)
[8] Update source                        ← unduh ulang src/*.txt dari URL aslinya
[Enter] Mulai    [0] Keluar
```

- **Source**: pertama kali jalan, node diambil dari file `.txt` di `src/` (`barry-far.txt`, `0xRadikal.txt`, `roosterkid.txt`; kalau `src/` kosong akan diunduh otomatis). Perbarui kapan saja lewat menu `[8]` atau `python3 sub2yaml.py --update-source`. File lama baru diganti kalau unduhan valid. Format yang dikenali: base64, daftar link polos, dan teks berhiasan seperti openproxylist (`🇩🇪 vless://… 85ms DE [ISP]` — bendera di depan dipakai untuk deteksi negara, keterangan di belakang dan baris website/donasi diabaikan, `&amp;` dinormalkan). File `.txt` lain yang kamu taruh di `src/` ikut muncul di menu `[1]`.
- **Output**: `hasil/proxy/` (`free.yaml`, `custom-*.yaml` bila Edit config diisi, `report.txt`). Path relatif selalu relatif ke folder script, bukan folder tempat kamu menjalankan.
- **Format YAML**: block style persis seperti `active.yaml` (tanpa `{}`/`[]` inline); nilai berisiko (angka-like, `true`/`null`, karakter khusus) otomatis diberi tanda kutip, dan keluaran dicek round-trip lewat PyYAML.
- **SNI custom**: node TLS dengan SNI beda dari `server` dan dari header Host otomatis diberi `skip-cert-verify: true` (juga bila link bilang `allowInsecure=0`/`insecure=0`), termasuk setelah Edit config mengganti SNI/Host. Tanpa ini node hidup bisa terbaca mati di URL-test karena sertifikat tidak cocok. Pilihan eksplisit `--insecure`/menu (y/n) tetap menang.
- **Validasi offline**: node yang pasti ditolak mihomo dibuang sebelum dites dan dicatat di `report.txt` (UUID bukan format UUID, reality `public-key`/`short-id` rusak, reality di network selain tcp/grpc/h2, `flow` di luar tcp, SNI/server mengandung spasi atau karakter terlarang). Ini berlaku juga di mode TCP-only.
- **Tes (URL-test mihomo wajib)**: tiap node dites lewat core Mihomo sungguhan (connect lewat node ke `gstatic generate_204`, lalu dikonfirmasi sekali lagi ke `cp.cloudflare.com`). Hanya node yang punya ping di kedua tes dan rata-rata ≤ `--max-ping` (default 3000 ms) yang masuk file. Core dicari otomatis (`./bin`, `~/.hikari-clash/bin`, `PATH`, `HIKARI_MIHOMO`, lokasi OpenClash) dan **diunduh otomatis** dari GitHub (MetaCubeX/mihomo) bila belum ada: varian sesuai perangkat (mis. `android-arm64`, lalu `linux-arm64`), unduhan bisa **dilanjutkan** kalau terputus (`bin/*.part`), dan dipakai hanya setelah terbukti bisa dijalankan (`mihomo -v`). Menu `[9]` = unduh/perbarui manual, `--no-download` mematikan unduh otomatis, `--mihomo /path` memakai core sendiri (core Box di `/data/adb` butuh root, jadi tidak dipakai otomatis). **Android/Termux:** kalau folder Hikari ada di penyimpanan bersama (mis. `/storage/emulated/0/Project/hikari-clash`), file di sana tidak boleh dieksekusi, jadi core otomatis dipasang di `~/.hikari-clash/bin/` (home Termux). Jumlah node bebas: `--top N` atau menu `[4]` — tes dikerjakan per batch dan berhenti begitu N node lolos. Tes TCP **bukan lagi cadangan otomatis** (hanya mengecek port terbuka, bukan berarti bisa dipakai); `--tcp-only` tetap ada tapi harus dipilih sengaja. Kalau hampir semua ping TCP ≤3 ms (koneksi dicegat Box/Nikki/VPN lokal), tahap TCP dilewati otomatis dan semua node langsung di-URL-test — sebaiknya matikan Box/VPN saat menjalankan sub2yaml.
