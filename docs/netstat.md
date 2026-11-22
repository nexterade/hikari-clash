# 📊 Hikari NetStat

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Collector statistik trafik untuk Mihomo. Dia memantau `/connections` dari external-controller, menjumlahkan byte per hari, lalu menyajikannya sebagai laporan web. Kodenya ada di [`netstat/`](../netstat/) dan **tidak bergantung** pada config Hikari: tanpa `hikari.yaml`, tanpa ruleset, tanpa folder proxy.

## Fitur

- **Periode:** 30 hari terakhir (harian), 12 minggu (Senin–Minggu), 12 bulan, plus total sejak collector pertama jalan.
- **WiFi vs Data seluler**, dipisah berdasarkan IP sumber koneksi (lihat [Klasifikasi](#klasifikasi-wifi-vs-data)).
- **Top 8 per periode** untuk tiap dimensi: aplikasi (`proc`), group proxy terakhir di chain, dan jalur keluar (**Direct / Proxy / Reject / DNS**).
- **Wawasan pemakaian** per tab (harian/mingguan/bulanan): waktu aktif (menit/jam), jam tersibuk, grafik per jam, app & rute teratas, hari terboros. Semua bisa diklik untuk detail.
- **Info perangkat:** alamat IP, uptime collector & HP, penyimpanan `/data` (endpoint `/api/device`).
- **Bahasa:** tombol EN/ID di header (default English, pilihan disimpan di browser).
- **Batas data (kuota):** isi batas paket (GB), tanggal reset (1–28), dan yang dihitung (data / wifi / semua). Halaman menampilkan sisa, jatah per hari, dan perkiraan total akhir periode.
- Rekap: hari terboros, jumlah hari beruntun ada trafik.
- **Ekspor** CSV / JSON dan **impor** cadangan dari halaman laporan.

## Pasang (Android root, arm64)

Dari folder `netstat/` (atau dari zip `hikari-netstat` yang diextract), sebagai root:

```sh
sh install.sh                 # pasang / update, jalan otomatis tiap boot
sh install.sh uninstall       # copot (stats.json & stats.conf tetap disimpan)
```

Installer menaruh semuanya di `/data/adb/hikari-stats/`, membuat `stats.conf` dari contoh bila belum ada (izin `600`, karena bisa berisi secret), dan membuat `/data/adb/service.d/hikari-stats.sh` supaya collector start setelah boot selesai. Update tidak menimpa `stats.json` maupun `stats.conf`.

Sesudah pasang, isi **`SECRET`** di `stats.conf` lalu restart:

```sh
vi /data/adb/hikari-stats/stats.conf
sh /data/adb/hikari-stats/stats-ctl.sh restart
sh /data/adb/hikari-stats/stats-ctl.sh status
```

> **Upgrade dari versi lama** (yang di `/data/adb/box/stats` dan membaca `hikari.yaml`): installer menghentikan yang lama dan **menyalin** `stats.json`-nya ke folder baru; folder lama tidak dihapus. Default secret berubah dari `hikari` menjadi kosong, jadi di Box isi `SECRET="hikari"` (atau secret yang kamu pakai).

## Konfigurasi — `stats.conf`

Format shell `KEY="nilai"`. Contoh lengkap: [`netstat/stats.conf.example`](../netstat/stats.conf.example).

| Kunci | Default | Keterangan |
|---|---|---|
| `API` | `http://127.0.0.1:9090` | Alamat external-controller Mihomo. Kalau controller bind `0.0.0.0:9090`, tetap pakai `127.0.0.1` |
| `SECRET` | *(kosong)* | Secret controller; kosong = tanpa auth |
| `LISTEN` | `127.0.0.1:9099` | Alamat halaman laporan |
| `WIFI` | `192.168.0.0/16` | CIDR sumber yang dihitung WiFi, pisah koma |
| `TZ_NAME` | `Asia/Jakarta` | Zona waktu untuk batas hari/minggu/bulan |
| `INTERVAL` | `3s` | Jeda polling |

Env `STATS_API`, `STATS_SECRET`, `STATS_LISTEN`, `STATS_WIFI`, `STATS_TZ`, `STATS_INTERVAL` menimpa isi file.

**Mengikuti platform Hikari**

| | Box | Nikki / OpenClash |
|---|---|---|
| Controller | `127.0.0.1:9090` | `0.0.0.0:9090` (dari LuCI) |
| `SECRET` | Secret config Box (default template: `hikari`) | Secret yang diset di LuCI |
| Installer | `install.sh` | Tidak didukung (installer memakai `/data/adb` dan `getprop`) |

Di OpenWrt jalankan binary manual: `hikari-stats -api http://127.0.0.1:9090 -secret <secret> -data /path/stats.json -listen 127.0.0.1:9099` (butuh build untuk arsitektur router; lihat [Build](#build--tes)). Pemakaian di OpenWrt **belum diuji**, dan di router semua client LAN berIP `192.168.x.x`, jadi pemisahan WiFi/Data praktis tidak bermakna di sana: NetStat paling berguna di Android.

## Klasifikasi WiFi vs Data

Tiap koneksi diklasifikasi dari `metadata.sourceIP`:

| IP sumber | Masuk ke |
|---|---|
| Kosong / tidak valid / loopback (`127.x`, `::1`) | **Internal** (DNS, port proxy lokal), tidak dihitung ke total |
| Ada di salah satu CIDR `WIFI` | **WiFi** |
| Lainnya | **Data** seluler |

Default hanya `192.168.0.0/16`. Kalau HP-mu memakai subnet WiFi lain (mis. `10.0.0.0/8`, hotspot iPhone `172.20.10.0/28`), tambahkan di `WIFI`. Cek IP sumber sebenarnya di kolom *Source* pada dashboard Mihomo. Apakah IP sumber yang terlihat core sesuai jaringan aktif **bergantung mode Box-mu** (redirect/tproxy) **[perlu cek di perangkat]**.

## Cara kerja & akurasi

- Tiap `INTERVAL`, collector mengambil `/connections` dan menghitung **selisih** byte tiap koneksi sejak polling sebelumnya.
- Koneksi yang sudah menutup di antara dua polling tidak terlihat; selisihnya diambil dari counter global (`uploadTotal`/`downloadTotal`) dan dibagi proporsional ke WiFi/Data berdasarkan koneksi yang terlihat. Jadi **total akurat, pembagian per aplikasi/jaringan adalah perkiraan** (makin kecil `INTERVAL`, makin rapat).
- Core restart terdeteksi (counter global turun, atau muncul koneksi lama yang belum dikenal); polling berikutnya hanya menjadi baseline supaya tidak ada angka lonjakan palsu.
- Kalau entri per hari membengkak, hanya 40 teratas per dimensi per jaringan yang dipertahankan; sisanya digabung jadi `(lainnya)`.
- Data ditulis ke `stats.json` tiap 30 detik (dan saat berhenti). File rusak dipindah ke `stats.json.corrupt-<waktu>` dan collector mulai baru, tidak crash.

## Kontrol, backup, API

```sh
sh stats-ctl.sh start|stop|restart|status
```

Backup / pindah data lewat CLI (hentikan collector sebelum `-import`):

```sh
hikari-stats -data stats.json -export backup.json
hikari-stats -data stats.json -import backup.json -mode fill   # fill | add | replace
```

`fill` hanya mengisi hari yang kosong, `add` menjumlahkan, `replace` mengganti semua. Dari halaman laporan, tombol Ekspor/Impor memakai format yang sama.

| Endpoint | Metode | Fungsi |
|---|---|---|
| `/` | GET | Halaman laporan |
| `/api/summary` | GET | Ringkasan harian/mingguan/bulanan + status collector |
| `/api/live` | GET | Kecepatan & jumlah koneksi terakhir (belum dipakai halaman) |
| `/api/device` | GET | IP lokal, uptime collector/HP, penyimpanan |
| `/api/export.csv` · `/api/export.json` | GET | Ekspor data |
| `/api/health` | GET | `ok` |
| `/api/import?mode=` | POST | Impor cadangan |
| `/api/settings` | POST | Simpan batas data (`limitBytes`, `resetDay`, `net`) |

## Keamanan

- Default `LISTEN` hanya `127.0.0.1`: halaman hanya terbuka dari HP itu sendiri.
- Endpoint `POST` wajib header `X-Hikari` supaya halaman web lain tidak bisa mengirim form diam-diam ke collector.
- **Jangan** mengubah `LISTEN` ke `0.0.0.0` di jaringan yang dipakai orang lain: halaman tidak punya login, siapa pun di jaringan bisa melihat riwayat pemakaian dan menimpa data lewat impor.
- `stats.conf` dibuat `chmod 600` karena memuat secret controller.

## Build & tes

Butuh Go ≥ 1.22, tanpa dependensi eksternal.

```sh
cd netstat
sh build.sh test      # unit test, lalu build bin/hikari-stats (linux/arm64, static)
```

Untuk arsitektur lain, build manual dari `netstat/src`: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o hikari-stats .`

## Masalah umum

| Gejala | Penyebab | Solusi |
|---|---|---|
| Chip "Mihomo putus", error `HTTP 401 (secret salah?)` | `SECRET` di `stats.conf` beda dengan controller | Samakan, lalu `stats-ctl.sh restart` |
| Chip "Mihomo putus", error `connection refused` | Core belum jalan, atau `API` salah | Pastikan Box/core hidup dan port di `API` sama dengan `external-controller` |
| `gagal start, cek stats.log` | Port `LISTEN` dipakai proses lain (mis. versi lama masih jalan) | Ubah `LISTEN`, atau hentikan yang lama: `sh /data/adb/box/stats/stats-ctl.sh stop` |
| Angka WiFi/Data tidak sesuai | IP sumber di luar CIDR `WIFI` | Lihat kolom *Source* di dashboard, tambahkan CIDR-nya |
| Setelah reboot collector tidak jalan | Skrip `service.d` tidak dieksekusi oleh root manager-mu | Cek `/data/adb/service.d/hikari-stats.sh` (harus executable), atau jalankan `stats-ctl.sh start` manual |
