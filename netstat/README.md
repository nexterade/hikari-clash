# Hikari NetStat (standalone)

Collector statistik trafik Mihomo: pemakaian harian / mingguan / bulanan, dipisah **WiFi vs Data seluler**,
plus top app, group, dan jalur keluar (Direct/Proxy/Reject). Data disimpan permanen di `stats.json`,
laporan HTML dibuka di `http://127.0.0.1:9099/`.

Versi ini **mandiri**: tidak butuh `hikari.yaml`, ruleset, folder proxy, atau folder `clash` Box.
Cukup Mihomo yang external-controller-nya bisa dijangkau.

## Pasang (root, Android arm64)

```sh
sh install.sh            # pasang / update, jalan otomatis tiap boot
vi /data/adb/hikari-stats/stats.conf    # isi SECRET kalau controller pakai secret
sh /data/adb/hikari-stats/stats-ctl.sh restart
```

Copot: `sh install.sh uninstall` (`stats.json` dan `stats.conf` tetap disimpan).

Kalau sebelumnya memakai versi lama di `/data/adb/box/stats`, installer menghentikannya dan
**menyalin** `stats.json`-nya ke folder baru (folder lama tidak dihapus).

## Konfigurasi — `stats.conf`

| Kunci | Default | Keterangan |
|---|---|---|
| `API` | `http://127.0.0.1:9090` | external-controller Mihomo |
| `SECRET` | *(kosong)* | secret controller; kosong = tanpa auth |
| `LISTEN` | `127.0.0.1:9099` | alamat halaman laporan |
| `WIFI` | `192.168.0.0/16` | CIDR sumber yang dihitung WiFi, pisah koma |
| `TZ_NAME` | `Asia/Jakarta` | zona waktu periode harian/mingguan/bulanan |
| `INTERVAL` | `3s` | jeda polling |

Env `STATS_API`, `STATS_SECRET`, `STATS_LISTEN`, `STATS_WIFI`, `STATS_TZ`, `STATS_INTERVAL`
menimpa isi file (berguna buat tes).

## Kontrol

```sh
sh stats-ctl.sh start|stop|restart|status
```

Backup/pindah data (collector harus berhenti saat import):

```sh
hikari-stats -data stats.json -export backup.json
hikari-stats -data stats.json -import backup.json -mode fill   # fill | add | replace
```

## Build ulang

Butuh Go ≥ 1.22, tanpa dependensi eksternal: `sh build.sh` (atau `sh build.sh test` untuk menjalankan unit test dulu).
Hasil: `bin/hikari-stats` (linux/arm64, static).

## Isi

```
install.sh  stats-ctl.sh  stats.conf.example  build.sh
bin/hikari-stats        binary arm64
src/                    kode Go + ui/index.html (di-embed ke binary) + tes
```

Catatan: halaman laporan hanya baca-tulis ke `stats.json`; tidak mengubah config Mihomo sama sekali.
