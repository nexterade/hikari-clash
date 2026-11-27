# Box Utilities (menu 6)

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Mengendalikan modul **Box for Root** (BFR) langsung dari Hikari lewat `su`: start / stop / restart, pasang hasil generate, ganti config aktif, lihat config, buka dashboard, log, dan update. Hanya untuk Android yang sudah root dengan BFR terpasang (Termux + `su`). Di PC atau HP tanpa root, menu hanya menampilkan pesan.

## Aturan keselamatan

- **Persetujuan tiap perubahan.** Sebelum menjalankan apa pun yang mengubah perangkat, Hikari menampilkan perintah root-nya (`# su -c …`) dan bertanya `Setuju? (y/N)`. Default tidak. Jawaban asal ditolak.
- Popup izin root (Magisk / KernelSU / APatch) bisa muncul saat menu dibuka — itu dari manajer root-mu, bukan Hikari. Info banner (menu utama) tetap **tidak** memanggil `su`.
- Perintah berhenti di kegagalan pertama; rc dan keluarannya ditampilkan.
- `settings.ini` selalu dicadangkan ke `settings.ini.hikari.bak` sebelum diubah, dan hasilnya dibaca ulang untuk memastikan perubahannya benar.

## Yang dibaca dari `settings.ini`

Hikari membaca `/data/adb/box/settings.ini` (dari modul BFR) dan memakai: `box_dir`, `clash_config` (→ folder clash, default `/data/adb/box/clash/`), `name_clash_config`, `clash_provide_path` (folder provider, default `…/clash/proxy`), `bin_name`, `xclash_option`, `network_mode`, `tproxy_port`, `redir_port`, `box_pid`, `box_log`, `bin_log`. Baris array dan `$(…)` dilewati.

> Folder tujuan Box adalah `/data/adb/box/clash/` (sesuai `clash_config`), bukan `/data/adb/clash/`.

## Menu

| Menu | Fungsi | Perintah root |
|---|---|---|
| `[1]` Start | Jalankan Box | `box.service start` lalu `box.iptables enable` |
| `[2]` Stop | Hentikan Box | `box.iptables disable` lalu `box.service stop` |
| `[3]` Restart | Stop lalu Start | gabungan dua di atas |
| `[4]` Status rinci | Keluaran `box.service status` | `box.service status` |
| `[5]` Pasang config hasil generate | Salin `hasil/full_config_box/<operator>.yaml` + `proxy/<operator>/` + `ruleset/` ke Box | `mkdir`, `cp` |
| `[6]` Ganti config aktif | Pilih salah satu `*.yaml` di folder clash, ubah `name_clash_config` | `sed -i` pada `settings.ini` |
| `[7]` Lihat / daftar config | Daftar file (● = aktif), ringkasan (port, controller, secret, provider, jumlah group/rule), teks penuh bertahap | `cat` |
| `[8]` Buka dashboard | Tampilkan URL + secret dari config aktif, tawarkan `box.tool upxui` bila folder dashboard kosong, buka di browser | `test`, `cat` |
| `[9]` Log | 40 baris terakhir `runs.log` atau log core | `tail` |
| `[A]` Update | `box.tool geox` / `subs` / `upkernel` / `upxui` | `box.tool <x>` |

Baris status di atas menu: berjalan/berhenti (dari `box.pid`, cadangan `pidof <bin_name>`), core, mode, port, dan config aktif.

## Pasang config hasil generate

Tersedia dari menu `[5]`, dan otomatis ditawarkan di akhir **Convert/Regenerate** untuk platform Box (hanya di Android dengan `su`: `Pasang ke Box sekarang (root)?`).

1. Pilih hasil (`xl.yaml`, `byu.yaml`, …). Port `tproxy-port` / `redir-port` di config dibandingkan dengan `settings.ini`; beda → peringatan.
2. Hikari menyalin ke `/data/adb/box/clash/`:
   - `<operator>.yaml` (kalau sudah ada, yang lama dicadangkan `<operator>.yaml.bak`);
   - `proxy/<operator>/` → `clash_provide_path/<operator>/`;
   - `free.yaml`, `subs.yaml` hanya bila **belum ada** di perangkat (hasil update subscription tidak ditimpa);
   - `ruleset/` (digabung/ditimpa per file).
   `config.yaml` lama dan operator lain tidak disentuh.
3. Tawaran **jadikan aktif**: mengubah `name_clash_config="<operator>.yaml"` di `settings.ini`. Jadi nama file tidak harus `config.yaml`.
4. Kalau Box sedang berjalan: tawaran **Restart** (dokumentasi BFR menyarankan mengubah config saat Box berhenti). Kalau tidak: tawaran Start.

Path sumber di `/storage/emulated/0/…` atau `/sdcard/…` diubah ke `/data/media/0/…` untuk root (lokasi aslinya), supaya tidak bergantung pada mount namespace `su`.

## Batasan / belum terbukti di perangkat

- Seluruh logika dites dengan "perangkat" tiruan (folder sementara + `sh`), bukan Box asli. Yang **belum** diverifikasi: format keluaran `box.service status`, arti persis `box.pid` (dipakai untuk deteksi "berjalan"), akses `su` ke `/data/media/0`, dan perilaku `termux-open-url` / `am start`.
- URL dashboard `http://<controller>/ui/` mengikuti `external-ui` Mihomo; secret ditampilkan agar bisa diisi manual di dashboard.
- Hanya core Clash/Mihomo (`bin_name=clash`); core lain diberi peringatan.
- Belum ada: hapus config dari perangkat, edit `settings.ini` bebas, dan `box.tool reload`.
