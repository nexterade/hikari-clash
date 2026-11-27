# 🚀 Cara Pakai

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

```bash
cd /storage/emulated/0/Project/hikari-clash
python3 hikari_converter.py
```

## Menu utama

```text
[1] Convert                 ← link ⇄ Clash YAML, regenerate dari node tersimpan, impor free node (sub2yaml)
[2] Edit Configuration      ← port & secret, ganti template, DNS, emoji node
[3] Check Status            ← template, provider, config yang sudah jadi
[4] Validasi / Audit Config ← cek template untuk ketiga platform
[5] Miscellaneous           ← converter .mrs, tester config / node / route, sniffer only, info banner
[6] Box Utilities           ← (root) start/stop/restart Box, pasang & ganti config, dashboard, log
────────────────────────────
[Q] Exit
```

## Info di bawah banner

Menu utama menampilkan panel info perangkat tepat di bawah banner; layar lain memakai satu baris ringkas.

```text
  IP       : 192.168.1.23 lokal  ·  36.71.12.34 publik
  Lokasi   : Jakarta, ID · XL Axiata
  Jaringan : WiFi  (wlan0)
  Status   : Box Aktif
  Usage    : ↓ 1.2 GB  ↑ 340 MB  (hari ini)
             Data 840 MB  ·  WiFi 1.4 GB  ·  sisa 12.3 GB
  Etc      : mihomo v1.19.2  ·  mode rule  ·  42 koneksi
             uptime 3 jam 12 mnt  ·  ping 87 ms
```

| Baris | Sumber | Catatan |
|---|---|---|
| **IP** | IP lokal dari interface aktif; IP publik dari `ipwho.is` (cadangan `ipinfo.io`) | Kalau Box aktif, IP publik = IP **keluar** (node), bukan IP operator |
| **Lokasi** | Hasil lookup yang sama (kota, negara, ISP) | Butuh internet |
| **Jaringan** | Nama interface: `wlan*` → WiFi, `rmnet*`/`ccmni*` → Data, `eth*`/`br-*` → LAN | Operator seluler dari `getprop`. HP **dual SIM** menampilkan semua SIM (`XL Axiata / by.U`) karena Android tanpa root tidak memberi tahu SIM data; pastikan lewat pengaturan **Operator** |
| **Status** | `external-controller` Mihomo: `Box Aktif` / `Nikki Aktif` / `OpenClash Aktif`, atau `... Tidak Aktif` | Cek `127.0.0.1:9090` dulu, lalu router di gateway `:9090` (Termux di HP + Nikki di router). Secret dicoba otomatis dari template. Controller + secret dari config hasil generate terbaru dan dari Inspector Live (selama sesi) ikut dicoba |
| **Usage** | [NetStat](netstat.md) (hari ini, WiFi vs Data, sisa kuota) → bila tidak jalan: total sesi core → counter interface sejak boot | Sumbernya selalu ditulis di dalam kurung |
| **Etc** | Versi core, mode, jumlah koneksi, uptime perangkat, ping ke `cp.cloudflare.com` | Baris yang datanya tidak ada dilewati |

**Pengaturan** — `Miscellaneous → [7] Info Banner` (disimpan di `settings.json`, kunci `info`):

- **Tampilan** `full` / `compact` / `off`. Pilihan ini jadi batas atas: `compact` berarti menu utama pun satu baris.
- **Sensor IP**: `36.71.12.34` → `36.71.x.x`, lokasi hanya negara. Pakai sebelum screenshot.
- **IP publik+lokasi**: matikan kalau tidak mau script menghubungi layanan lookup (satu-satunya panggilan keluar dari fitur ini).
- **Operator**: isi nama operator (mis. `by.U`) kalau HP dual SIM dan deteksi otomatis menampilkan SIM yang salah.
- **Platform** (`auto` / `box` / `nikki` / `openclash`), **alamat controller** (mis. `192.168.1.1:9090`), dan **secret** — isi kalau deteksi otomatis salah.

Env yang setara (menimpa file): `HIKARI_INFO`, `HIKARI_INFO_MASK=1`, `HIKARI_INFO_LOOKUP=0`, `HIKARI_PLATFORM`, `HIKARI_API`, `HIKARI_SECRET`, `HIKARI_STATS`, `HIKARI_OPERATOR`.

Catatan: info otomatis mati kalau output bukan terminal (pipe/tes), data di-cache beberapa detik supaya menu tidak lambat, dan script **tidak pernah memanggil `su`**. Kalau lookup IP publik gagal, baris itu tampil `-` tanpa menunda menu lebih dari beberapa detik.

## Alur Convert (URI ➜ Clash)

1. **Paste** link (`vless://` / `vmess://` / `trojan://`), satu per baris. Enter 2× untuk selesai.
2. **Preview**: lihat daftar node. Aksi: `[T]` tambah · `[H]` hapus (mis. `1,3`) · `[U]` **uji bug/custom SNI·Host·Address** (banyak sekaligus, mode TCP/Mihomo/V2Ray — lihat [bugtest.md](bugtest.md)) · `[L]` lanjut · `[B]` batal.
   Baris yang gagal ditampilkan beserta alasannya (UUID kosong, transport belum didukung, dll). Varian yang lolos uji muncul sebagai baris `VARIAN` dan ikut diproses saat `[L]`.
3. **Pilih platform**: `B` Box · `N` Nikki · `O` OpenClash.
4. **Pilih provider**: `active.yaml` atau `trial.yaml`.
5. **Operator / ISP**: pilih `[1]` xl · `[2]` axis · `[3]` smartfren · `[4]` telkomsel · `[5]` byu · `[6]` indosat · `[7]` three, atau `[8]` ketik nama sendiri. Operator menentukan nama file dan folder provider:
   - config → `hasil/full_config_<platform>/<operator>.yaml` (mis. `xl.yaml`, `byu.yaml`) — **bukan** `config.yaml`, jadi tiap generate tidak saling menimpa;
   - provider node → `proxy/<operator>/active.yaml` (OpenClash: `proxy_provider/<operator>/`), dan path di dalam config otomatis ikut (`/proxy/xl/`, `/proxy/axis/`, `/proxy/smartfren/`, `/proxy/telkomsel/`, `/proxy/byu/`, `/proxy/indosat/`, `/proxy/three/`);
   - Enter = operator yang terakhir dipakai (tersimpan di `settings.json`); belum ada → wajib diisi;
   - `xl` otomatis memasang DNS ISP XL (Nikki/OpenClash); operator lain tanpa DNS ISP.
   Jika `<operator>/<provider>` sudah berisi node, pilih **Ganti** atau **Tambahkan**. `free.yaml` dan `subs.yaml` tetap bersama di `proxy/` (bukan per operator).
6. **Mode rule-provider**: ikuti template (auto-update GitHub) atau **Offline** (file lokal saja).
7. **Secret dashboard**: `[1]` ikuti template (default: `hikari`) atau `[2]` acak.
8. Selesai. Script menampilkan lokasi hasil, hasil validasi, dan secret yang dipakai.

> **Input asal ditolak.** Semua pilihan di alur ini memakai validasi: jawaban di luar pilihan (mis. `x`, `g`) menampilkan pesan dan ditanya ulang — tidak lagi diproses diam-diam sebagai Enter/default. Enter hanya berlaku di prompt yang menampilkan `Enter=...`.

## Regenerate dari node tersimpan

Menu `1 → 3`. Kamu mengubah template, DNS, profil ISP, emoji, atau secret dan ingin config baru **tanpa paste URI lagi**? Script membaca node dari `hasil/full_config_*/proxy*/<operator>/active.yaml` dan `trial.yaml` (juga layout lama `proxy/active.yaml`), lalu membangun ulang `<operator>.yaml` + ruleset dari template yang sedang aktif.

- **`[1]…[n]`** — pilih satu sumber (mis. `nikki/xl/active.yaml`, lengkap dengan jumlah node & waktu ubah). Operator dipakai dari folder asal (Enter), atau pilih operator lain untuk menyalin node ke sana. Enter = tetap di platform/provider yang sama, jadi file node-nya **tidak** ditanya timpa/tambah. Pilih platform lain untuk menyalin node ke sana (format node sama di semua platform).
- **`[A]`** — bangun ulang semua sumber sekaligus dengan pilihan baku: rule-provider & secret ikut template, operator dari folder asal masing-masing.
- Nama node dipakai apa adanya; hanya node yang **belum** berawalan emoji (mis. varian baru dari Uji Bug) yang diberi emoji sesuai metodenya. Node di provider lain tidak disentuh.
- Setelah memilih satu sumber ada aksi **`[U]` Uji bug / custom** (SNI · Host · Address) sebelum `[L]` Lanjut — varian yang lolos ditambahkan (atau mengganti node asli) lalu ikut ditulis ke provider. Lihat [bugtest.md](bugtest.md).

## Box Utilities

Menu utama `6` (Android berroot + Box for Root): start/stop/restart, pasang hasil generate ke `/data/adb/box/clash/`, ganti config aktif, lihat/daftar config, dashboard, log, update. Setiap perubahan meminta persetujuan. Rinci: [box.md](box.md).

## Free node (☘️ FREE NODE)

Menu `1 → 4` mengisi `proxy/free.yaml` — provider `📄 Free` yang dipakai group **☘️ FREE NODE** — dari keluaran `sub2yaml`. Langkah lengkap dan opsi `sub2yaml.py`: [sub2yaml.md](sub2yaml.md).

## Convert Clash ➜ URI

Menu `1 → 2`: paste YAML, atau pilih file provider hasil generate. Hasil bisa disimpan ke `hasil/URI_<tanggal>.txt`.

## Edit Configuration

- **Port & Secret**: ketik `acak` pada Secret untuk generate otomatis. Port divalidasi 1–65535.
- **Ganti Template**: pilih dari `template/config_v*.yaml` yang ada, atau path file sendiri (divalidasi sebelum dipakai).
- **DNS & Nameserver** (`2 → 3`): lihat isi tiap field beserta jenisnya (`[DoH]`, `[DoT]`, `[UDP]`, …), lalu:
  - **Preset** — urutan: **BebasDNS (default)**, Cloudflare+Google, Quad9, NextDNS, AdGuard. Pilih provider + protokol (DoH/DoT/DoQ; DoQ hanya di provider yang menyediakannya). **BebasDNS** punya 4 varian: Bawaan, Security (anti-malware), Unfiltered, Family — hanya DoH/DoT, dan karena BebasDNS tidak punya IP polos publik, field IP-nya diisi 1.1.1.1 & 8.8.8.8. Memilih BebasDNS otomatis mengisi `nameserver` = BebasDNS dan `fallback` = Cloudflare + Google. `nameserver`/`fallback` diisi alamat terenkripsi, sedangkan `default-`/`proxy-server-`/`direct-nameserver` diisi IP polos dari provider yang sama.
  - **Custom manual** — pilih field target (boleh beberapa, mis. `1,3`), lalu ketik entri bebas format, satu per baris atau pisah koma. Contoh: `1.1.1.1`, `8.8.8.8:53`, `https://dns.google/dns-query`, `tls://1.1.1.1`, `quic://dns.adguard-dns.com`, `tcp://1.1.1.1`, `system`, `dhcp://wlan0`, `https://1.1.1.1/dns-query#NamaGroup`. Mode **Ganti** atau **Tambahkan**.
  - **Kembalikan ke master** — salin nilai DNS dari template master terbaru.
  - **Profil ISP** — lihat [DNS leak & provider XL Axiata](tips.md).
  - **Mode Anti-Blokir** (`2 → 3 → 5`) — mengubah `nameserver`, `fallback`, `proxy-server-nameserver`, `direct-nameserver` jadi DoH berbasis IP (Cloudflare/Google), sehingga tidak ada query DNS polos port 53 yang bisa dibelokkan ISP. Pilihan `[2]` membiarkan `proxy-server-nameserver` apa adanya (kalau node timeout). Idempoten: kalau sudah sama, tidak mengubah apa-apa.
  - Aturan per field: `default-nameserver` **harus IP** (ditolak kalau bukan); `nameserver`/`fallback` diperingatkan kalau tidak terenkripsi; `proxy-server-nameserver` diperingatkan kalau terenkripsi semua. Selalu ada preview `-`/`+` dan konfirmasi sebelum menulis, plus backup `.bak`.
- **Emoji Node**: emoji **mengikuti metode node** (bukan acak). `[E]` ubah emoji satu metode (nomor + emoji baru), `[T]` nyalakan/matikan, `[R]` reset ke bawaan. Tersimpan di `emoji.json` (`{"enabled": true, "methods": {...}}`; format lama `emojis: [...]` diabaikan dengan peringatan).

  | Emoji | Metode | Emoji | Metode |
  |---|---|---|---|
  | 🌠 | node asli, tanpa custom | 🏙️ | `wildcard` |
  | 🌌 | node asli CloudFront, tanpa custom | 🌇 | `wildcard-sni` (juga dipakai `wildcard-ip`) |
  | 🎬 | `bug-sni` | 🌁 | `host-bug` |
  | 💭 | `bug-addr` | 🪲 | `host-bug-sni` |
  | 🐬 | `ip-edge` | 🧸 | `ganti-path` (semua `path-*`) |
  | ☕ | `sni-ip` (juga `host-ip`) | 🏞️ | `bug-addr-sni` |
  | 🏖️ | `ip-bug-sni` | | |

  Metode dibaca dari tag di nama node hasil Uji Bug (`Nama [bug-sni:instagram.com:443]`). Node CloudFront dikenali dari server/SNI/Host `*.cloudfront.net` atau nama yang memuat "cloudfront". Varian `http-*` mengikuti metode induknya; tag `[port:…]`, `[alpn:…]`, `[fp:…]`, `[combo]` tetap dianggap node asli.
