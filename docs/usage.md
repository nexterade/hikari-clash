# 🚀 Cara Pakai

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

```bash
cd /storage/emulated/0/Documents/hikari-clash
python hikari_converter.py
```

## Menu utama

```text
[1] Convert                 ← link ⇄ Clash YAML, regenerate dari node tersimpan, impor free node (sub2yaml)
[2] Edit Configuration      ← port & secret, ganti template, DNS, emoji node
[3] Check Status            ← template, provider, config yang sudah jadi
[4] Validasi / Audit Config ← cek template untuk ketiga platform
[5] Miscellaneous           ← converter .mrs, tester config / node / route, sniffer only
────────────────────────────
[Q] Exit
```

## Alur Convert (URI ➜ Clash)

1. **Paste** link (`vless://` / `vmess://` / `trojan://`), satu per baris. Enter 2× untuk selesai.
2. **Preview**: lihat daftar node. Aksi: `[T]` tambah · `[H]` hapus (mis. `1,3`) · `[L]` lanjut · `[B]` batal.
   Baris yang gagal ditampilkan beserta alasannya (UUID kosong, transport belum didukung, dll).
3. **Pilih platform**: `B` Box · `N` Nikki · `O` OpenClash.
4. **Pilih provider**: `active.yaml` atau `trial.yaml`. Jika sudah berisi node, pilih **Ganti** atau **Tambahkan**.
5. **Mode rule-provider**: ikuti template (auto-update GitHub) atau **Offline** (file lokal saja).
6. **Secret dashboard**: `[1]` ikuti template (default: `hikari`) atau `[2]` acak.
7. Selesai. Script menampilkan lokasi hasil, hasil validasi, dan secret yang dipakai.

## Regenerate dari node tersimpan

Menu `1 → 3`. Kamu mengubah template, DNS, profil ISP, emoji, atau secret dan ingin config baru **tanpa paste URI lagi**? Script membaca node dari `hasil/full_config_*/proxy*/active.yaml` dan `trial.yaml`, lalu membangun ulang `config.yaml` + ruleset dari template yang sedang aktif.

- **`[1]…[n]`** — pilih satu sumber (mis. `nikki/active.yaml`, lengkap dengan jumlah node & waktu ubah). Enter = tetap di platform/provider yang sama, jadi file node-nya **tidak** ditanya timpa/tambah. Pilih platform lain untuk menyalin node ke sana (format node sama di semua platform).
- **`[A]`** — bangun ulang semua sumber sekaligus dengan pilihan baku: rule-provider & secret ikut template, profil ISP dari `settings.json`.
- Nama node dipakai apa adanya (emoji tidak ditambah lagi), dan node di provider lain tidak disentuh.

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
- **Emoji Node**: lihat daftar emoji, `[A]` tambah, `[H]` hapus (nomor), `[T]` nyalakan/matikan, `[R]` reset ke bawaan. Tersimpan di `emoji.json`.
