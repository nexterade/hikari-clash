# 🎒 Tips & Trik

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

**🔖 Shortcut `hikari-clash` (Termux)** — sudah dibuat oleh langkah instalasi di [README](../README.md#-instalasi); ketik `hikari-clash` dari folder mana saja. Kalau perlu membuat ulang (mis. folder dipindah), jalankan dua baris ini dengan path folder yang baru:

```bash
printf '#!/bin/sh\ncd /storage/emulated/0/Project/hikari-clash && exec python3 hikari_converter.py "$@"\n' > "$PREFIX/bin/hikari-clash"
chmod +x "$PREFIX/bin/hikari-clash"
```

Hapus kapan saja dengan `rm "$PREFIX/bin/hikari-clash"`. Di Linux/PC caranya sama: taruh file serupa di `~/.local/bin/hikari-clash` (shebang `#!/bin/sh`, path folder disesuaikan) lalu `chmod +x`; `~/.local/bin` biasanya sudah ada di PATH.

**📦 Active vs Trial** — `active.yaml` untuk node harian, `trial.yaml` untuk node yang lagi dicoba; keduanya ada per operator (`proxy/xl/active.yaml`, `proxy/byu/trial.yaml`, …). Keduanya otomatis masuk **💫 AUTO MODE** dan **🗳️ PROXY LIST**.

**📑 Keyring & 📄 Free (v1.0+)** — saat generate, script menaruh `proxy/subs.yaml` (salinan `subscription.yaml` sebagai cache awal) dan `proxy/free.yaml` (kosong, untuk hasil sub2yaml) di samping `active.yaml`/`trial.yaml`. Di Mode Offline, provider `📑 Keyring` ikut jadi `file` (tidak auto-update). Regenerate (`1 → 3`) hanya membaca `active.yaml`/`trial.yaml`; `subs.yaml` dan `free.yaml` tidak dianggap sumber node. Isi `free.yaml` dari sub2yaml lewat `1 → 4`. ⚠️ Node gratis publik dikelola pihak lain: jangan dipakai untuk login/transaksi sensitif, karena operator node bisa melihat trafik yang tidak terenkripsi end-to-end.

**🌠 Emoji nama node** — emoji mengikuti **metode** node, bukan acak: 🌠 asli, 🌌 CloudFront asli, lalu satu emoji per metode custom (🎬 `bug-sni`, 💭 `bug-addr`, 🐬 `ip-edge`, …; tabel lengkap di [usage.md](usage.md#edit-configuration)). Edit lewat `2 → 4` atau ubah `emoji.json`. Nama yang sudah berawalan emoji (apa pun, mis. `🪟 Rekayasa` atau `🇸🇬 Singapore`) dibiarkan apa adanya, tidak jadi dobel, jadi aman dipakai bareng Append.

**➕ Pakai Append** — tambah node baru tanpa menghapus yang lama. Nama otomatis dijaga unik.

**🌐 Tips DNS (penting!)**

- **Default sekarang (v0.9 sampai v1.3):** `nameserver` = **BebasDNS Unfiltered** (DoH), `fallback` = **Cloudflare + Google** (DoH), `proxy-server-nameserver` & `default-nameserver` = `1.1.1.1`/`8.8.8.8`, `direct-nameserver` = Quad9 `9.9.9.10`/`149.112.112.10`, `fallback-filter.geoip: false`. Dengan `respect-rules` + `fake-ip`, query DNS domain yang lewat proxy keluar lewat proxy, jadi dnsleak test seharusnya menampilkan resolver BebasDNS/Cloudflare/Google, bukan DNS ISP. DNS polos di `proxy-server-`/`direct-nameserver` bisa dibelokkan ISP (hipotesis, belum diuji di jaringan XL); kalau terjadi, pakai **Mode Anti-Blokir** (template v0.7/v0.8 sudah begitu). Menu `5 → 2` memeriksa ini secara statis; verifikasi akhir tetap lewat dnsleaktest.com / bash.ws dari perangkat. (Catatan: Mihomo meng-query `fallback` bersamaan dengan `nameserver`, jadi **semua** isi keduanya harus non-ISP.)
- `fallback-filter.geoip: false` dipasang karena filter bawaan Mihomo (geoip CN) tidak relevan di Indonesia. Perilaku persisnya belum diuji di core asli; validator memperingatkan kalau `fallback` dipakai tanpa itu.
- **Hasil dnscheck.tools:** tabel **DNSSEC** akan tetap FAIL semua — itu normal. Mihomo tidak memvalidasi DNSSEC, `fake-ip` selalu menjawab, dan resolve asli terjadi di resolver server node. Yang menentukan lolos/tidaknya kebocoran adalah daftar "Your DNS resolvers" (tidak boleh ada resolver ISP-mu) dan "Your IP addresses" (tidak boleh ada IP ISP-mu; kalau ada, cek koneksi DIRECT di dashboard).
- **Internet Positif / situs terblokir:** tiga lapis berbeda. (1) DNS ISP dibelokkan → diatasi fake-ip untuk domain yang lewat proxy, dan DoH berbasis IP (v0.7 / Mode Anti-Blokir) untuk sisanya. (2) Koneksi lewat proxy tapi `ERR_CONNECTION_CLOSED` dengan `DL 0 B` di dashboard dan *Remote address* berupa IP Indonesia → server node-nya sendiri yang menutup koneksi (DNS/egress server di dalam jaringan yang menyensor); tidak bisa diperbaiki dari config klien — coba node di luar negeri dan bandingkan. (3) Rule: pastikan domain-nya jatuh ke 🧩 Inject, bukan DIRECT (kolom Rule/Chains di dashboard). Tes terbaik: buka situs terblokir lalu lihat Chains-nya, bukan dnscheck.tools (DNSSEC tidak ada hubungannya dengan sensor).
- **XL Axiata:** di jaringan XL, tunneling Nikki/OpenClash butuh DNS `112.215.203.254`. Pilih operator **xl** saat generate (Nikki/OpenClash), atau **Profil ISP → XL Axiata** (menu `2 → 3 → 4`). Script menyuntikkannya ke `default-nameserver` dan `proxy-server-nameserver` — hanya me-resolve host DoH & domain server proxy, **bukan** domain yang kamu buka, sehingga dnsleak tetap bersih. Template v0.2 dulu menaruhnya juga di `fallback`; kalau tunneling masih gagal, tambahkan `fallback` lewat menu yang sama — tapi DNS XL lalu akan terlihat di dnsleak (audit menandainya `LEAK`). Pengaturan tersimpan di `settings.json`; Box tidak diubah.
- `nameserver` (DoH) lewat proxy → aman dari reset ISP.
- `proxy-server-nameserver` & `direct-nameserver` sengaja **DNS polos** (`8.8.8.8`, `1.1.1.1`). Banyak ISP/modem **me-reset DoH** ke IP publik port 443; kalau itu dipakai untuk resolve domain server proxy, **semua node timeout**.
- Kalau `8.8.8.8` ikut diblok di jaringanmu, ganti ke DNS ISP lewat menu *DNS → Custom manual* (field `proxy-server-nameserver`) atau edit `template/template.yaml`.
- Preset hanya mengisi `proxy-server-nameserver` dengan IP polos; kalau kamu isi dengan DoH/DoT lewat Custom, menu dan validator akan memperingatkan.
- **BebasDNS** (`dns.bebasid.com`, MIT): kalau ISP/WiFi-mu memakai DPI dan memblokir domain DoH/DoT-nya, hubungi `dukungan@bebasid.com` untuk domain alternatif, lalu masukkan lewat *Custom manual*.
- Host DoH/DoT/DoQ berupa domain (mis. `dns.google`) di-resolve lewat `default-nameserver`, makanya field itu wajib IP.

**🔌 Mode Offline** — pilih saat generate kalau tidak mau ruleset berubah sendiri, atau GitHub raw sedang lambat/terblokir.

**🧪 Validasi dulu sebelum pasang** — menu `4` mengecek template untuk Box, Nikki, dan OpenClash sekaligus; menu `5 → 2` mengecek config hasil generate (dan menjalankan `mihomo -t` otomatis kalau core ada). Manual:

```bash
mihomo -t -d hasil/full_config_box -f hasil/full_config_box/xl.yaml
```

**🔐 Secret dashboard** — default template: **`hikari`**. Setiap generate script menanyakan: ikuti template (`hikari`) atau acak. Mau secret tetap lain? Isi lewat menu `2 → 1` (ketik `acak` atau secret sendiri), tersimpan di `template/template.yaml`. ⚠️ `hikari` adalah secret yang mudah ditebak: di Box aman karena controller hanya `127.0.0.1`, tetapi di Nikki/OpenClash controller dibuka ke `0.0.0.0` — pakai secret acak/sendiri kalau jaringanmu dipakai orang lain. Di Nikki/OpenClash yang berlaku biasanya secret dari LuCI.

**🪵 Debug** — ubah `log-level: warning` jadi `debug` di `template/template.yaml`, generate ulang, lalu lihat tab *Logs* di dashboard.

**🧯 Backup** — setiap edit lewat menu membuat `template/template.yaml.bak`. Template master & `archive/` aman untuk rollback.

**🎮 Rule GAMING** — `port-games.yaml` mencocokkan port TCP+UDP. Kalau ingin hanya UDP, ubah entri jadi `AND,((NETWORK,UDP),(DST-PORT,5000-5221))`.
