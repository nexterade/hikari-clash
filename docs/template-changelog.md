# 🧾 Riwayat Template (v0.3 → v1.3)

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Perbedaan antar versi `template/config_v*.yaml`, terbaru di atas. Template master lama dibiarkan utuh; salinan kerja `template/template.yaml` tidak ikut berubah — ganti lewat menu `2 → 2`.

## v1.3 vs v1.2
DNS, rule, dan provider node sama. (1) Grup baru **💫 FALLBACK** (`fallback`, `hidden`, provider 🗳️ Active + 📅 Trial; tanpa `tolerance` karena itu field `url-test`), ditambahkan ke pilihan 🧩 INJECT, 🌳 SMART MODE, 👾 GAMING, dan 💕 Plusplus. (2) Grup baru **🗃️ UPDATER** (`fallback`, `hidden`: 💫 AUTO MODE → 🎮 DIRECT); semua rule-provider dan provider 📑 Keyring memakai `proxy: 🗃️ UPDATER` (sebelumnya 💫 AUTO MODE), jadi update tidak macet bila node mati. Tidak ada siklus: provider `http` → UPDATER → AUTO MODE → provider `file` saja. (3) URL test (grup dan health-check provider) tetap `http://www.gstatic.com/generate_204` dengan `expected-status: 204`; `https://cp.cloudflare.com/generate_204` sempat dicoba tetapi gagal connect, jadi tidak dipakai. (4) 💫 AUTO MODE `hidden: true`. Emoji `🗃️` tidak dipakai daftar emoji nama node. Config lama tetap jalan; generate ulang dari v1.3 (*Regenerate* `1 → 3`), dan ganti `template/template.yaml` salinan kerjamu lewat `2 → 2`.

## v1.2 vs v1.1
Terutama penamaan dan susunan group node, DNS dan urutan rule sama. (1) Nama diganti kapital: `🧩 Inject` → `🧩 INJECT`, `📚 List` → `🗳️ PROXY LIST`, `💫 Auto` → `💫 AUTO MODE`, `🌳 Smart` → `🌳 SMART MODE`, `👾 Gaming` → `👾 GAMING`, `🍪 Wifi` → `🍪 WIFI MODE`, serta `🎮 DIRECT`, `✂️ REJECT`, `🐬 HIJACK`. (2) `🗺️ Public` dihapus, diganti dua url-test tersembunyi, **📄 FREE NODE** (provider 📄 Free) dan **📑 KEYRING** (provider 📑 Keyring); group pilihannya **☘️ FREE NODE** (dulu 🐦 Free) dan **🧊 KEYRING** (dulu 🛠️ Keyring) masing-masing memilih url-test-nya sendiri. (3) 🌳 SMART MODE dan 💕 Plusplus memilih ☘️ FREE NODE & 🧊 KEYRING langsung. (4) Provider 📑 Keyring `interval: 864000`. Emoji `🧊` dikeluarkan dari daftar emoji nama node karena kini dipakai nama group. Config lama tetap jalan selama dibuat ulang dari v1.2 (*Regenerate* `1 → 3`); `template/template.yaml` salinan kerjamu tidak ikut berubah, ganti lewat `2 → 2`.

## v1.1 vs v1.0
Koreksi, bukan fitur baru. (1) **🗺️ Public** dipindah dari blok `proxies:` ke `proxy-groups` (grup url-test tidak boleh ada di `proxies:`). (2) **🛠️ Keyring** dan **🐦 Free**: provider lewat `use:`, grup 🗺️ Public lewat `proxies:` (sebelumnya terbalik). (3) Nama **🐦 Free** dibetulkan (ada karakter tak terlihat di depan namanya, sehingga tidak cocok dengan 🧩 Inject). (4) Provider **📑 Keyring** memakai `proxy: 💫 Auto` (sebelumnya merujuk grup yang sudah tidak ada). (5) Typo `expexted-status` → `expected-status`. Rename dari v1.0: 🛸 AUTO MODE → 💫 Auto, 👒 PROXY LIST → 📚 List, 🌳 SMART ROUTING → 🌳 Smart, 🪼 Gaming → 👾 Gaming, 🛹 Free node → 🐦 Free (provider 📖 → 📄 Free), provider 🍞 → 📑 Keyring. Grup 🥪 Subscription dihapus; node gratisnya sekarang bisa dipilih lewat 🛠️ Keyring dan 🐦 Free. Config hasil v1.0 tetap jalan selama dibuat ulang dari v1.1 (*Regenerate* `1 → 3`).

## v1.0 vs v0.9
(1) Group baru **🥪 Subscription** (provider `🍞 Subscription`, `http` → `subscription.yaml` repo) dan **🛹 Free node** (provider `📖 Free node`, `file` → `proxy/free.yaml`), keduanya ditambahkan ke pilihan **🧩 Inject**. (2) Nama group diseragamkan: `💤 BLOCKER` → `💤 AdBlock`, `💕 PLUSPLUS` → `💕 Plusplus`, `🍪 WIFI` → `🍪 Wifi`, `🪼 GAMING` → `🪼 Gaming`; nama provider jadi `🗳️ Active` / `📅 Trial`. (3) Rule-provider `Plusplus` ikut memakai `proxy: 🛸 AUTO MODE` seperti yang lain. DNS, urutan rule, dan sniffer sama dengan v0.9. v0.3–v0.9 tidak diubah. *Config lama yang kamu edit manual dan masih memakai nama group lama tidak ikut berubah — generate ulang dari template v1.0.*

## v0.9 vs v0.8
Hanya dua hal. (1) DNS: `nameserver` = BebasDNS Unfiltered (DoH), `proxy-server-nameserver` & `default-nameserver` = `1.1.1.1`/`8.8.8.8`, `direct-nameserver` = Quad9 `9.9.9.10`/`149.112.112.10`, `fallback` = Cloudflare + Google (DoH). Ini kembali memakai DNS polos port 53 untuk `proxy-server-`/`direct-nameserver` (v0.7/v0.8 memakai DoH berbasis IP); kalau ISP membelokkannya, jalankan menu DNS → **Mode Anti-Blokir**. (2) URL icon grup dan rule-provider memakai branch `master` (`.../hikari-clash/refs/heads/master/...`). v0.3–v0.8 tidak diubah.

## v0.8 vs v0.7
Hanya link sumber: semua rule-provider dan icon grup sekarang menunjuk ke `https://github.com/nexterade/hikari-clash` (branch `main`). Dulu ruleset ada di `nexterade/crispy-funicular` dan icon di `nexterade/Hikari-SC` (branch `master`). v0.3–v0.7 tetap menunjuk ke repo lama. *Catatan: URL icon di v0.8 memakai branch `main` dan ternyata tidak valid — diperbaiki di v0.9 (branch `master`).*

## v0.7 vs v0.6
Hanya DNS (anti-blokir / Internet Positif): `proxy-server-nameserver` dan `direct-nameserver` dari UDP polos `8.8.8.8`/`1.1.1.1` jadi DoH berbasis IP (`https://1.1.1.1/dns-query`, `https://8.8.8.8/dns-query`), dan `nameserver` jadi Cloudflare DoH (BebasDNS tetap ada di menu Preset). DNS polos port 53 di jalur DIRECT bisa dibelokkan ISP ke resolver sensor. Domain yang lewat proxy tidak terdampak berkat fake-ip. **Batasan:** ini tidak membuka node yang server-nya sendiri diblokir atau berada di jaringan yang menyensor (lihat [Tips & Trik](tips.md)). Kalau node timeout setelah v0.7 (DoH di-reset ISP), balikkan `proxy-server-nameserver` ke IP polos lewat *Custom manual* atau pakai v0.6.

## v0.6 vs v0.5
Satu hal: dua rule STUN/TURN (UDP 3478-3479 dan 19302-19309) ke 🧩 Inject, sebelum `Portgames`. Di v0.5 STUN (mis. `stun.l.google.com:19302`) kena `Portgames` (16999-20100) → 🪼 GAMING → Direct, sehingga browser yang memakai WebRTC membocorkan IP asli ISP (terlihat di dnscheck.tools sebagai IP provider di samping IP proxy). Konsekuensinya: panggilan suara/video yang memakai STUN lewat proxy butuh node yang mendukung UDP. Rule game lain tidak berubah.

## v0.5 vs v0.4
Hanya DNS: `nameserver` jadi BebasDNS, `fallback` Cloudflare+Google dengan `fallback-filter.geoip: false`, supaya lolos dnsleak. Profil ISP (XL Axiata) disuntik script, bukan ditaruh di template. v0.4 tetap ada. *Catatan: `template/template.yaml` salinan kerjamu tidak ikut berubah — pakai `2 → 2` untuk pindah ke v0.5 atau `2 → 3 → 3` untuk menyalin DNS-nya saja.*

## v0.4 vs v0.3
Isinya sama, tetapi v0.4 benar-benar netral: blok khusus Box (`tun`, `find-process-mode`, `geodata-mode`, `experimental`, `external-ui`) dipindah dari template ke overlay Box di `hikari_converter.py`. v0.3 tetap ada untuk rollback.
