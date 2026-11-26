# 🧪 Miscellaneous (Menu 5)

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Kumpulan tools tambahan. Semuanya offline; yang butuh sesuatu dari luar (core Mihomo, zstd) bilang jelas kalau belum ada.

| Submenu | Fungsi | Catatan |
|---|---|---|
| **1. Rule-Provider Converter** | `.mrs` ⇄ `.yaml` / `.txt`. Arah otomatis dari ekstensi; ada mode batch (semua `.mrs` di `ruleset/` → YAML) dan info `.mrs` | Hasil di `hasil/rules/`. Perlu backend zstd (lihat [Instalasi](../README.md#-instalasi)). `domain` sudah diuji: hasil tulis identik (setelah dekompresi) dengan `blocker.mrs` & `plus18.mrs`; `ipcidr` belum diuji dengan file asli → cek dengan core sebelum dipakai |
| **2. Config Tester** | Validator internal untuk config hasil generate + `mihomo -t` kalau core ketemu (PATH, lokasi umum Box/OpenClash, atau env `HIKARI_MIHOMO`) | Juga menjalankan **audit DNS leak statis** (DNS ISP / tak terenkripsi di nameserver & fallback, respect-rules, fake-ip, IPv6). Tes core untuk Nikki dilewati di luar perangkat Nikki (path-nya absolut `/etc/nikki/run`) |
| **3. Proxy Node Tester** | **Offline**: DNS → TCP → TLS ke server node. **Via core**: delay sungguhan lewat `external-controller` | Offline hanya menjawab "server terjangkau dari jaringan ini?", bukan "proxy tembus ke internet?". Node UDP (hysteria/tuic) dilewati. Node hidup bisa disimpan ke `hasil/nodes_ok_*.yaml` |
| **4. Route Tester** | Ketik domain/IP (`chatgpt.com`, `1.1.1.1:443`, `udp://x.com:443`) → rule & group yang kena | Tanpa DNS lookup; rule `GEOIP`/`SRC-*`/`PROCESS-*` ditandai "tidak bisa dievaluasi", tidak ditebak |
| **5. Sniffer Only** | Config pengintai tanpa node + inspector detail per koneksi — lihat [Sniffer Only](sniffer.md) | Semua trafik DIRECT lewat kuota reguler |
| **6. Info Lingkungan** | Versi Python/PyYAML, backend zstd, lokasi core, template aktif | Berguna untuk debugging |
| **7. Info Banner** | Atur info di bawah banner (IP, lokasi, jaringan, status core, usage): tampilan, sensor IP, lookup IP publik, platform, controller | Lihat [Info di bawah banner](usage.md#info-di-bawah-banner) |
