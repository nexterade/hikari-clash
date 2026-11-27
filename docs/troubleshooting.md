# 🔧 Troubleshooting

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

| Gejala | Penyebab | Solusi |
|---|---|---|
| Semua node *timed out*; log: `dns resolve failed ... connection reset by peer` | DoH ke 8.8.8.8 / 1.1.1.1 :443 di-reset ISP, domain server proxy tidak ter-resolve | `proxy-server-nameserver` pakai DNS polos (default template sekarang). Cek: `nslookup domain-server-mu 8.8.8.8` |
| Di OpenWrt semua trafik Direct | Rule WIFI ikut ke router | Pakai script v3 / template v0.3+ (WIFI otomatis dibuang) |
| Node Reality/Vision tidak konek | Parser lama membuang `flow` & `fp` | Script v3 membawa `flow`, `client-fingerprint`, `pbk`, `sid` |
| `PermissionError` | Folder di `~` Termux | Pindah ke `/storage/emulated/0/...` setelah `termux-setup-storage` |
| `PyYAML belum terpasang` | Library belum ada | `pip install pyyaml` |
| Semua node dari `active.yaml` tidak punya ping / *timed out*, padahal node yang sama jalan di DarkTunnel/HTTP Custom | `skip-cert-verify: false` + SNI bug (mis. `instagram.com`) → sertifikat server tidak cocok → handshake TLS gagal. Biasanya karena link membawa `allowInsecure=0` / `insecure=0` | Pakai script versi ini (SNI custom otomatis `true`, juga saat regenerate node lama). Manual: ubah ke `skip-cert-verify: true` di `proxy/active.yaml` lalu reload core |
| Dashboard minta secret | Secret default `hikari`, acak, atau dari LuCI | Lihat ringkasan setelah generate; di Nikki/OpenClash pakai secret dari LuCI |
| Emoji node tidak sesuai `emoji.json` | JSON rusak (mis. koma berlebih di akhir), atau `emoji.json` masih format lama (`emojis: [...]`, acak) | Script memberi peringatan saat start & di Check Status; perbaiki filenya atau Reset lewat menu `2 → 4 → R` |
| Port bentrok / core gagal start | Dua port sama | Menu `4` (Validasi) menunjukkan port ganda |
| Rule-provider gagal download | GitHub raw lambat/terblokir | Mode Offline, atau pakai `proxy:` pada provider |
| `transport 'xhttp' belum didukung` | Transport belum ada di parser | Pakai node dengan ws/grpc/tcp, atau tambahkan manual di YAML |
| Provider kosong bikin error di core tertentu | `trial.yaml` / `free.yaml` berisi `proxies: []` | Isi minimal 1 node |
| `☘️ FREE NODE` kosong | `free.yaml` belum diisi sub2yaml (default `proxies: []`) | `1 → 4`, lalu restart core |
| `free.yaml` dari sub2yaml ditolak core (field/karakter tidak dikenali) | Versi lama memakai `{}` inline dan tidak membuang node dengan UUID/reality rusak saat TCP-only | Pakai `sub2yaml.py` versi ini (block style + validasi offline), jalankan ulang lalu impor `1 → 4` |
| `free.yaml` isinya node "hidup" tapi hampir semua tanpa ping / semua ping 1–3 ms | Versi lama jatuh ke tes TCP (port terbuka) saat core tidak ada; atau Box/Nikki/VPN aktif sehingga semua koneksi TCP dijawab proxy lokal | Pakai `sub2yaml.py` versi ini (URL-test mihomo wajib, 2 kali verifikasi) dan matikan Box/VPN saat tes |
| `Unduh core mihomo … tidak bisa dijalankan` / `Permission denied` | Folder Hikari di `/sdcard` (noexec), atau varian core tidak cocok dengan HP | Versi ini otomatis memasang di `~/.hikari-clash/bin` dan mencoba varian lain; baca baris alasan yang ditampilkan. Manual: taruh binary di `~/.hikari-clash/bin/mihomo` lalu `chmod 755` |
| Unduh core terputus di tengah jalan | Koneksi GitHub tidak stabil | Tekan `[9]` lagi: unduhan dilanjutkan dari `bin/*.part` |
| `src/` kosong / source basi | File `.txt` belum diunduh atau sudah lama | Menu `[8]` di sub2yaml, atau `python3 sub2yaml.py --update-source` (butuh internet) |
| `📑 Keyring` kosong / provider gagal download | Download lewat 🗃️ UPDATER: node dulu, DIRECT kalau semua node mati. Gagal kalau keduanya tidak bisa menjangkau GitHub raw (mis. diblokir) | Pakai cache awal dari `subscription.yaml`, atau Mode Offline. Di start pertama, core mungkin masih mencoba node dulu sebelum jatuh ke DIRECT (perilaku core belum diuji) |
| Operator di Info Banner salah (mis. `XL Axiata` padahal pakai by.U) | HP dual SIM: `getprop` memberi satu nama per slot dan Android tanpa root tidak menunjukkan SIM data | Kini semua SIM ditampilkan; isi **Operator** di `Misc → 7 Info Banner → 7` untuk memastikan |
| `Status: Box Tidak Aktif` padahal core jalan | Controller bukan di `127.0.0.1:9090`, secret beda, atau (Android tanpa root) proses tidak terlihat | `Misc → 7 Info Banner`: isi **alamat controller** dan **secret**. Cek manual: `curl -H "Authorization: Bearer <secret>" http://127.0.0.1:9090/version` |
| Status tampil `Mihomo Aktif`, bukan `Nikki Aktif` (core di router) | Label router hanya heuristik halaman LuCI | `Misc → 7 Info Banner → Platform` = `nikki` / `openclash` |
| Menu utama terasa lambat sebentar saat dibuka | Lookup IP publik menunggu internet (batas ±3,5 dtk, lalu di-cache) | Matikan *IP publik+lokasi* di Info Banner, atau set `off` / `compact` |
| Chip "Mihomo putus" di halaman NetStat | `API`/`SECRET` di `stats.conf` tidak cocok dengan controller, atau core belum jalan | Samakan lalu `stats-ctl.sh restart`; detail di [netstat.md](netstat.md#masalah-umum) |
| NetStat `gagal start, cek stats.log` | Port 9099 dipakai (mis. versi lama masih jalan) | Ubah `LISTEN` di `stats.conf` atau hentikan yang lama |
