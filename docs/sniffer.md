# 🔎 Sniffer Only (Menu 5 → 5)

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Config khusus **mengintip koneksi**, bukan menerowongnya: **tanpa node, tanpa provider, semua trafik DIRECT lewat kuota reguler** (tidak ada bug-host, SNI custom, atau DNS khusus ISP). Dipakai untuk melihat ke mana saja sebuah aplikasi/situs benar-benar terhubung.

| Submenu | Fungsi |
|---|---|
| **1. Generate Config** | Bangun `hasil/sniffer/<platform>/config.yaml` dari `template/sniffer_only.yaml` untuk Box / Nikki / OpenClash (opsional: ASN, secret acak). Hanya `config.yaml` yang perlu disalin ke perangkat; folder provider tidak ada |
| **2. Inspector Live** | Membaca `/connections` dari core yang sedang jalan, mencetak koneksi baru (mode ringkas atau detail), lalu ringkasan sesi dan ekspor CSV/JSON/**Markdown** ke `hasil/sniffer/` |
| **3. Update CIDR CDN** | Unduh daftar resmi Cloudflare (`cloudflare.com/ips-v4`, `ips-v6`) dan CloudFront (AWS `ip-ranges.json`, layanan `CLOUDFRONT`) ke cache lokal. Memakai kuota reguler, ukuran `ip-ranges.json` beberapa MB |

**Laporan Markdown (`koneksi_<waktu>.md`):** dibuat otomatis saat sesi inspector disimpan. Isinya hanya koneksi yang **menerima data** (download > 0 B), koneksi serupa digabung (aplikasi + protokol + port + host + chain; IP-nya dikumpulkan), upload dan download dijumlahkan, lalu ditutup dengan daftar kandidat SNI, Address (`host:port`), dan wildcard domain format rule-set Mihomo. Kolom Catatan menandai `HTTP polos`, `respons kecil` (bisa redirect/halaman operator), `host dari DNS, bukan SNI`, dan `tanpa SNI`. Untuk rekaman lama: `python3 sniffer.py laporan koneksi_XXXX.json [keluaran.md]` (JSON atau CSV). Kandidat bukan jaminan gratis; buktinya paling kuat kalau direkam di SIM tanpa kuota reguler.

**Data per koneksi:** alamat tujuan (IP:port), host hasil **sniff** (SNI/Host) dan host dari **DNS** (dipisah), subdomain, domain dasar, GeoIP negara, ASN (bila diaktifkan), CDN (Cloudflare / CloudFront) beserta **dasar deteksinya** (`rule` / `ip` / `host`), rule + chain, sumber, aplikasi (Box: nama package), dan trafik ↑/↓.

**Cara kerja config:**

| Setelan | Alasan |
|---|---|
| `sniffer.override-destination: false` | IP tujuan asli dan host hasil sniff tetap terpisah (`destinationIP` vs `sniffHost`) |
| `dns.enhanced-mode: redir-host` | `destinationIP` berisi IP sungguhan, bukan `198.18.x.x` (fake-ip) |
| `geodata-mode: false` + rule probe `GEOIP,ZZ,DIRECT` | Mihomo mengisi `destinationGeoIP` hanya di mode mmdb; negara `ZZ` tidak pernah cocok, jadi rule ini hanya mengisi cache GeoIP |
| Group `🔶 Cloudflare`, `🟧 CloudFront`, `🏠 LAN`, `🧭 DNS`, `📶 WIFI`, `🔍 Lainnya` (isinya cuma `DIRECT`) | Label: dashboard (MetaCubeXD, Zashboard, Yacd) langsung menampilkan kolom chain tanpa inspector |
| Rule `SRC-IP-CIDR,192.168.0.0/16,📶 WIFI` tepat sebelum `MATCH` *(mode WiFi, sniffer-1.1)* | Menandai koneksi dari client WiFi/hotspot/router (IP sumber LAN). Sengaja di bawah rule CDN/DNS/LAN, jadi koneksi ke Cloudflare/CloudFront tetap berlabel CDN-nya; trafik non-LAN (mis. data seluler di Box) tetap `🔍 Lainnya` |

**Mode WiFi:**
- Perangkat asal tiap koneksi selalu terlihat di kolom Source (`/connections`) dan "Sumber" di inspector. Untuk label per perangkat di chain, aktifkan contoh `SRC-IP-CIDR,<ip>/32,<label>` di template (taruh sebelum rule WIFI dan tambahkan grup labelnya).
- Subnet lain: hotspot iPhone memakai `172.20.10.x`; CGNAT seluler sering `10.x` / `100.64.x` (jangan dimasukkan). Cek kolom Source lalu sesuaikan rule WIFI.
- **Nikki/OpenClash:** semua client LAN berIP `192.168.x.x`, jadi semua trafik non-CDN berlabel `📶 WIFI` dan `🔍 Lainnya` praktis kosong. Itu wajar; hapus rule WIFI kalau tidak ingin label itu.
- **Box + hotspot:** client hotspot hanya terlihat kalau Box memakai mode tproxy.
- `ipv6: false`: client yang memakai IPv6 bisa lolos dari pengintaian. Client dengan DNS sendiri (DoH/Private DNS) tampil sebagai host sniff atau IP murni, bukan host dari DNS core.

**Aplikasi provider (MyXL, MyTelkomsel, by.U, myIM3) tidak mau terbuka saat Box aktif** *(template sniffer-1.2; penyebabnya hipotesis, belum diuji di perangkat)*:

| Dugaan | Gejala | Perbaikan |
|---|---|---|
| **DNS (terbukti di kartu XL).** Box membelokkan semua DNS ke core, dan core hanya memakai DoH `1.1.1.1` / `dns.google`. IP gratis paket aplikasi adalah cache milik operator (mis. `scdn.co`/`spotifycdn.com` → `112.215.x.x`, AS24203 PT XL Axiata) yang hanya dijawab DNS operator | Aplikasi macet di splash / "tidak ada koneksi", padahal browser normal. Normal lagi saat Box dimatikan. Log core menampilkan `dns resolve failed` atau timeout untuk domain operator | Menu Sniffer Only > Generate Config > **DNS operator**: `[D]` deteksi dari perangkat (`su -c dumpsys connectivity`, butuh root), preset XL / AXIS, atau isi manual. Cakupan `[2]` (default) memakai DNS itu untuk **semua** domain; cakupan `[1]` hanya domain provider |
| **Deteksi VPN.** Box mode `tun`/`mixed` membuat Android menandai jaringan sebagai VPN | Aplikasi menolak jalan atau menampilkan pesan VPN, apa pun isi config | Pakai mode `tproxy`/`redirect` di settings Box. Blok `tun` di config ini sengaja `enable: false` |
| **Kecualikan aplikasinya** | Dua dugaan di atas sudah dicek, tetap gagal | Masukkan paket aplikasi ke blacklist Box (`proxy_mode=blacklist`). Konsekuensinya: aplikasi itu tidak terintip. Nama paket tampil di kolom Aplikasi inspector |

**Daftar DNS operator.** Hanya XL / AXIS yang punya preset (`112.215.203.254`, terverifikasi di kartu XL). IP Telkomsel / by.U, Indosat / IM3 / Tri, dan Smartfren / XL Smart sengaja tidak ditebak: salah satu IP membuat semua koneksi gagal resolve, dan DNS operator berbeda per wilayah. Untuk operator itu pakai `[D]` (deteksi) atau `[M]` (manual). Kartu by.U memakai jaringan Telkomsel. Antarmuka seluler (`rmnet*`, `ccmni*`) dipertahankan walau IP-nya privat; DNS WiFi (router) dibuang. Laporan Markdown menandai host yang di-resolve ke IP milik operator ("IP operator") karena itu kandidat jalur gratis.

Cara membedakan: buka aplikasinya dengan dashboard terbuka. Kalau muncul koneksi tapi domain operator gagal di-resolve, itu DNS. Kalau tidak ada koneksi sama sekali dan aplikasi langsung menolak, curigai deteksi VPN.

**Batasan yang perlu diketahui:**
- Cloudflare dikenali dari daftar CIDR inline di template; CloudFront di config hanya dari nama `*.cloudfront.net`. Pengenalan CloudFront lewat **IP** dilakukan inspector setelah submenu 3 dijalankan. Tebakan dari nama host (`workers.dev`, `pages.dev`, …) ditandai `dasar: host`, itu bukan bukti.
- Sniffer hanya melihat SNI / Host header / QUIC SNI. Koneksi tanpa itu (ECH, protokol non-HTTP) tampil sebagai **IP murni**.
- Subdomain dipecah dengan heuristik (daftar akhiran multi-label kecil seperti `co.id`), bukan Public Suffix List penuh.
- GeoIP butuh mode mmdb dan file `country.mmdb`/`geoip.metadb` di core. ASN butuh `GeoLite2-ASN.mmdb`, diunduh core saat start kalau opsi ASN dipilih.
- Nikki/OpenClash menimpa port, DNS, dan controller dari LuCI; pastikan di sana tidak memakai mode `geoip.dat` kalau ingin kolom GeoIP terisi.
- Config **belum diuji dengan core Mihomo asli**; yang teruji: validator internal, struktur config, dan inspector terhadap controller tiruan. Config Tester (menu `5 → 2`) hanya memeriksa config utama, bukan config sniffer; uji dengan `mihomo -t -d <folder core> -f hasil/sniffer/<platform>/config.yaml` sebelum dipakai.
