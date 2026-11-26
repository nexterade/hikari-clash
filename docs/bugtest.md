# 🧪 Uji Bug / Custom (SNI · Host · Address)

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Uji **banyak domain/IP sekaligus** pada node yang kamu paste: SNI, Host, Address (server) mana yang masih bisa konek. Yang lolos jadi **node varian** + file YAML/URI siap pakai. Kode ada di `bugtest.py` (logika) dan `hikari_converter.py` (menu).

## Alur

1. `1 → 1` **Convert URI ➜ Clash**, paste URI (vless/vmess/trojan) → muncul **Preview**.
2. Pilih aksi **`[U]` Uji bug / custom**.
3. **Yang mau diuji**: SNI, Host, Address (default), Port, Path, ALPN, Fingerprint, Phantom — boleh beberapa. Atau **`L` = Lazy**: isi bug saja, script mencoba semua metode otomatis (lihat [Mode Lazy](#mode-lazy-otomatis-coba-semua-metode)). Tiap field dites **terpisah** (satu field diganti per varian, sisanya tetap seperti node asli).
4. **Kandidat**: paste banyak sekaligus (satu per baris / spasi / koma). `@file.txt` memuat dari file. URL (`https://a.b.com/x`) dan `host:port` dirapikan otomatis; token tidak valid dilewati + dilaporkan.
5. **Mode tes** (boleh lebih dari satu, mis. `1,2`): varian harus lolos **semua** mode yang dipilih, berurutan dari yang termurah (yang sudah gagal tidak ikut mode berikutnya).
6. Script menguji → tampil hasil per field → opsional **uji gabungan terbaik** (SNI tercepat + Host tercepat + Address tercepat dipasang sekaligus dalam 1 node).
7. Hasil disimpan ke `hasil/bugtest/<tanggal_jam>/`, lalu pilih: **tambahkan** varian ke daftar node, **ganti** node asli dengan varian-nya, atau **jangan dipakai**.
8. Kembali ke Preview → `[L]` Lanjut Proses → config Box/Nikki/OpenClash berisi varian itu. Coba di mihomo; atau impor `bug-ok-uri.txt` ke klien v2ray.

Aksi yang sama ada di **Regenerate** (`1 → 3`, pilih satu sumber): `[U]` uji dulu, `[L]` lanjut, `[B]` batal — jadi node yang sudah tersimpan di `active.yaml`/`trial.yaml` juga bisa diuji tanpa paste ulang.

## Mode tes

| Mode | Cara kerja | Catatan |
|---|---|---|
| **TCP/TLS** | DNS → TCP connect → TLS handshake dengan SNI varian → untuk node **WebSocket** kirim HTTP Upgrade (Host + path varian), lolos hanya bila server membalas **101** | Cepat, tanpa core. Sinyal kuat untuk ws (Host/path/SNI salah ditolak CDN dengan 403/404/handshake gagal). Node grpc/h2 hanya sampai TLS, reality hanya TCP, fingerprint tidak bisa dites. **Bukan** bukti proxy tembus internet |
| **Mihomo** | URL-test sungguhan lewat core Mihomo (memakai mesin `sub2yaml.py`: core dicari otomatis, bisa diunduh otomatis) | Tes paling meyakinkan untuk dipakai di Clash |
| **V2Ray/Xray** | Satu proses `xray`/`v2ray` (≥ 5) dengan satu inbound SOCKS per varian, lalu HTTP GET lewat SOCKS5 | Core dicari di `./bin`, `~/.hikari-clash/bin`, `PATH`, atau env `HIKARI_XRAY` / `HIKARI_V2RAY`. **Tidak diunduh otomatis** |

Penting: matikan Box/Nikki/VPN saat menguji. Kalau hampir semua TCP connect ≤ 3 ms, script memperingatkan bahwa koneksi dijawab proxy lokal.

## Address & varian lain

- **Address** mengganti `server`. Kalau node belum punya SNI / Host eksplisit, nilai lama dikunci dulu (supaya SNI & Host tidak ikut berubah ke Address baru) — ini pola umum node di belakang CDN.
- SNI/Address custom otomatis diberi `skip-cert-verify: true` (sertifikat server hampir pasti tidak cocok).
- Field yang tidak berlaku untuk suatu node dilewati dengan alasan (mis. Host di node tcp/grpc, SNI di node tanpa TLS). Kandidat yang sama dengan nilai asli tidak diuji ulang.
- Nama varian: `Nama [sni:cdn.example.com]`, `Nama [addr:104.16.1.1]`, `Nama [combo]`.

## Mode Lazy (otomatis coba semua metode)

Di menu **Yang mau diuji** pilih **`L`**. Kamu cukup mengisi **bug** (domain), **IP edge tambahan** (opsional) dan **port** (Enter = `443,80`); script menyusun semua kombinasi address + port + host + SNI, mengujinya, lalu menunjukkan **metode mana yang cocok** untuk node itu.

Simbol: **S** = domain server, **B** = bug, **IP** = IP edge CDN, **W** = `<bug>.<server>` (wildcard).

| Metode | Address | Host | SNI | Catatan |
|---|---|---|---|---|
| `bug-sni` | S | S | B | server asli, SNI = bug |
| `bug-addr` | B | S | S | address = bug (harus satu CDN dengan server) |
| `ip-edge` | IP | S | S | address = IP edge |
| `host-ip` | S | IP | IP | Host & SNI berupa IP |
| `sni-ip` | S | S | IP | SNI = IP (Go tidak mengirim SNI untuk IP, jadi praktis tanpa SNI) |
| `bug-addr-sni` | B | S | B | |
| `ip-bug-sni` | IP | S | B | |
| `wildcard` | S | W | W | butuh wildcard di server |
| `wildcard-ip` | IP | W | W | |
| `host-bug` | S | B | S | injeksi Host |
| `host-bug-sni` | S | B | B | |

Lima metode pertama adalah pola dari contoh; sisanya tambahan. Aturannya:

- **Domain server (S)** diambil dari Host, lalu SNI, lalu Address node. **IP edge** = Address node (kalau IP) + hasil resolve S (maks 2, pakai DNS operator bila dipilih) + IP tambahan dari kamu. Metode berbasis IP dilewati dengan alasan kalau tidak ada satu pun IP.
- **Port tanpa TLS** (80, 8080, 8880, 2052, 2082, 2086, 2095): TLS dimatikan dan SNI dibuang, jadi kombinasi dengan (address, host) yang sama digabung dan diberi label `http-*` (`http-direct`, `http-bug-addr`, `http-ip-edge`, `http-host-ip`, `http-wildcard`, `http-wildcard-ip`, `http-host-bug`). Port lain dianggap TLS. Trojan, gRPC dan H2 tidak punya varian tanpa TLS.
- **Duplikat efektif dibuang**: kombinasi yang sama dengan config asli, atau yang bedanya hanya di field yang tidak dipakai (mis. Host di node tcp/gRPC), tidak diuji dua kali.
- Semua varian TLS diberi `skip-cert-verify: true`. Hanya node vless/vmess/trojan non-Reality; tipe lain dilewati dengan alasan.
- Tidak ada langkah "gabungan terbaik" di mode ini (tiap varian sudah kombinasi penuh), dan Phantom tidak termasuk (pakai field **Phantom** untuk itu).
- Ukuran tes: 1 bug + 2 IP edge + port `443,80` ≈ **26 varian per node**; tiap bug tambahan menambah ≈ 15. Mulai dari mode TCP/TLS untuk menyaring, lalu konfirmasi pemenangnya di Mihomo.

Hasil: per node tampil kombinasi lolos tercepat (address / host / SNI + port) dan tabel **per metode**; `report.txt` memuat bagian *Ringkasan metode Lazy*; varian lolos ada di `custom-lazy.yaml`, `bug-ok.yaml` dan `bug-ok-uri.txt`.

## Phantom (PhantomNG)

Field **Phantom** menguji kandidat **domain bug** untuk klien PhantomNG (patch Phantom di atas Xray-core): SNI = bug murni, Host = domain server, sertifikat tetap diverifikasi terhadap domain server (bukan terhadap bug).

- **Domain server** diambil dari node asli: **Host** (ws/h2/http), lalu **SNI**, lalu **Address** — yang pertama berupa domain (bukan IP). Pastikan Host di node yang kamu paste memang domain servermu; node tanpa domain sama sekali (Address IP, tanpa Host/SNI) dilewati dengan alasan.
- **Paste link PhantomNG** (`sni=phantom:<server>:<bug>[:rand|:auto]`) juga bisa: node otomatis dinormalkan (SNI = bug, Host = server) dan tetap diuji dengan verifikasi sertifikat. Suffix `rand`/`auto` dipertahankan di `bug-ok-phantom-uri.txt`, tapi **tidak disimulasikan** — tes memakai satu SNI = bug.
- **Verifikasi sertifikat per mode:**

  | Mode | Perilaku untuk varian Phantom |
  |---|---|
  | TCP/TLS | Rantai sertifikat harus valid (CA sistem / `SSL_CERT_FILE`) **dan** berlaku untuk domain server (SAN, wildcard satu label). Gagal dengan pesan `sertifikat tidak cocok dengan <server> (dapat: ...)`. Kalau tidak ada CA yang bisa dimuat (mis. Termux tanpa `ca-certificates`), verifikasi dilewati dan hasilnya diberi catatan `sertifikat tidak diverifikasi` |
  | Mihomo | **Tidak bisa** verifikasi per-nama; hanya `skip-cert-verify: true`. Lolos di sini bukan bukti sertifikat cocok |
  | V2Ray/Xray | `tlsSettings.serverName` = bug, `verifyPeerCertByName` = domain server (tanpa `allowInsecure`) |

- Di gabungan terbaik, Phantom menggantikan SNI biasa (SNI dibuang dari kombinasi) dan domain server tetap dari node asli, bukan dari kandidat Host.
- `custom-phantom.yaml` / `bug-ok.yaml` berisi node Clash biasa (SNI = bug, `skip-cert-verify: true`, tanpa metadata Phantom) supaya aman dipakai di Mihomo; link untuk PhantomNG ada di `bug-ok-phantom-uri.txt`.

## Keluaran (`hasil/bugtest/<tanggal_jam>/`)

| File | Isi |
|---|---|
| `custom-sni.yaml` `custom-host.yaml` `custom-address.yaml` … | Hanya varian **lolos** per field (hanya dibuat bila ada yang lolos) |
| `custom-combined.yaml` | Gabungan terbaik (bila diuji) |
| `bug-ok.yaml` | Semua varian lolos, format `proxies:` Clash |
| `bug-ok-uri.txt` | Link `vless://` / `vmess://` / `trojan://` untuk klien v2ray (v2rayNG, NekoBox, …) |
| `custom-lazy.yaml` | Varian mode Lazy yang lolos (kombinasi address + port + host + SNI) |
| `custom-phantom.yaml` | Varian Phantom yang lolos (SNI = bug, Host = domain server) |
| `bug-ok-phantom-uri.txt` | Varian Phantom sebagai link `sni=phantom:<server>:<bug>:rand` untuk **PhantomNG** (hanya dibuat bila ada varian Phantom yang lolos) |
| `report.txt` | Semua varian: ✓/✗ + alasan, status config asli, field yang dilewati |

## Timeout dan DNS operator

- **Timeout maksimal 30 detik.** API Mihomo mem-parsing parameter timeout sebagai bilangan 16-bit, jadi nilai di atas sekitar 32 detik ditolak dengan error `Body invalid` untuk **semua** node, termasuk config asli yang sehat (dugaan penyebab hasil "0/52 lolos, config asli gagal: urltest: Body invalid" saat timeout diisi 40 detik; belum diuji dengan core asli). Nilai yang lebih besar otomatis dipotong ke 30 detik.
- **DNS operator.** Mode TCP/TLS dan Mihomo menanyakan DNS operator (deteksi dari perangkat `[D]`, preset XL / AXIS, atau manual). Di jaringan operator, IP gratis (cache milik operator) hanya dijawab DNS operator; DNS publik memberi IP lain sehingga uji bisa salah gagal. Mode TCP/TLS memakai klien DNS UDP bawaan; mode Mihomo menambahkan blok `dns` (nameserver, default-nameserver, proxy-server-nameserver) ke config sementara. Kalau DNS operator tidak menjawab, hasilnya `DNS gagal (DNS operator gagal ...)`, bukan diam-diam jatuh ke DNS sistem. Mode V2Ray/Xray belum memakai DNS ini.
- **Matikan Box saat uji.** Box membelokkan semua DNS ke DoH publik sehingga pilihan DNS operator di atas tidak berpengaruh.

## Batasan

- Core asli (mihomo/xray) **belum dites di lingkungan pengembangan** — tes otomatis memakai server WS/TLS/SOCKS5 lokal dan core palsu. Konfigurasi Xray dibangun sesuai dokumentasi (`allowInsecure` dipakai untuk skip-verify; sudah ditandai *deprecated* di Xray, bila core barumu menolaknya hasilnya muncul sebagai "ditolak core").
- Mode V2Ray mendukung vless/vmess/trojan/ss dengan transport tcp, ws, httpupgrade, grpc, h2 + tls/reality. Hysteria/TUIC/WireGuard hanya lewat mode Mihomo. sing-box belum didukung.
- Phantom: yang diuji adalah **padanan di kawat** (SNI = bug, Host = server), bukan kode PhantomNG itu sendiri — `phantom.go` belum dibaca/dites di sini, jadi perilaku persisnya (mis. makna `:rand`) tidak disimulasikan. Nama kunci `verifyPeerCertByName` mengikuti [dokumentasi Xray](https://xtls.github.io/en/config/transports/tls.html); versi core yang lebih baru bisa saja mengganti namanya (core yang tidak mengenalnya akan memverifikasi terhadap SNI = bug sehingga varian gagal).
- Jumlah tes = node × kandidat. Ribuan kandidat di mode core bisa lama; mulai dari mode TCP/TLS untuk menyaring.
