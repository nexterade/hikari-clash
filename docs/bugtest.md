# 🧪 Uji Bug / Custom (SNI · Host · Address)

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

Uji **banyak domain/IP sekaligus** pada node yang kamu paste: SNI, Host, Address (server) mana yang masih bisa konek. Yang lolos jadi **node varian** + file YAML/URI siap pakai. Kode ada di `bugtest.py` (logika) dan `hikari_converter.py` (menu).

## Alur

1. `1 → 1` **Convert URI ➜ Clash**, paste URI (vless/vmess/trojan) → muncul **Preview**.
2. Pilih aksi **`[U]` Uji bug / custom**.
3. **Yang mau diuji**: SNI, Host, Address (default), Port, Path, ALPN, Fingerprint — boleh beberapa. Tiap field dites **terpisah** (satu field diganti per varian, sisanya tetap seperti node asli).
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

## Keluaran (`hasil/bugtest/<tanggal_jam>/`)

| File | Isi |
|---|---|
| `custom-sni.yaml` `custom-host.yaml` `custom-address.yaml` … | Hanya varian **lolos** per field (hanya dibuat bila ada yang lolos) |
| `custom-combined.yaml` | Gabungan terbaik (bila diuji) |
| `bug-ok.yaml` | Semua varian lolos, format `proxies:` Clash |
| `bug-ok-uri.txt` | Link `vless://` / `vmess://` / `trojan://` untuk klien v2ray (v2rayNG, NekoBox, …) |
| `report.txt` | Semua varian: ✓/✗ + alasan, status config asli, field yang dilewati |

## Timeout dan DNS operator

- **Timeout maksimal 30 detik.** API Mihomo mem-parsing parameter timeout sebagai bilangan 16-bit, jadi nilai di atas sekitar 32 detik ditolak dengan error `Body invalid` untuk **semua** node, termasuk config asli yang sehat (dugaan penyebab hasil "0/52 lolos, config asli gagal: urltest: Body invalid" saat timeout diisi 40 detik; belum diuji dengan core asli). Nilai yang lebih besar otomatis dipotong ke 30 detik.
- **DNS operator.** Mode TCP/TLS dan Mihomo menanyakan DNS operator (deteksi dari perangkat `[D]`, preset XL / AXIS, atau manual). Di jaringan operator, IP gratis (cache milik operator) hanya dijawab DNS operator; DNS publik memberi IP lain sehingga uji bisa salah gagal. Mode TCP/TLS memakai klien DNS UDP bawaan; mode Mihomo menambahkan blok `dns` (nameserver, default-nameserver, proxy-server-nameserver) ke config sementara. Kalau DNS operator tidak menjawab, hasilnya `DNS gagal (DNS operator gagal ...)`, bukan diam-diam jatuh ke DNS sistem. Mode V2Ray/Xray belum memakai DNS ini.
- **Matikan Box saat uji.** Box membelokkan semua DNS ke DoH publik sehingga pilihan DNS operator di atas tidak berpengaruh.

## Batasan

- Core asli (mihomo/xray) **belum dites di lingkungan pengembangan** — tes otomatis memakai server WS/TLS/SOCKS5 lokal dan core palsu. Konfigurasi Xray dibangun sesuai dokumentasi (`allowInsecure` dipakai untuk skip-verify; sudah ditandai *deprecated* di Xray, bila core barumu menolaknya hasilnya muncul sebagai "ditolak core").
- Mode V2Ray mendukung vless/vmess/trojan/ss dengan transport tcp, ws, httpupgrade, grpc, h2 + tls/reality. Hysteria/TUIC/WireGuard hanya lewat mode Mihomo. sing-box belum didukung.
- Jumlah tes = node × kandidat. Ribuan kandidat di mode core bisa lama; mulai dari mode TCP/TLS untuk menyaring.
