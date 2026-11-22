# Template, Group & Ruleset

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

## 🧩 Isi Template & Group

Urutan rule = prioritas (atas ke bawah):

| # | Rule-set | Group tujuan | Fungsi |
|---|---|---|---|
| 1 | `Direct` | DIRECT | LAN, `.local`, `.lan` |
| 2 | `DnsHijack` | 🐬 HIJACK | DNS port 53 |
| 3 | `Reject` | ✂️ REJECT | DoT (853) & QUIC (UDP 443) |
| 4 | `WifiClients` | 🍪 WIFI MODE | Client WiFi/hotspot *(Box saja)* |
| 5 | `Blocker` | 💤 AdBlock | Blokir iklan |
| 6 | `Plusplus` | 💕 Plusplus | Unblock konten +18 |
| 6b | *(inline)* `AND,((NETWORK,UDP),(DST-PORT,3478-3479))` dan `…19302-19309` | 🧩 INJECT | STUN/TURN (WebRTC) dipaksa lewat proxy supaya IP asli tidak bocor *(v0.6)* |
| 7 | `Portgames` | 👾 GAMING | Port game (default Direct) |
| 8 | `Inject` | 🧩 INJECT | Google, Bing, DuckDuckGo |
| 9 | `SmartMode` | 🌳 SMART MODE | AI, game launcher, sosmed, ISP |
| – | `MATCH` | 🧩 INJECT | Sisanya |

Group node (v1.3): **🧩 INJECT** adalah pusat. Semua rule utama dan trafik default menuju ke sini, lalu INJECT memilih dari daftar group di bawah. Node milikmu ada di provider **🗳️ Active** + **📅 Trial**:

| Group | Tipe | Isi / fungsi |
|---|---|---|
| **🗳️ PROXY LIST** | select | Pilih manual dari node **Active** + **Trial** |
| **💫 AUTO MODE** | url-test (`hidden`) | Otomatis memilih node tercepat dari **Active** + **Trial** |
| **💫 FALLBACK** | fallback (`hidden`) | Memakai node pertama yang hidup dari **Active** + **Trial**; pindah ke berikutnya hanya kalau gagal (urutan node di file menentukan prioritas). Dipilih lewat INJECT, SMART MODE, GAMING, Plusplus |
| **🗃️ UPDATER** | fallback (`hidden`) | Jalur download semua rule-provider dan provider 📑 Keyring: **💫 AUTO MODE** dulu, **🎮 DIRECT** kalau semua node mati, supaya update tidak macet saat node belum ada |
| **📄 FREE NODE** | url-test (`hidden`) | Best ping dari provider **📄 Free**. Disembunyikan dari dashboard; dipilih lewat **☘️ FREE NODE** |
| **📑 KEYRING** | url-test (`hidden`) | Best ping dari provider **📑 Keyring**. Disembunyikan dari dashboard; dipilih lewat **🧊 KEYRING** |
| **☘️ FREE NODE** | select | Pilih **📄 FREE NODE** (otomatis) atau node satu per satu dari **📄 Free** |
| **🧊 KEYRING** | select | Pilih **📑 KEYRING** (otomatis) atau node satu per satu dari **📑 Keyring** |

Node gratis datang dari dua provider:

| Provider | Tipe | Isi |
|---|---|---|
| **📑 Keyring** | `http` → `proxy/subs.yaml` | Node dari `subscription.yaml` repo, di-update lewat group 🗃️ UPDATER (node dulu, langsung/DIRECT kalau node mati) |
| **📄 Free** | `file` → `proxy/free.yaml` | Khusus keluaran **sub2yaml**: diisi lewat `1 → 4` (file kosong `proxies: []` dibuat otomatis saat generate, tidak pernah ditimpa) |

Nama group di tabel ini identik dengan `template/config_v1.3.yaml`. Kalau kamu mengganti nama di template, ganti juga di `rules:` dan `proxies:` group yang mengacu ke nama itu. Validator (menu 4) menandai referensi yang salah.

## 📚 Ruleset

| File | Isi |
|---|---|
| `blocker.mrs` | Daftar iklan (domain, format mrs) |
| `plus18.mrs` | Daftar +18 (domain, format mrs) |
| `smartmode.yaml` | Domain/CIDR untuk SMART ROUTING |
| `inject.yaml` | Domain yang selalu lewat Inject |
| `direct.yaml` / `reject.yaml` / `dns-hijack.yaml` | Aturan dasar |
| `wifi.yaml` | Client WiFi (SRC-IP) |
| `port-games.yaml` | 87 range port game (versi penuh ada di `archive/`) |
| `fakeip-filter.yaml` | Domain yang di-resolve IP asli |
| `skip-sniff.yaml` / `force-sniff.yaml` | Daftar sniffer |

Rule-provider di template bertipe `http` (update tiap 24 jam dari GitHub); file di `ruleset/` dipakai sebagai cache awal. Mau 100% offline? Pilih **Mode Offline** saat generate.
