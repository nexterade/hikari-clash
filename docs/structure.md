# 📂 Struktur Folder

> [← Kembali ke README](../README.md) · [Dokumentasi lainnya](../README.md#-dokumentasi)

```text
hikari-clash/
├── hikari_converter.py          # Script utama (menu & generator)
├── banner.py                    # Banner Hikari /.CLASH
├── mrs_codec.py                 # Codec rule-set .mrs ⇄ .yaml/.txt   (menu 5)
├── sub2yaml.py                  # Subscription (base64) ➜ YAML Clash, dites & diurut; hasilnya diimpor ke ☘️ FREE NODE (menu 1 → 4)
├── src/                         # Sumber subscription untuk sub2yaml: barry-far.txt, 0xRadikal.txt, roosterkid.txt (update lewat menu [8] sub2yaml)
├── bin/                         # (otomatis, tidak di-commit) core mihomo hasil unduh sub2yaml; di /sdcard dipasang di ~/.hikari-clash/bin
├── bugtest.py                   # Uji Bug / Custom: tes banyak SNI·Host·Address (TCP/Mihomo/V2Ray)   (menu 1 → [U])
├── nodetest.py                  # Tester node proxy                  (menu 5)
├── routetest.py                 # Tester route domain/IP             (menu 5)
├── sniffer.py                   # Inspector koneksi (Sniffer Only)   (menu 5)
├── template/
│   ├── sniffer_only.yaml        # Config pengintai: tanpa node, semua DIRECT (bukan template konversi; tidak ikut glob config_v*.yaml)
│   ├── config_v1.3.yaml         # Template master terbaru (netral; 💫 FALLBACK, 🗃️ UPDATER; URL test Cloudflare)
│   ├── config_v1.2.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v1.1.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v1.0.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.9.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.8.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.7.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.6.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.5.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.4.yaml         # Template master lama (dibiarkan utuh)
│   ├── config_v0.3.yaml         # Template master lama (dibiarkan utuh)
│   └── template.yaml            # (otomatis) salinan kerja, dibuat saat kamu edit lewat menu
├── subscription.yaml            # Node gratis (100 node, dibuat sub2yaml.py) — URL raw-nya dipakai provider 📑 Keyring
├── emoji.json                   # Daftar emoji nama node (edit lewat menu atau langsung di file)
├── settings.json                # (otomatis, tidak di-commit) pengaturan pengguna: profil ISP
├── ruleset/                     # Ruleset (WAJIB): *.yaml & *.mrs
├── archive/                     # Template lama v0.1/v0.2 + port-games versi penuh
├── tests/                       # Tes otomatis: python3 -m unittest discover -s tests
├── netstat/                     # Hikari NetStat: collector statistik trafik, standalone (docs/netstat.md)
│   ├── bin/hikari-stats         #   binary arm64
│   ├── src/                     #   kode Go + ui/index.html + tes
│   ├── install.sh  stats-ctl.sh  stats.conf.example  build.sh
├── docs/                        # Dokumentasi lengkap (usage, faq, tips, …)
│   └── img/                     #   Screenshot untuk README
├── AUDIT.md                     # Perbandingan template, temuan audit, saran
└── hasil/                       # (otomatis) hasil generate
    ├── full_config_box/
    ├── full_config_nikki/
    ├── full_config_openclash/
    ├── bugtest/<tanggal_jam>/   # hasil Uji Bug: custom-*.yaml, bug-ok.yaml, bug-ok-uri.txt, report.txt
    └── rules/                   # hasil Rule-Provider Converter (menu 5)
```

Template yang dipakai: **`template/template.yaml`** bila ada, kalau tidak **`template/config_v*.yaml` terbaru**. Edit lewat menu selalu mengubah `template/template.yaml`; template master tidak pernah disentuh. Template baru ditambahkan sebagai file baru (`config_v0.5.yaml`, dst.), versi lama tidak ditimpa.

> Upgrade dari layout lama? Saat dijalankan, script otomatis memindahkan `Hasil/` → `hasil/` dan `template.yaml` (root) → `template/template.yaml`.
