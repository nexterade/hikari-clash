#!/system/bin/sh
# Pasang / copot Hikari NetStat (standalone). Jalankan sebagai root dari folder hasil extract.
#   sh install.sh              pasang (atau update) + jalan otomatis tiap boot
#   sh install.sh uninstall    copot (stats.json & stats.conf tetap disimpan)
# Override buat tes: STATS_DIR=/path SERVICE_D=/path LEGACY_DIR=/path sh install.sh
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DST="${STATS_DIR:-/data/adb/hikari-stats}"
SVC="${SERVICE_D:-/data/adb/service.d}"
LEGACY="${LEGACY_DIR:-/data/adb/box/stats}"     # lokasi versi lama (ikut Box), dipakai buat migrasi data

if [ "$1" = "uninstall" ]; then
  [ -f "$DST/stats-ctl.sh" ] && sh "$DST/stats-ctl.sh" stop || true
  rm -f "$SVC/hikari-stats.sh" "$DST/hikari-stats" "$DST/stats-ctl.sh" "$DST/stats.pid"
  echo "dicopot. Data & config tetap ada di $DST (stats.json, stats.conf); hapus foldernya kalau mau bersih total."
  exit 0
fi

[ -f "$SRC/bin/hikari-stats" ] || { echo "binary nggak ada di $SRC/bin"; exit 1; }
[ -f "$SRC/stats-ctl.sh" ]     || { echo "stats-ctl.sh nggak ada di $SRC"; exit 1; }
mkdir -p "$DST" "$SVC"

# versi lama (di folder Box) dihentikan dulu supaya port 9099 nggak bentrok; datanya disalin, bukan dipindah
if [ -f "$LEGACY/stats-ctl.sh" ] && [ "$LEGACY" != "$DST" ]; then
  sh "$LEGACY/stats-ctl.sh" stop || true
  if [ -f "$LEGACY/stats.json" ] && [ ! -f "$DST/stats.json" ]; then
    cp -p "$LEGACY/stats.json" "$DST/stats.json" && echo "data lama disalin dari $LEGACY/stats.json"
  fi
fi

[ -f "$DST/stats-ctl.sh" ] && sh "$DST/stats-ctl.sh" stop || true
cp -f "$SRC/bin/hikari-stats" "$DST/hikari-stats"
cp -f "$SRC/stats-ctl.sh" "$DST/stats-ctl.sh"
chmod 0755 "$DST/hikari-stats" "$DST/stats-ctl.sh"      # stats.json & stats.conf yang sudah ada nggak disentuh
if [ ! -f "$DST/stats.conf" ]; then
  cp -f "$SRC/stats.conf.example" "$DST/stats.conf"
  chmod 0600 "$DST/stats.conf"                           # bisa berisi secret
  echo "config dibuat: $DST/stats.conf  (isi SECRET kalau controller Mihomo pakai secret)"
fi

cat > "$SVC/hikari-stats.sh" <<EOF
#!/system/bin/sh
# Jalankan Hikari NetStat setelah boot selesai
(
  until [ "\$(getprop sys.boot_completed)" = "1" ]; do sleep 5; done
  sleep 20
  sh $DST/stats-ctl.sh start
) >/dev/null 2>&1 &
EOF
chmod 0755 "$SVC/hikari-stats.sh"

sh "$DST/stats-ctl.sh" start
echo "Laporan: buka http://127.0.0.1:9099/ di browser HP."
