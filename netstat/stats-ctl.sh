#!/system/bin/sh
# Kontrol collector Hikari NetStat (standalone).
# Pakai: sh stats-ctl.sh start|stop|restart|status
# Konfigurasi dibaca dari stats.conf di folder yang sama (lihat stats.conf.example).
# Env STATS_API / STATS_SECRET / STATS_LISTEN / STATS_WIFI / STATS_TZ / STATS_INTERVAL
# menimpa isi stats.conf (berguna buat tes).
D="$(cd "$(dirname "$0")" && pwd)"
CONF="${STATS_CONF:-$D/stats.conf}"

API="http://127.0.0.1:9090"; SECRET=""; LISTEN="127.0.0.1:9099"; WIFI=""; TZ_NAME="Asia/Jakarta"; INTERVAL="3s"
[ -f "$CONF" ] && . "$CONF"
[ -n "${STATS_API:-}" ]      && API="$STATS_API"
[ -n "${STATS_SECRET:-}" ]   && SECRET="$STATS_SECRET"
[ -n "${STATS_LISTEN:-}" ]   && LISTEN="$STATS_LISTEN"
[ -n "${STATS_WIFI:-}" ]     && WIFI="$STATS_WIFI"
[ -n "${STATS_TZ:-}" ]       && TZ_NAME="$STATS_TZ"
[ -n "${STATS_INTERVAL:-}" ] && INTERVAL="$STATS_INTERVAL"

BIN="$D/hikari-stats"; [ -x "$BIN" ] || BIN="$D/bin/hikari-stats"   # bin/ = jalan langsung dari folder hasil extract
PIDF="$D/stats.pid"; LOG="$D/stats.log"

running() {
  [ -f "$PIDF" ] || return 1
  p="$(cat "$PIDF" 2>/dev/null)"; [ -n "$p" ] && [ -d "/proc/$p" ] && grep -q hikari-stats "/proc/$p/cmdline" 2>/dev/null
}

case "$1" in
start)
  running && { echo "sudah jalan (pid $(cat "$PIDF")): http://$LISTEN/"; exit 0; }
  [ -x "$BIN" ] || { echo "$BIN nggak ada / bukan executable"; exit 1; }
  [ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 1048576 ] && mv -f "$LOG" "$LOG.old"
  set -- -api "$API" -data "$D/stats.json" -listen "$LISTEN" -tz "$TZ_NAME" -interval "$INTERVAL"
  [ -n "$WIFI" ] && set -- "$@" -wifi "$WIFI"
  HIKARI_SECRET="$SECRET" "$BIN" "$@" >> "$LOG" 2>&1 &
  echo $! > "$PIDF"; sleep 1
  running && echo "jalan: http://$LISTEN/" || { echo "gagal start, cek $LOG"; rm -f "$PIDF"; exit 1; }
  ;;
stop)
  running || { echo "nggak jalan"; exit 0; }
  p="$(cat "$PIDF")"; kill "$p"
  i=0; while [ -d "/proc/$p" ] && [ $i -lt 10 ]; do sleep 1; i=$((i+1)); done
  [ -d "/proc/$p" ] && kill -9 "$p"
  rm -f "$PIDF"; echo "berhenti (data tersimpan di $D/stats.json)"
  ;;
restart) sh "$0" stop; sh "$0" start ;;
status)
  if running; then echo "jalan (pid $(cat "$PIDF")): http://$LISTEN/"; else echo "mati"; fi
  echo "api: $API | config: $([ -f "$CONF" ] && echo "$CONF" || echo "(belum ada, pakai default)")"
  [ -f "$D/stats.json" ] && echo "data: $D/stats.json ($(wc -c < "$D/stats.json") byte)"
  [ -f "$LOG" ] && { echo "--- log terakhir"; tail -n 5 "$LOG"; }
  ;;
*) echo "pakai: sh stats-ctl.sh start|stop|restart|status"; exit 1 ;;
esac
