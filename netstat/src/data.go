package main

// data.go: ekspor/impor database, pengaturan batas data, ringkasan buat kartu dashboard,
// dan sampel kecepatan live.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	hariID  = []string{"Min", "Sen", "Sel", "Rab", "Kam", "Jum", "Sab"}
	bulanID = []string{"", "Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"}
)

func dayLabel(t time.Time) string {
	return fmt.Sprintf("%s %d %s", hariID[t.Weekday()], t.Day(), bulanID[t.Month()])
}

// ---------- pengaturan (batas data) ----------

type Settings struct {
	LimitBytes int64  `json:"limitBytes"` // 0 = tanpa batas
	ResetDay   int    `json:"resetDay"`   // tanggal reset kuota, 1..28
	Net        string `json:"net"`        // yang dihitung: data | wifi | all
}

func (st Settings) norm() Settings {
	if st.LimitBytes < 0 {
		st.LimitBytes = 0
	}
	if st.ResetDay < 1 || st.ResetDay > 28 {
		st.ResetDay = 1
	}
	if st.Net != "wifi" && st.Net != "all" {
		st.Net = "data"
	}
	return st
}

// ---------- kecepatan live ----------

type Sample struct {
	T    int64 `json:"t"`    // unix detik
	Up   int64 `json:"up"`   // byte/detik
	Down int64 `json:"down"` // byte/detik
}

const liveMax = 100 // ~5 menit pada interval 3 dtk

type Live struct {
	mu    sync.Mutex
	s     []Sample
	conns int
}

func (l *Live) push(sm Sample) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.s = append(l.s, sm)
	if len(l.s) > liveMax {
		l.s = append([]Sample(nil), l.s[len(l.s)-liveMax:]...)
	}
}

func (l *Live) setConns(n int) {
	l.mu.Lock()
	l.conns = n
	l.mu.Unlock()
}

func (l *Live) snapshot() ([]Sample, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Sample, len(l.s))
	copy(out, l.s)
	return out, l.conns
}

// ---------- ringkasan buat kartu ----------

type Record struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Total int64  `json:"total"`
}

type LimitInfo struct {
	Bytes       int64  `json:"bytes"` // 0 = belum diatur
	ResetDay    int    `json:"resetDay"`
	Net         string `json:"net"`
	Used        int64  `json:"used"`
	Remaining   int64  `json:"remaining"` // bisa negatif kalau terlampaui
	PerDay      int64  `json:"perDay"`    // sisa / hari tersisa (termasuk hari ini)
	Avg         int64  `json:"avg"`
	Projected   int64  `json:"projected"` // perkiraan total akhir periode
	Start       string `json:"start"`
	End         string `json:"end"`
	DaysTotal   int    `json:"daysTotal"`
	DaysElapsed int    `json:"daysElapsed"`
	Left        int    `json:"left"` // hari tersisa termasuk hari ini
}

type Overview struct {
	MonthDay    int       `json:"monthDay"`
	MonthDays   int       `json:"monthDays"`
	Busiest     *Record   `json:"busiest,omitempty"`
	Streak      int       `json:"streak"` // hari berturut-turut (sampai hari ini) yang ada trafik
	TrackedDays int       `json:"trackedDays"`
	Limit       LimitInfo `json:"limit"`
}

func ctrTotal(c *Ctr) int64 {
	if c == nil {
		return 0
	}
	return c.Up + c.Down
}

// dayTotal = WiFi + data seluler (internal nggak dihitung, sama seperti total di UI).
func dayTotal(d *Day) int64 {
	if d == nil {
		return 0
	}
	return ctrTotal(d.Nets[NetWifi]) + ctrTotal(d.Nets[NetData])
}

// buildOverview dipanggil dengan s.mu SUDAH dipegang (dari buildSummary).
func buildOverview(s *Store, now time.Time, loc *time.Location) Overview {
	now = now.In(loc)
	day0 := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	ov := Overview{
		MonthDay:  now.Day(),
		MonthDays: time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, loc).Day(),
	}

	var best int64
	for k, d := range s.f.Days {
		t := dayTotal(d)
		if t <= 0 {
			continue
		}
		ov.TrackedDays++
		if t > best || (t == best && ov.Busiest != nil && k > ov.Busiest.Key) {
			if tm, err := time.ParseInLocation("2006-01-02", k, loc); err == nil {
				best = t
				ov.Busiest = &Record{Key: k, Label: dayLabel(tm), Total: t}
			}
		}
	}

	// streak: kalau hari ini belum ada trafik (mis. baru lewat tengah malam), hitung dari kemarin
	off := 0
	if dayTotal(s.f.Days[day0.Format("2006-01-02")]) <= 0 {
		off = 1
	}
	for i := off; i <= len(s.f.Days)+1; i++ {
		if dayTotal(s.f.Days[day0.AddDate(0, 0, -i).Format("2006-01-02")]) <= 0 {
			break
		}
		ov.Streak++
	}

	ov.Limit = buildLimit(s, now, loc)
	return ov
}

// buildLimit: pemakaian pada periode kuota berjalan (reset tiap tanggal ResetDay). s.mu sudah dipegang.
func buildLimit(s *Store, now time.Time, loc *time.Location) LimitInfo {
	cfg := s.f.Settings.norm()
	now = now.In(loc)
	day0 := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	start := time.Date(day0.Year(), day0.Month(), cfg.ResetDay, 0, 0, 0, 0, loc)
	if day0.Before(start) {
		start = start.AddDate(0, -1, 0)
	}
	next := start.AddDate(0, 1, 0)
	li := LimitInfo{
		Bytes:       cfg.LimitBytes,
		ResetDay:    cfg.ResetDay,
		Net:         cfg.Net,
		Start:       start.Format("2006-01-02"),
		End:         next.AddDate(0, 0, -1).Format("2006-01-02"),
		DaysTotal:   int(next.Sub(start).Hours()/24 + 0.5),
		DaysElapsed: int(day0.Sub(start).Hours()/24+0.5) + 1,
	}
	for d := start; !d.After(day0); d = d.AddDate(0, 0, 1) {
		dd := s.f.Days[d.Format("2006-01-02")]
		if dd == nil {
			continue
		}
		switch cfg.Net {
		case "wifi":
			li.Used += ctrTotal(dd.Nets[NetWifi])
		case "all":
			li.Used += ctrTotal(dd.Nets[NetWifi]) + ctrTotal(dd.Nets[NetData])
		default:
			li.Used += ctrTotal(dd.Nets[NetData])
		}
	}
	if li.DaysElapsed > 0 {
		li.Avg = li.Used / int64(li.DaysElapsed)
		li.Projected = li.Used * int64(li.DaysTotal) / int64(li.DaysElapsed)
	}
	li.Left = li.DaysTotal - li.DaysElapsed + 1
	if li.Left < 1 {
		li.Left = 1
	}
	if cfg.LimitBytes > 0 {
		li.Remaining = cfg.LimitBytes - li.Used
		if li.Remaining > 0 {
			li.PerDay = li.Remaining / int64(li.Left)
		}
	}
	return li
}

// ---------- ekspor / impor ----------

const (
	maxImportBytes = 64 << 20
	maxImportDays  = 20000
	keepBackups    = 5
)

type ImportResult struct {
	OK      bool   `json:"ok"`
	Mode    string `json:"mode"`
	Added   int    `json:"added"`   // hari yang belum ada, ditambahkan
	Merged  int    `json:"merged"`  // hari yang angkanya dijumlahkan (mode add)
	Skipped int    `json:"skipped"` // hari yang dilewati (mode fill)
	Days    int    `json:"days"`    // total hari di database sekarang
	Backup  string `json:"backup,omitempty"`
}

func (s *Store) exportJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(&s.f)
}

// parseImport membaca + memvalidasi file statistik (format sama dengan stats.json).
func parseImport(r io.Reader) (*File, error) {
	var f File
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("bukan file statistik Hikari yang valid (%v)", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("versi file %d tidak didukung (yang didukung: 1)", f.Version)
	}
	if len(f.Days) > maxImportDays {
		return nil, fmt.Errorf("terlalu banyak hari (%d, maksimal %d)", len(f.Days), maxImportDays)
	}
	bad := func(c *Ctr) bool { return c == nil || c.Up < 0 || c.Down < 0 || c.Conns < 0 }
	for k, d := range f.Days {
		if _, err := time.Parse("2006-01-02", k); err != nil {
			return nil, fmt.Errorf("kunci tanggal %q bukan format YYYY-MM-DD", k)
		}
		if d == nil {
			delete(f.Days, k)
			continue
		}
		if d.Nets == nil {
			d.Nets = map[string]*Ctr{}
		}
		for n, c := range d.Nets {
			if n == "" || bad(c) {
				return nil, fmt.Errorf("angka jaringan %q pada %s rusak", n, k)
			}
		}
		if d.Dims == nil {
			d.Dims = map[string]map[string]*Ctr{}
		}
		for dim, m := range d.Dims {
			for key, c := range m {
				// kunci wajib "net|nama": kode lain memotong di tanda "|"
				if bad(c) || !strings.Contains(key, "|") {
					return nil, fmt.Errorf("data %s/%q pada %s rusak", dim, key, k)
				}
			}
		}
	}
	if len(f.Days) == 0 {
		return nil, errors.New("file tidak berisi data harian")
	}
	if f.Started < 0 {
		f.Started = 0
	}
	if f.Settings != (Settings{}) {
		f.Settings = f.Settings.norm()
	}
	return &f, nil
}

func mergeDay(dst, src *Day) {
	for n, c := range src.Nets {
		dst.net(n).add(c.Up, c.Down, c.Conns)
	}
	for dim, m := range src.Dims {
		for key, c := range m {
			i := strings.Index(key, "|")
			dst.dim(dim, key[:i], key[i+1:]).add(c.Up, c.Down, c.Conns)
		}
	}
}

func (s *Store) pruneBackups(keep int) {
	m, _ := filepath.Glob(s.path + ".bak-*")
	if len(m) <= keep {
		return
	}
	sort.Strings(m)
	for _, f := range m[:len(m)-keep] {
		_ = os.Remove(f)
	}
}

// writeBackupLocked: s.mu harus dipegang.
func (s *Store) writeBackupLocked() (string, error) {
	b, err := json.Marshal(&s.f)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dirOf(s.path), 0o755); err != nil {
		return "", err
	}
	bak := s.path + ".bak-" + time.Now().Format("20060102-150405")
	if err := os.WriteFile(bak, b, 0o644); err != nil {
		return "", err
	}
	s.pruneBackups(keepBackups)
	return bak, nil
}

// applyImport: mode "replace" (ganti semua), "add" (jumlahkan per hari), "fill" (hanya hari yang belum ada).
// Database sekarang dicadangkan dulu; kalau backup gagal, impor dibatalkan.
func (s *Store) applyImport(in *File, mode string) (ImportResult, error) {
	res := ImportResult{Mode: mode}
	switch mode {
	case "replace", "add", "fill":
	default:
		return res, fmt.Errorf("mode %q tidak dikenal (pakai fill, add, atau replace)", mode)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.f.Days) > 0 {
		bak, err := s.writeBackupLocked()
		if err != nil {
			return res, fmt.Errorf("gagal membuat cadangan, impor dibatalkan: %v", err)
		}
		res.Backup = bak
	}

	switch mode {
	case "replace":
		started, settings := in.Started, in.Settings
		if started == 0 {
			started = s.f.Started
		}
		if settings == (Settings{}) {
			settings = s.f.Settings
		}
		res.Added = len(in.Days)
		s.f = File{Version: 1, Started: started, Days: in.Days, Settings: settings}
	default:
		for k, d := range in.Days {
			cur := s.f.Days[k]
			switch {
			case cur == nil:
				s.f.Days[k] = d
				res.Added++
			case mode == "add":
				mergeDay(cur, d)
				res.Merged++
			default:
				res.Skipped++
			}
		}
		if in.Started != 0 && (s.f.Started == 0 || in.Started < s.f.Started) {
			s.f.Started = in.Started
		}
		if s.f.Settings == (Settings{}) && in.Settings != (Settings{}) {
			s.f.Settings = in.Settings
		}
	}
	s.dirty = true
	res.Days = len(s.f.Days)
	return res, nil
}

// runOffline: dipakai flag -import / -export (collector sebaiknya dihentikan dulu).
func runOffline(st *Store, exportTo, importFrom, mode string) error {
	if importFrom != "" {
		fh, err := os.Open(importFrom)
		if err != nil {
			return err
		}
		defer fh.Close()
		in, err := parseImport(fh)
		if err != nil {
			return fmt.Errorf("impor %s: %v", importFrom, err)
		}
		res, err := st.applyImport(in, mode)
		if err != nil {
			return err
		}
		st.flush()
		log.Printf("impor selesai (mode %s): %d hari baru, %d digabung, %d dilewati, total %d hari; cadangan: %q",
			res.Mode, res.Added, res.Merged, res.Skipped, res.Days, res.Backup)
	}
	if exportTo != "" {
		b, err := st.exportJSON()
		if err != nil {
			return err
		}
		if err := os.WriteFile(exportTo, b, 0o644); err != nil {
			return err
		}
		log.Printf("ekspor selesai: %s (%d byte)", exportTo, len(b))
	}
	return nil
}

// ---------- endpoint HTTP ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// guardPost: hanya POST + header kustom X-Hikari. Header kustom memaksa preflight CORS,
// jadi halaman web lain di browser HP nggak bisa menembak endpoint ini diam-diam.
func guardPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "pakai metode POST"})
		return false
	}
	if r.Header.Get("X-Hikari") == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "header X-Hikari wajib ada"})
		return false
	}
	return true
}

func registerExtra(mux *http.ServeMux, s *Store, st *Status, loc *time.Location, live *Live) {
	if live == nil {
		live = &Live{}
	}

	mux.HandleFunc("/api/live", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		ok, last, lerr := st.OK, st.LastPoll, st.LastErr
		st.mu.Unlock()
		samples, conns := live.snapshot()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": ok, "lastPoll": last, "lastErr": lerr, "now": time.Now().Unix(),
			"conns": conns, "samples": samples,
		})
	})

	mux.HandleFunc("/api/export.json", func(w http.ResponseWriter, r *http.Request) {
		b, err := s.exportJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="hikari-stats-`+time.Now().In(loc).Format("20060102")+`.json"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/api/import", func(w http.ResponseWriter, r *http.Request) {
		if !guardPost(w, r) {
			return
		}
		mode := r.URL.Query().Get("mode")
		if mode == "" {
			mode = "fill" // paling aman: nggak menimpa dan nggak bikin angka dobel
		}
		in, err := parseImport(http.MaxBytesReader(w, r.Body, maxImportBytes))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		res, err := s.applyImport(in, mode)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		s.flush()
		res.OK = true
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if !guardPost(w, r) {
			return
		}
		var in Settings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "JSON salah: " + err.Error()})
			return
		}
		switch {
		case in.LimitBytes < 0 || in.LimitBytes > 1<<50:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "batas di luar jangkauan"})
			return
		case in.ResetDay < 1 || in.ResetDay > 28:
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "tanggal reset harus 1-28"})
			return
		case in.Net != "data" && in.Net != "wifi" && in.Net != "all":
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "net harus data, wifi, atau all"})
			return
		}
		s.mu.Lock()
		s.f.Settings = in
		s.dirty = true
		s.mu.Unlock()
		s.flush()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
}
