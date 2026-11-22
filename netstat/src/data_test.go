package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, *time.Location) {
	t.Helper()
	loc, _ := time.LoadLocation("Asia/Jakarta")
	st := &Store{path: filepath.Join(t.TempDir(), "s.json"), loc: loc}
	st.load()
	return st, loc
}

// total WiFi = wifiDown+1, total data = dataDown+2
func seedDay(st *Store, key string, wifiDown, dataDown int64) {
	d := newDay()
	d.Nets[NetWifi] = &Ctr{Down: wifiDown, Up: 1}
	d.Nets[NetData] = &Ctr{Down: dataDown, Up: 2}
	d.dim("proc", NetData, "com.x").add(2, dataDown, 1)
	st.f.Days[key] = d
}

func TestExportImportRoundtrip(t *testing.T) {
	a, _ := testStore(t)
	seedDay(a, "2026-10-19", 1000, 10)
	seedDay(a, "2026-10-20", 2000, 20)
	a.f.Settings = Settings{LimitBytes: 5e9, ResetDay: 5, Net: "all"}
	b, err := a.exportJSON()
	if err != nil {
		t.Fatal(err)
	}
	in, err := parseImport(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := testStore(t)
	res, err := c.applyImport(in, "replace")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 2 || len(c.f.Days) != 2 || res.Backup != "" {
		t.Fatalf("hasil impor: %+v", res)
	}
	if got := c.f.Days["2026-10-20"].Nets[NetWifi].Down; got != 2000 {
		t.Fatalf("wifi 20 okt = %d", got)
	}
	if c.f.Settings.ResetDay != 5 || c.f.Settings.LimitBytes != 5e9 {
		t.Fatalf("settings nggak ikut: %+v", c.f.Settings)
	}
}

func TestImportModes(t *testing.T) {
	st, _ := testStore(t)
	seedDay(st, "2026-10-19", 1000, 10)
	mk := func() *File {
		f := &File{Version: 1, Started: 123, Days: map[string]*Day{}}
		d := newDay()
		d.Nets[NetWifi] = &Ctr{Down: 500}
		d.dim("proc", NetWifi, "com.y").add(0, 500, 0)
		f.Days["2026-10-19"] = d
		d2 := newDay()
		d2.Nets[NetWifi] = &Ctr{Down: 7}
		f.Days["2026-10-18"] = d2
		return f
	}

	// fill: hanya hari yang belum ada
	res, err := st.applyImport(mk(), "fill")
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || res.Skipped != 1 || res.Days != 2 {
		t.Fatalf("fill: %+v", res)
	}
	if st.f.Days["2026-10-19"].Nets[NetWifi].Down != 1000 {
		t.Fatal("fill menimpa hari yang sudah ada")
	}
	if res.Backup == "" {
		t.Fatal("harusnya bikin cadangan")
	}
	if _, err := os.Stat(res.Backup); err != nil {
		t.Fatalf("file cadangan nggak ada: %v", err)
	}

	// add: jumlahkan
	res, err = st.applyImport(mk(), "add")
	if err != nil {
		t.Fatal(err)
	}
	if res.Merged != 2 || res.Added != 0 {
		t.Fatalf("add: %+v", res)
	}
	if got := st.f.Days["2026-10-19"].Nets[NetWifi].Down; got != 1500 {
		t.Fatalf("add wifi 19 okt = %d, harusnya 1500", got)
	}
	if got := st.f.Days["2026-10-18"].Nets[NetWifi].Down; got != 14 {
		t.Fatalf("add wifi 18 okt = %d, harusnya 14", got)
	}
	if got := st.f.Days["2026-10-19"].Dims["proc"]["wifi|com.y"].Down; got != 500 {
		t.Fatalf("dim ikut digabung? %d", got)
	}
	if st.f.Started != 123 {
		t.Fatalf("started harus ambil yang paling awal: %d", st.f.Started)
	}

	// replace: ganti semua
	res, err = st.applyImport(mk(), "replace")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.f.Days) != 2 || st.f.Days["2026-10-19"].Nets[NetWifi].Down != 500 || res.Added != 2 {
		t.Fatalf("replace: %+v", res)
	}

	// mode ngawur ditolak sebelum menyentuh apa pun
	if _, err := st.applyImport(mk(), "hapus"); err == nil {
		t.Fatal("mode ngawur harusnya ditolak")
	}
}

func TestImportRejectsBadFiles(t *testing.T) {
	cases := map[string]string{
		"bukan json": `halo`,
		"versi":      `{"version":2,"days":{"2026-10-19":{"nets":{}}}}`,
		"kosong":     `{"version":1,"days":{}}`,
		"tanggal":    `{"version":1,"days":{"kemarin":{"nets":{}}}}`,
		"negatif":    `{"version":1,"days":{"2026-10-19":{"nets":{"wifi":{"up":-1,"down":0,"conns":0}}}}}`,
		"kunci dim":  `{"version":1,"days":{"2026-10-19":{"nets":{},"dims":{"proc":{"tanpa-pipa":{"up":1,"down":1,"conns":0}}}}}}`,
	}
	for name, body := range cases {
		if _, err := parseImport(strings.NewReader(body)); err == nil {
			t.Errorf("%s: harusnya ditolak", name)
		}
	}
	ok := `{"version":1,"days":{"2026-10-19":{"nets":{"wifi":{"up":1,"down":2,"conns":0}}}}}`
	if _, err := parseImport(strings.NewReader(ok)); err != nil {
		t.Fatalf("file valid ditolak: %v", err)
	}
}

func TestLimitInfo(t *testing.T) {
	st, loc := testStore(t)
	st.f.Settings = Settings{LimitBytes: 10000, ResetDay: 15, Net: "data"}
	seedDay(st, "2026-10-14", 0, 5000-2) // sebelum periode: nggak dihitung
	seedDay(st, "2026-10-15", 0, 1000-2)
	seedDay(st, "2026-10-20", 0, 2000-2)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)

	st.mu.Lock()
	li := buildLimit(st, now, loc)
	st.mu.Unlock()
	if li.Start != "2026-10-15" || li.End != "2026-11-14" || li.DaysTotal != 31 || li.DaysElapsed != 6 {
		t.Fatalf("periode: %+v", li)
	}
	if li.Used != 3000 || li.Avg != 500 || li.Projected != 15500 || li.Remaining != 7000 || li.Left != 26 || li.PerDay != 269 {
		t.Fatalf("angka: %+v", li)
	}

	// sebelum tanggal reset -> periode dimulai bulan lalu
	st.mu.Lock()
	li = buildLimit(st, time.Date(2026, 10, 10, 12, 0, 0, 0, loc), loc)
	st.mu.Unlock()
	if li.Start != "2026-09-15" || li.End != "2026-10-14" || li.DaysTotal != 30 || li.DaysElapsed != 26 {
		t.Fatalf("periode sebelum reset: %+v", li)
	}
}

func TestOverview(t *testing.T) {
	st, loc := testStore(t)
	for _, k := range []string{"2026-10-17", "2026-10-18", "2026-10-19", "2026-10-20"} {
		seedDay(st, k, 100, 0)
	}
	seedDay(st, "2026-10-10", 9999, 0) // terboros, tapi streak putus sebelum ini
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)

	st.mu.Lock()
	ov := buildOverview(st, now, loc)
	st.mu.Unlock()
	if ov.Streak != 4 || ov.TrackedDays != 5 || ov.MonthDay != 20 || ov.MonthDays != 31 {
		t.Fatalf("overview: %+v", ov)
	}
	if ov.Busiest == nil || ov.Busiest.Key != "2026-10-10" {
		t.Fatalf("hari terboros: %+v", ov.Busiest)
	}

	// hari ini belum ada trafik -> streak dihitung dari kemarin
	st.mu.Lock()
	ov = buildOverview(st, time.Date(2026, 10, 21, 0, 5, 0, 0, loc), loc)
	st.mu.Unlock()
	if ov.Streak != 4 {
		t.Fatalf("streak lewat tengah malam: %d", ov.Streak)
	}
}

func TestLiveRate(t *testing.T) {
	var cur []fc
	var tu, td int64
	srv := serve(t, &cur, &tu, &td)
	defer srv.Close()
	st, loc := testStore(t)
	cls := &Classifier{wifi: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}
	p := &Poller{api: srv.URL, secret: "s3", cl: srv.Client(), store: st, cls: cls, st: &Status{}, last: map[string]seenConn{}, baseline: true, share: map[string]float64{}}
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, loc)

	p.poll(t0) // baseline
	tu, td = 600, 3000
	p.poll(t0.Add(3 * time.Second))
	s, _ := p.live.snapshot()
	if len(s) != 1 || s[0].Down != 1000 || s[0].Up != 200 {
		t.Fatalf("sampel: %+v", s)
	}

	// core restart (counter turun): nggak ada sampel baru dan nggak ada nilai negatif
	tu, td = 5, 10
	p.poll(t0.Add(6 * time.Second))
	s, _ = p.live.snapshot()
	if len(s) != 1 {
		t.Fatalf("restart nambah sampel: %+v", s)
	}
}

func TestHTTPDataEndpoints(t *testing.T) {
	st, loc := testStore(t)
	seedDay(st, "2026-10-19", 1000, 10)
	ts := httptest.NewServer(newMux(st, &Classifier{}, &Status{}, loc, &Live{}))
	defer ts.Close()

	r, err := http.Get(ts.URL + "/api/export.json")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !strings.Contains(r.Header.Get("Content-Disposition"), "hikari-stats-") {
		t.Fatalf("export: %d %q", r.StatusCode, r.Header.Get("Content-Disposition"))
	}
	var f File
	if err := json.Unmarshal(body, &f); err != nil || f.Days["2026-10-19"] == nil {
		t.Fatalf("isi export salah: %v", err)
	}

	post := func(path string, payload []byte, header bool) (int, string) {
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(payload))
		if header {
			req.Header.Set("X-Hikari", "1")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := post("/api/import?mode=replace", body, false); code != http.StatusForbidden {
		t.Fatalf("tanpa header harus 403, dapat %d", code)
	}
	if code, out := post("/api/import?mode=fill", body, true); code != 200 {
		t.Fatalf("impor fill: %d %s", code, out)
	}
	if code, _ := post("/api/import?mode=ngawur", body, true); code != http.StatusBadRequest {
		t.Fatalf("mode ngawur harus 400, dapat %d", code)
	}
	if code, out := post("/api/settings", []byte(`{"limitBytes":5000000000,"resetDay":10,"net":"all"}`), true); code != 200 {
		t.Fatalf("settings: %d %s", code, out)
	}
	if code, _ := post("/api/settings", []byte(`{"limitBytes":1,"resetDay":31,"net":"all"}`), true); code != http.StatusBadRequest {
		t.Fatalf("resetDay 31 harus 400, dapat %d", code)
	}

	r2, err := http.Get(ts.URL + "/api/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	var sum Summary
	if err := json.NewDecoder(r2.Body).Decode(&sum); err != nil {
		t.Fatal(err)
	}
	if sum.Overview.Limit.Bytes != 5000000000 || sum.Overview.Limit.ResetDay != 10 || sum.Overview.Limit.Net != "all" {
		t.Fatalf("limit di summary: %+v", sum.Overview.Limit)
	}

	r3, err := http.Get(ts.URL + "/api/live")
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Body.Close()
	var lv map[string]any
	if err := json.NewDecoder(r3.Body).Decode(&lv); err != nil || lv["samples"] == nil {
		t.Fatalf("live: %v %v", err, lv)
	}
}
