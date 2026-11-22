package main

// device.go: info perangkat buat kartu di halaman laporan (IP, uptime, penyimpanan).

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type DevIP struct {
	Iface string `json:"iface"`
	Addr  string `json:"addr"`
	Kind  string `json:"kind"` // wifi | data
}

type DevStorage struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

type DeviceInfo struct {
	Now       int64       `json:"now"`
	IPs       []DevIP     `json:"ips"`
	Collector int64       `json:"collectorSince"` // unix detik collector mulai jalan
	Boot      int64       `json:"boot"`           // unix detik perangkat boot, 0 = tidak diketahui
	Uptime    int64       `json:"uptime"`         // detik sejak boot, 0 = tidak diketahui
	Storage   *DevStorage `json:"storage,omitempty"`
}

var fakeIPNet = netip.MustParsePrefix("198.18.0.0/15") // fake-ip Mihomo / TUN

func localIPs(cls *Classifier) []DevIP {
	out := []DevIP{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		if strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "meta") ||
			strings.HasPrefix(name, "clash") || strings.HasPrefix(name, "dummy") {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ad, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ad = ad.Unmap()
			if ad.IsLoopback() || ad.IsLinkLocalUnicast() || ad.IsMulticast() || fakeIPNet.Contains(ad) {
				continue
			}
			kind := NetData
			if cls != nil && cls.classify(ad.String()) == NetWifi {
				kind = NetWifi
			}
			out = append(out, DevIP{Iface: ifc.Name, Addr: ad.String(), Kind: kind})
		}
	}
	return out
}

func readUptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0
	}
	return int64(v)
}

func storageInfo(paths ...string) *DevStorage {
	for _, p := range paths {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(p, &fs); err != nil || fs.Blocks == 0 {
			continue
		}
		bs := uint64(fs.Bsize)
		return &DevStorage{Path: p, Total: bs * uint64(fs.Blocks), Free: bs * uint64(fs.Bavail)}
	}
	return nil
}

func registerDevice(mux *http.ServeMux, s *Store, cls *Classifier, st *Status) {
	mux.HandleFunc("/api/device", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		st.mu.Lock()
		since := st.Since
		st.mu.Unlock()
		di := DeviceInfo{Now: now.Unix(), IPs: localIPs(cls), Collector: since, Uptime: readUptime()}
		if di.Uptime > 0 {
			di.Boot = now.Unix() - di.Uptime
		}
		di.Storage = storageInfo("/data", dirOf(s.path))
		writeJSON(w, http.StatusOK, di)
	})
}
