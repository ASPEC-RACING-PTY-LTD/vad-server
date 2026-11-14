package api_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClamd answers clamd's INSTREAM: "FOUND" for content containing EICAR.
func fakeClamd(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if cmd, _ := br.ReadString(0); cmd != "zINSTREAM\x00" {
					return
				}
				var data []byte
				for {
					var l [4]byte
					if _, err := io.ReadFull(br, l[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(l[:])
					if n == 0 {
						break
					}
					b := make([]byte, n)
					if _, err := io.ReadFull(br, b); err != nil {
						return
					}
					data = append(data, b...)
				}
				if strings.Contains(string(data), "EICAR") {
					c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
				} else {
					c.Write([]byte("stream: OK\x00"))
				}
			}(c)
		}
	}()
	return "tcp://" + ln.Addr().String()
}

// Every upload is inspected, an administrator's too: programs are flagged
// (download only, no public links), disguised files and antivirus findings
// are quarantined (not served) until an administrator releases them.
func TestUploadInspection(t *testing.T) {
	t.Setenv("VAULTDOCK_CLAMD", fakeClamd(t))
	e := newEnv(t, "")
	admin := e.setupAdmin()
	dc := e.enrollDevice(admin, "admin", adminPass)
	dir := t.TempDir()
	upload := func(name string, data []byte) int64 {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := dc.UploadFile(context.Background(), p, "/"+name, nil)
		if err != nil {
			t.Fatal(err)
		}
		return nodeID(t, res.Node)
	}
	content := func(id int64) (int, http.Header) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/files/%d/content", e.ts.URL, id), nil)
		resp, err := admin.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	mz := append([]byte("MZ"), make([]byte, 200)...)

	clean := upload("notes.txt", []byte("hello"))
	exe := upload("setup.exe", mz)
	disguised := upload("holiday.mp4", append(mz, 1))
	eicar := upload("readme.txt", []byte("X5O!P%@AP EICAR test file"))

	if code, _ := content(clean); code != 200 {
		t.Fatalf("clean file: %d", code)
	}
	if code, h := content(exe); code != 200 || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || h.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("program: %d %v", code, h)
	}
	if code, _ := content(disguised); code != 403 {
		t.Fatalf("disguised program served: %d", code)
	}
	waitFor(t, 20*time.Second, "antivirus finding", func() bool {
		code, _ := content(eicar)
		return code == 403
	})

	items := admin.must("GET", "/api/v1/admin/security/uploads", nil, 200)["items"].([]any)
	byName := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["setup.exe"]["verdict"] != "flagged" || byName["holiday.mp4"]["kind"] != "disguised" || byName["readme.txt"]["engine"] != "clamav" {
		t.Fatalf("flagged list: %v", items)
	}
	if _, ok := byName["notes.txt"]; ok {
		t.Fatal("clean file listed")
	}

	// An administrator releases the antivirus finding after review.
	m := byName["readme.txt"]
	admin.must("PUT", "/api/v1/admin/security/uploads", map[string]any{"user_id": m["user_id"], "sha256": m["sha256"], "verdict": "clean"}, 200)
	if code, _ := content(eicar); code != 200 {
		t.Fatalf("released file: %d", code)
	}
}
