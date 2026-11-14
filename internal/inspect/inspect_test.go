package inspect

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

func TestStatic(t *testing.T) {
	mz := append([]byte("MZ"), make([]byte, 100)...)
	cases := []struct {
		name    string
		head    []byte
		verdict string
		kind    string
	}{
		{"holiday.mp4", []byte("\x00\x00\x00\x18ftypmp42"), Clean, ""},
		{"setup.exe", mz, Flagged, "program"},
		{"holiday.mp4", mz, Quarantined, "disguised"},
		{"photo.jpg", []byte("#!/bin/sh\necho hi"), Quarantined, "disguised"},
		{"run.ps1", []byte("Write-Host hi"), Flagged, "script"},
		{"notes.txt", []byte("hello"), Clean, ""},
		{"tool", []byte("\x7fELF\x02\x01"), Flagged, "program"},
		{"report.docm", []byte("PK\x03\x04"), Flagged, "macro document"},
	}
	for _, c := range cases {
		r := Static(c.name, c.head)
		if r.Verdict != c.verdict || r.Kind != c.kind {
			t.Errorf("%s: %+v, want %s/%s", c.name, r, c.verdict, c.kind)
		}
	}
}

// fakeClamd answers INSTREAM like clamd: "FOUND" for content with EICAR.
func fakeClamd(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
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
			}(conn)
		}
	}()
	return "tcp://" + ln.Addr().String()
}

func TestClamd(t *testing.T) {
	c := Clamd{Addr: fakeClamd(t), MaxSize: 1 << 20}
	if found, err := c.Scan(strings.NewReader("hello"), 5); err != nil || found != "" {
		t.Fatalf("clean: %q %v", found, err)
	}
	if found, err := c.Scan(strings.NewReader("X5O EICAR test"), 14); err != nil || found != "Eicar-Test-Signature" {
		t.Fatalf("eicar: %q %v", found, err)
	}
	if _, err := c.Scan(strings.NewReader(""), 2<<20); err != ErrTooLarge {
		t.Fatalf("too large: %v", err)
	}
}
