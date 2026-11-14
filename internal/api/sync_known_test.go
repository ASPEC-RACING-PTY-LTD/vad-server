package api_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A device that forgot its sync index asks which files are already stored.
func TestUploadsKnown(t *testing.T) {
	e := newEnv(t, "")
	admin := e.setupAdmin()
	bob := e.createUser(admin, "bob", 0)
	dc := e.enrollDevice(bob, "bob", "password-bob")
	p := filepath.Join(t.TempDir(), "clip.mp4")
	if err := os.WriteFile(p, []byte("not really a video"), 0o644); err != nil {
		t.Fatal(err)
	}
	mt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.UploadFile(context.Background(), p, "/Clips/clip.mp4", nil); err != nil {
		t.Fatal(err)
	}
	ms := mt.UnixMilli()
	var out struct {
		Known []bool `json:"known"`
	}
	err := dc.Call(context.Background(), "POST", "/api/v1/uploads/known", map[string]any{"files": []map[string]any{
		{"name": "clip.mp4", "size": 18, "modified_at": ms},
		{"name": "CLIP.MP4", "size": 18, "modified_at": ms + 1000},
		{"name": "clip.mp4", "size": 19, "modified_at": ms},
		{"name": "clip.mp4", "size": 18, "modified_at": ms + 60000},
		{"name": "other.mp4", "size": 18, "modified_at": ms},
	}}, &out)
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, true, false, false, false}
	for i := range want {
		if i >= len(out.Known) || out.Known[i] != want[i] {
			t.Fatalf("known = %v, want %v", out.Known, want)
		}
	}
}
