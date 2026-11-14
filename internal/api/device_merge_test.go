package api_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A PC that reconnects (new key, same identifier) keeps one device: the
// earlier registration and its history merge into the approved one. Devices
// can also be merged by hand.
func TestDeviceReconnectAndMerge(t *testing.T) {
	e := newEnv(t, "")
	admin := e.setupAdmin()
	bob := e.createUser(admin, "bob", 0)
	first := e.enrollDevice(bob, "bob", "password-bob")
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := first.UploadFile(context.Background(), p, "/a.txt", nil); err != nil {
		t.Fatal(err)
	}

	second := e.enrollDevice(bob, "bob", "password-bob")
	devs := bob.must("GET", "/api/v1/devices", nil, 200)["devices"].([]any)
	if len(devs) != 1 || int64(devs[0].(map[string]any)["id"].(float64)) != second.DeviceID {
		t.Fatalf("after reconnect: %v", devs)
	}
	if _, err := first.Me(context.Background()); err == nil {
		t.Fatal("the replaced key still works")
	}
	if _, err := second.Me(context.Background()); err != nil {
		t.Fatalf("reconnected device: %v", err)
	}

	// Manual merge (a device registered under another PC identifier).
	third := e.enrollDeviceAs(bob, "bob", "password-bob", "other-pc")
	bob.must("POST", "/api/v1/devices/merge", map[string]any{"device_ids": []int64{second.DeviceID, third.DeviceID}}, 200)
	devs = bob.must("GET", "/api/v1/devices", nil, 200)["devices"].([]any)
	if len(devs) != 1 {
		t.Fatalf("after merge: %d devices", len(devs))
	}
	// Someone else's devices cannot be merged.
	eve := e.createUser(admin, "eve", 0)
	ev := e.enrollDevice(eve, "eve", "password-eve")
	code, _ := bob.req("POST", "/api/v1/devices/merge", map[string]any{"device_ids": []int64{ev.DeviceID, int64(devs[0].(map[string]any)["id"].(float64))}})
	if code != 404 {
		t.Fatalf("merge of another user's device: %d", code)
	}
	_ = fmt.Sprint
}
