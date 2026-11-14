package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/ASPEC-RACING-PTY-LTD/vad-server/internal/store"
)

// The same PC can end up as several devices: a reconnect after its
// credentials were lost registers a new request. Approving such a request
// merges the PC's older devices into it, and the owner can merge devices by
// hand on the Devices page; either way the history (uploads, sync folders,
// backups, activity) is kept under one device.

// mergeSurvivor picks the device that keeps going: the one the PC uses now
// (approved, then most recently seen, then newest).
func mergeSurvivor(ds []store.Device) store.Device {
	return slices.MaxFunc(ds, func(a, b store.Device) int {
		rank := func(d store.Device) int {
			if d.Status == "approved" {
				return 1
			}
			return 0
		}
		if c := rank(a) - rank(b); c != 0 {
			return c
		}
		seen := func(d store.Device) int64 {
			if d.LastSeenAt != nil {
				return *d.LastSeenAt
			}
			return 0
		}
		if c := seen(a) - seen(b); c != 0 {
			if c > 0 {
				return 1
			}
			return -1
		}
		switch {
		case a.CreatedAt > b.CreatedAt:
			return 1
		case a.CreatedAt < b.CreatedAt:
			return -1
		}
		return 0
	})
}

// handleDevicesMerge merges the owner's devices: POST /devices/merge
// {device_ids: [..]} (two or more).
func (s *Server) handleDevicesMerge(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var req struct {
		DeviceIDs []int64 `json:"device_ids"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	slices.Sort(req.DeviceIDs)
	req.DeviceIDs = slices.Compact(req.DeviceIDs)
	if len(req.DeviceIDs) < 2 || len(req.DeviceIDs) > 50 {
		writeErr(w, r, errf(400, "bad_request", "Choose at least two devices to merge"))
		return
	}
	var ds []store.Device
	for _, id := range req.DeviceIDs {
		d, err := s.st.Device(r.Context(), id)
		if err != nil || d.UserID != p.User.ID {
			writeErr(w, r, store.ErrNotFound)
			return
		}
		if d.Status == "pending" {
			writeErr(w, r, errf(409, "pending", "Approve or reject %s first", d.Name))
			return
		}
		ds = append(ds, *d)
	}
	keep := mergeSurvivor(ds)
	var others []int64
	var names []string
	for _, d := range ds {
		if d.ID != keep.ID {
			others = append(others, d.ID)
			names = append(names, fmt.Sprintf("%s (#%d)", d.Name, d.ID))
		}
	}
	if err := s.st.MergeDevices(r.Context(), p.User.ID, keep.ID, others); err != nil {
		writeErr(w, r, err)
		return
	}
	s.activity(r, p.User.ID, "device.merged", keep.Name, "merged "+strings.Join(names, ", "), true)
	d2, _ := s.st.Device(r.Context(), keep.ID)
	writeJSON(w, 200, map[string]any{"device": s.deviceView(r.Context(), d2), "merged": len(others)})
}

// mergeSamePC merges the user's other devices registered from the same PC
// (identifier) into the just-approved device d.
func (s *Server) mergeSamePC(ctx context.Context, r *http.Request, d *store.Device) {
	if d.Identifier == "" {
		return
	}
	ds, err := s.st.DevicesWithIdentifier(ctx, d.UserID, d.Identifier)
	if err != nil {
		slog.Warn("same-PC devices not listed", "device", d.ID, "err", err)
		return
	}
	var others []int64
	for _, o := range ds {
		if o.ID != d.ID && o.Status != "pending" {
			others = append(others, o.ID)
		}
	}
	if len(others) == 0 {
		return
	}
	if err := s.st.MergeDevices(ctx, d.UserID, d.ID, others); err != nil {
		slog.Warn("same-PC devices not merged", "device", d.ID, "err", err)
		return
	}
	s.activity(r, d.UserID, "device.merged", d.Name, fmt.Sprintf("reconnected: %d earlier registration(s) of this PC merged", len(others)), true)
}
