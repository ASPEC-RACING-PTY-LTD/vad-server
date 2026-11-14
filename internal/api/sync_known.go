package api

import (
	"net/http"
	"strings"
)

// handleSyncKnown tells a device which of its files the account already
// stores: POST /uploads/known {files: [{name, size, modified_at}]} ->
// {known: [bool, ...]} in the same order. A file counts as stored when a
// live file of the account has the same name (any folder; automations may
// have routed it), size and modification time (within 2 s). Used after a
// device forgot its local sync index, so nothing already uploaded is queued
// or sent again.
func (s *Server) handleSyncKnown(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Files []struct {
			Name       string `json:"name"`
			Size       int64  `json:"size"`
			ModifiedAt int64  `json:"modified_at"`
		} `json:"files"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	if len(req.Files) > 1000 {
		writeErr(w, r, errf(400, "too_many", "Ask about at most 1000 files at a time"))
		return
	}
	uid := principal(r).User.ID
	known := make([]bool, len(req.Files))
	for i, f := range req.Files {
		name := strings.TrimSpace(f.Name)
		if name == "" || f.Size < 0 {
			continue
		}
		ok, err := s.st.HasFile(r.Context(), uid, name, f.Size, f.ModifiedAt)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		known[i] = ok
	}
	writeJSON(w, 200, map[string]any{"known": known})
}
