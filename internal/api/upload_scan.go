package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/ASPEC-RACING-PTY-LTD/vad-server/internal/inspect"
	"github.com/ASPEC-RACING-PTY-LTD/vad-server/internal/store"
)

// Zero trust for uploads: every upload is unknown content, whoever sent it
// and from whichever device (administrators included). Each upload is
// inspected (internal/inspect: programs, scripts, disguised files, and
// ClamAV when VAULTDOCK_CLAMD is set); flagged content is only ever served
// as a download and cannot be shared publicly; quarantined content is not
// served, shared, processed or copied at all until an administrator
// releases it. Every user's content stays in their own space: blobs,
// deduplication, thumbnails and caches are per user, so nothing uploaded by
// one account can reach another's files.

// errQuarantined is returned by openBlob for quarantined content.
var errQuarantined = errors.New("quarantined")

// scanSlots limits background antivirus scans.
var scanSlots = make(chan struct{}, 2)

// inspectUpload runs the quick checks on a just-finished upload (before any
// media processing) from its temporary file, and records the result.
func (s *Server) inspectUpload(ctx context.Context, userID int64, sha, name string, head []byte) inspect.Result {
	res := inspect.Static(name, head)
	if err := s.st.SetBlobScan(ctx, store.BlobScan{UserID: userID, SHA256: sha, Verdict: res.Verdict, Kind: res.Kind, Detail: res.Detail, Engine: res.Engine}); err != nil {
		slog.Warn("upload inspection not recorded", "user", userID, "sha", sha, "err", err)
	}
	return res
}

// uploadCommitted runs after an upload is stored: the antivirus scan (in
// the background), reports for anything not clean, and the overflow move
// when the user's space on this server is now full.
func (s *Server) uploadCommitted(userID int64, n *store.Node) {
	if n == nil || n.SHA256 == "" {
		return
	}
	ctx := context.Background()
	if prev, err := s.st.BlobScanOf(ctx, userID, n.SHA256); err == nil && prev.Verdict != inspect.Clean {
		s.reportFlagged(ctx, userID, n, prev)
	}
	if s.cfg.ClamdAddr != "" {
		s.ops.wg.Add(1)
		go func() {
			defer s.ops.wg.Done()
			scanSlots <- struct{}{}
			defer func() { <-scanSlots }()
			s.clamScan(ctx, userID, n)
		}()
	}
	if s.overLocalQuota(ctx, userID) {
		if u, err := s.st.UserByID(ctx, userID); err == nil && u.OverflowNode != nil {
			s.remote().startOverflowMove(s, userID, *u.OverflowNode)
		}
	}
}

// clamScan streams content to ClamAV and quarantines what it reports.
func (s *Server) clamScan(ctx context.Context, userID int64, n *store.Node) {
	f, err := s.openBlob(ctx, userID, n.SHA256)
	if err != nil {
		return
	}
	defer f.Close()
	c := inspect.Clamd{Addr: s.cfg.ClamdAddr, MaxSize: int64(s.cfg.ClamdMaxMB) << 20}
	found, err := c.Scan(io.Reader(f), f.Size())
	switch {
	case errors.Is(err, inspect.ErrTooLarge):
		return
	case err != nil:
		slog.Warn("antivirus scan failed", "user", userID, "file", n.Name, "err", err)
		return
	case found == "":
		return
	}
	b := store.BlobScan{UserID: userID, SHA256: n.SHA256, Verdict: inspect.Quarantined, Kind: "malware", Detail: found, Engine: "clamav"}
	if err := s.st.SetBlobScan(ctx, b); err != nil {
		slog.Error("antivirus finding not recorded", "user", userID, "file", n.Name, "err", err)
		return
	}
	s.reportFlagged(ctx, userID, n, &b)
}

// reportFlagged logs a not-clean upload and tells the owner and, for
// quarantined content, every administrator.
func (s *Server) reportFlagged(ctx context.Context, userID int64, n *store.Node, b *store.BlobScan) {
	uid := userID
	action := "upload.flagged"
	if b.Verdict == inspect.Quarantined {
		action = "upload.quarantined"
	}
	s.st.LogActivity(ctx, store.Activity{UserID: &uid, Action: action, Target: n.Name, Details: fmt.Sprintf("%s: %s (%s)", b.Kind, b.Detail, b.Engine), Audit: true, DeviceID: n.OriginDev})
	if b.Verdict != inspect.Quarantined {
		return
	}
	msg := fmt.Sprintf("%s was quarantined: %s. It cannot be opened, shared or downloaded until an administrator releases it.", n.Name, b.Detail)
	_ = s.st.AddNotification(ctx, userID, store.Notification{Title: "Upload quarantined", Level: "error", Source: "security", Message: msg})
	users, err := s.st.ListUsers(ctx)
	if err != nil {
		return
	}
	owner := ""
	for _, u := range users {
		if u.ID == userID {
			owner = u.Username
		}
	}
	for _, u := range users {
		if u.IsAdmin() && !u.Disabled && u.ID != userID {
			_ = s.st.AddNotification(ctx, u.ID, store.Notification{Title: "Upload quarantined", Level: "error", Source: "security",
				Message: fmt.Sprintf("%s uploaded %s: %s (%s). Review it under Administration > Security.", owner, n.Name, b.Detail, b.Engine)})
		}
	}
}

// handleFlaggedUploads lists uploads that are not clean (administrators).
func (s *Server) handleFlaggedUploads(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.FlaggedBlobs(r.Context(), 500)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": list, "clamav": s.cfg.ClamdAddr != ""})
}

// handleReleaseUpload marks quarantined content as reviewed and safe
// (administrators): PUT /admin/security/uploads/{user}/{sha} {verdict}.
func (s *Server) handleReleaseUpload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  int64  `json:"user_id"`
		SHA256  string `json:"sha256"`
		Verdict string `json:"verdict"` // clean or flagged
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, r, err)
		return
	}
	if req.Verdict != inspect.Clean && req.Verdict != inspect.Flagged && req.Verdict != inspect.Quarantined {
		writeErr(w, r, errf(400, "bad_verdict", "verdict must be clean, flagged or quarantined"))
		return
	}
	prev, err := s.st.BlobScanOf(r.Context(), req.UserID, req.SHA256)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	who := principal(r).User.Username
	b := *prev
	b.Verdict, b.Engine = req.Verdict, "reviewed by "+who+" "+time.Now().UTC().Format("2006-01-02")
	if err := s.st.SetBlobScan(r.Context(), b); err != nil {
		writeErr(w, r, err)
		return
	}
	s.activity(r, req.UserID, "upload.reviewed", req.SHA256[:12], fmt.Sprintf("%s -> %s (%s)", prev.Verdict, req.Verdict, prev.Detail), true)
	writeJSON(w, 200, map[string]any{"ok": true})
}
