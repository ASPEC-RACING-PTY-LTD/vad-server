package store

import (
	"context"
	"database/sql"
	"errors"
)

// BlobScan is the inspection result of a user's stored content.
type BlobScan struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username,omitempty"`
	SHA256    string `json:"sha256"`
	Verdict   string `json:"verdict"` // clean, flagged, quarantined
	Kind      string `json:"kind,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Engine    string `json:"engine,omitempty"`
	ScannedAt int64  `json:"scanned_at"`
	Name      string `json:"name,omitempty"`    // a file with this content
	NodeID    int64  `json:"node_id,omitempty"` // that file
	Size      int64  `json:"size,omitempty"`
}

// SetBlobScan records an inspection result.
func (s *Store) SetBlobScan(ctx context.Context, b BlobScan) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO blob_scans(user_id, sha256, verdict, kind, detail, engine, scanned_at) VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(user_id, sha256) DO UPDATE SET verdict = excluded.verdict, kind = excluded.kind, detail = excluded.detail, engine = excluded.engine, scanned_at = excluded.scanned_at`,
		b.UserID, b.SHA256, b.Verdict, b.Kind, b.Detail, b.Engine, now())
	return err
}

// BlobScanOf returns the inspection result of content (ErrNotFound: not
// inspected yet).
func (s *Store) BlobScanOf(ctx context.Context, userID int64, sha string) (*BlobScan, error) {
	b := BlobScan{UserID: userID, SHA256: sha}
	err := s.DB.QueryRowContext(ctx, "SELECT verdict, kind, detail, engine, scanned_at FROM blob_scans WHERE user_id = ? AND sha256 = ?", userID, sha).
		Scan(&b.Verdict, &b.Kind, &b.Detail, &b.Engine, &b.ScannedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Quarantined reports whether content is quarantined.
func (s *Store) Quarantined(ctx context.Context, userID int64, sha string) bool {
	var v string
	err := s.DB.QueryRowContext(ctx, "SELECT verdict FROM blob_scans WHERE user_id = ? AND sha256 = ?", userID, sha).Scan(&v)
	return err == nil && v == "quarantined"
}

// FlaggedBlobs lists content that is not clean, newest first, with one file
// that holds it (all users).
func (s *Store) FlaggedBlobs(ctx context.Context, limit int) ([]BlobScan, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT b.user_id, COALESCE(u.username,''), b.sha256, b.verdict, b.kind, b.detail, b.engine, b.scanned_at,
			COALESCE((SELECT n.name FROM nodes n WHERE n.user_id = b.user_id AND n.sha256 = b.sha256 ORDER BY n.deleted_at IS NOT NULL, n.id DESC LIMIT 1), ''),
			COALESCE((SELECT n.id FROM nodes n WHERE n.user_id = b.user_id AND n.sha256 = b.sha256 ORDER BY n.deleted_at IS NOT NULL, n.id DESC LIMIT 1), 0),
			COALESCE((SELECT bl.size FROM blobs bl WHERE bl.user_id = b.user_id AND bl.sha256 = b.sha256), 0)
		FROM blob_scans b LEFT JOIN users u ON u.id = b.user_id WHERE b.verdict != 'clean' ORDER BY b.scanned_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BlobScan{}
	for rows.Next() {
		var b BlobScan
		if err := rows.Scan(&b.UserID, &b.Username, &b.SHA256, &b.Verdict, &b.Kind, &b.Detail, &b.Engine, &b.ScannedAt, &b.Name, &b.NodeID, &b.Size); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
