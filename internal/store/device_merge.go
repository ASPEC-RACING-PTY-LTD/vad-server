package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// MergeDevices moves everything recorded for the devices others (uploads,
// sync folders, backup jobs and runs, snapshots, tasks, activity, ...) to
// survivor and deletes them. Every device must belong to userID. Rows that
// would duplicate one of the survivor's (one row per device) keep the
// survivor's. Columns are found by name (device_id and *_device_id), so new
// tables are covered too.
func (s *Store) MergeDevices(ctx context.Context, userID, survivor int64, others []int64) error {
	if len(others) == 0 {
		return nil
	}
	return s.Tx(ctx, func(tx *sql.Tx) error {
		ids := append([]int64{survivor}, others...)
		for _, id := range ids {
			var owner int64
			if err := tx.QueryRowContext(ctx, "SELECT user_id FROM devices WHERE id = ?", id).Scan(&owner); err != nil {
				if err == sql.ErrNoRows {
					return ErrNotFound
				}
				return err
			}
			if owner != userID {
				return ErrNotFound
			}
		}
		cols, err := deviceColumns(ctx, tx)
		if err != nil {
			return err
		}
		for _, old := range others {
			if old == survivor {
				continue
			}
			for _, c := range cols {
				q := fmt.Sprintf("UPDATE OR IGNORE %q SET %q = ? WHERE %q = ?", c[0], c[1], c[1])
				if _, err := tx.ExecContext(ctx, q, survivor, old); err != nil {
					return fmt.Errorf("merge %s.%s: %w", c[0], c[1], err)
				}
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM devices WHERE id = ?", old); err != nil {
				return err
			}
		}
		return nil
	})
}

// deviceColumns lists (table, column) pairs that hold a device id.
func deviceColumns(ctx context.Context, tx *sql.Tx) ([][2]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'devices'")
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, n)
	}
	rows.Close()
	var out [][2]string
	for _, t := range tables {
		cr, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT name FROM pragma_table_info(%q)", t))
		if err != nil {
			return nil, err
		}
		for cr.Next() {
			var c string
			if err := cr.Scan(&c); err != nil {
				cr.Close()
				return nil, err
			}
			if c == "device_id" || strings.HasSuffix(c, "_device_id") {
				out = append(out, [2]string{t, c})
			}
		}
		cr.Close()
	}
	return out, nil
}

// DevicesWithIdentifier lists a user's devices registered with identifier
// (the same PC), newest first.
func (s *Store) DevicesWithIdentifier(ctx context.Context, userID int64, identifier string) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT "+deviceCols+deviceFrom+" WHERE d.user_id = ? AND d.identifier = ? ORDER BY d.created_at DESC", userID, identifier)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}
