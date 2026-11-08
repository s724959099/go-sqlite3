package tests

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	"github.com/ncruces/go-sqlite3/internal/testcfg"
)

// osroVFSName is the fixed, dependency-owned read-only VFS name requested by
// the opt-in DSN. It is a string, not an exported Go symbol, so these tests
// compile against the unchanged baseline and fail by observable open/read.
const osroVFSName = "os-ro"

type osroQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// osroFileState maps a directory's own metadata and every entry name to
// mode, size, mtime and (for regular files) content hash. Access time is
// deliberately excluded because reads legitimately change it.
type osroFileState map[string]string

func osroSnapshot(t *testing.T, dir string) osroFileState {
	t.Helper()
	state := make(osroFileState)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	state["."] = fmt.Sprintf("dir:%s:%d", dirInfo.Mode().String(), dirInfo.ModTime().UnixNano())
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		entry := fmt.Sprintf("%s:%d:%d", info.Mode().String(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			entry += ":" + hex.EncodeToString(sum[:])
		}
		state[e.Name()] = entry
	}
	return state
}

func osroAssertSameState(t *testing.T, before, after osroFileState) {
	t.Helper()
	for name, want := range before {
		got, ok := after[name]
		if !ok {
			t.Errorf("entry %s was removed by the read-only path", name)
		} else if got != want {
			t.Errorf("entry %s changed: before %s after %s", name, want, got)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("entry %s was created by the read-only path", name)
		}
	}
}

func osroExec(t *testing.T, conn *sqlite3.Conn, query string) {
	t.Helper()
	if err := conn.Exec(query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// osroWriter opens a synthetic WAL database owned by this test and keeps the
// connection open, so -wal and -shm stay active for the reader under test.
func osroWriter(t *testing.T, path string) *sqlite3.Conn {
	t.Helper()
	conn, err := sqlite3.OpenContext(testcfg.Context(t), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	osroExec(t, conn, `PRAGMA journal_mode=wal`)
	osroExec(t, conn, `CREATE TABLE meta (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, value TEXT NOT NULL)`)
	return conn
}

// osroDSN builds the opt-in read-only DSN for a database path.
func osroDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro&vfs=" + osroVFSName
}

// osroReader returns a handle requesting the os-ro VFS. Opening is lazy; the
// first query reports whether the VFS is available on the build under test.
func osroReader(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := driver.Open(osroDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func osroEnabledRows(t *testing.T, q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}) string {
	t.Helper()
	rows, err := q.Query(`SELECT id, value FROM meta WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		t.Fatalf("read enabled rows: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id int
		var value string
		if err := rows.Scan(&id, &value); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%d=%s;", id, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func osroCount(t *testing.T, q osroQuerier) int {
	t.Helper()
	var n int
	if err := q.QueryRow(`SELECT count(*) FROM meta`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// Latest committed enabled metadata in an active WAL is visible; an
// uncommitted writer transaction and committed disabled rows are not.
// Expected exact rows: 1=v1;2=v2b;. Baseline: RED on the os-ro open/read.
func TestOSROActiveWALLatestCommittedVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.db")
	w := osroWriter(t, path)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (2, 1, 'v2')`)
	osroExec(t, w, `UPDATE meta SET value = 'v2b' WHERE id = 2`)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (4, 0, 'off')`)
	osroExec(t, w, `BEGIN`)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (3, 1, 'uncommitted')`)
	t.Cleanup(func() { w.Exec(`ROLLBACK`) })

	r := osroReader(t, path)
	if got, want := osroEnabledRows(t, r), "1=v1;2=v2b;"; got != want {
		t.Fatalf("reader rows = %q, want %q", got, want)
	}
}

// A read transaction keeps its snapshot while a normal writer commits, and a
// new read after the snapshot ends sees the committed row.
// Expected: snapshot count 1 before and after concurrent commit; then 1=v1;2=v2;.
// Baseline: RED on the os-ro open.
func TestOSROActiveWALReaderSnapshotAndWriterProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.db")
	w := osroWriter(t, path)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)

	r := osroReader(t, path)
	tx, err := r.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if got := osroCount(t, tx); got != 1 {
		t.Fatalf("first snapshot count = %d, want 1", got)
	}

	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (2, 1, 'v2')`)

	if got := osroCount(t, tx); got != 1 {
		t.Fatalf("snapshot count after concurrent commit = %d, want 1", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if got, want := osroEnabledRows(t, r), "1=v1;2=v2;"; got != want {
		t.Fatalf("post-snapshot rows = %q, want %q", got, want)
	}
}

// Reading an active WAL database through os-ro leaves the directory and every
// entry (main, -wal, -shm) unchanged in name, mode, size, mtime and content.
// Baseline: RED on the os-ro open; the precondition proves the sidecars exist.
func TestOSROWritableSourceZeroMutations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zero.db")
	w := osroWriter(t, path)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)

	before := osroSnapshot(t, dir)
	for _, name := range []string{"zero.db", "zero.db-wal", "zero.db-shm"} {
		if _, ok := before[name]; !ok {
			t.Fatalf("precondition: active WAL sidecar %s missing; test would be vacuous", name)
		}
	}

	r := osroReader(t, path)
	if got, want := osroEnabledRows(t, r), "1=v1;"; got != want {
		t.Fatalf("rows = %q, want %q", got, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	osroAssertSameState(t, before, osroSnapshot(t, dir))
}

// A non-WAL database with no sidecars is readable with exact rows and never
// gains -wal or -shm. This is the promised missing-sidecar case.
// Baseline: RED on the os-ro open.
func TestOSRONonWALNoSidecarsReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.db")
	conn, err := sqlite3.OpenContext(testcfg.Context(t), path)
	if err != nil {
		t.Fatal(err)
	}
	osroExec(t, conn, `CREATE TABLE meta (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, value TEXT NOT NULL)`)
	osroExec(t, conn, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	before := osroSnapshot(t, dir)
	if _, ok := before["plain.db-wal"]; ok {
		t.Fatal("precondition: non-WAL database must have no -wal sidecar")
	}
	r := osroReader(t, path)
	if got, want := osroEnabledRows(t, r), "1=v1;"; got != want {
		t.Fatalf("rows = %q, want %q", got, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	osroAssertSameState(t, before, osroSnapshot(t, dir))
}

// A read-only handle rejects writes and leaves committed rows and files intact.
// Expected: SQLITE_READONLY from the INSERT. Baseline: RED on the os-ro open.
func TestOSROReadOnlyRejectsWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ro.db")
	w := osroWriter(t, path)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)

	before := osroSnapshot(t, dir)
	r := osroReader(t, path)
	_, err := r.Exec(`INSERT INTO meta (id, enabled, value) VALUES (9, 1, 'x')`)
	var code sqlite3.ErrorCode
	if err == nil || !errors.As(err, &code) || code != sqlite3.READONLY {
		t.Fatalf("write through read-only handle: err=%v type=%T primary=%d, want SQLITE_READONLY=8", err, err, code)
	}
	var extended sqlite3.ExtendedErrorCode
	if errors.As(err, &extended) {
		t.Logf("rejected INSERT type=%T primary=%d extended=%d", err, code, extended)
	}
	if got, want := osroEnabledRows(t, r), "1=v1;"; got != want {
		t.Fatalf("rows after rejected write = %q, want %q", got, want)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	osroAssertSameState(t, before, osroSnapshot(t, dir))
}

// Preservation guard, not in-flight coverage. The context is cancelled before
// the call; database/sql checks ctx before acquiring a driver connection, so
// the error is context.Canceled without any VFS being resolved. Expected
// baseline outcome is GREEN (control). Files must stay unchanged either way.
// It does not prove cancellation of a query already running in SQLite.
func TestOSROPreCancelledContextPreservation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cancel.db")
	w := osroWriter(t, path)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)

	before := osroSnapshot(t, dir)
	r := osroReader(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var n int
	err := r.QueryRowContext(ctx, `SELECT count(*) FROM meta`).Scan(&n)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled read: err = %v, n = %d, want context.Canceled", err, n)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	osroAssertSameState(t, before, osroSnapshot(t, dir))
}

// Control that must pass on the baseline: the default (empty) VFS read-only
// path on a non-WAL database is unchanged by the opt-in os-ro work.
func TestOSRODefaultModeROControl(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "default.db")
	conn, err := sqlite3.OpenContext(testcfg.Context(t), path)
	if err != nil {
		t.Fatal(err)
	}
	osroExec(t, conn, `CREATE TABLE meta (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, value TEXT NOT NULL)`)
	osroExec(t, conn, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := driver.Open("file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got, want := osroEnabledRows(t, db), "1=v1;"; got != want {
		t.Fatalf("default mode=ro rows = %q, want %q", got, want)
	}
}
