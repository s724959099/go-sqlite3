// External package vfs_test. No sqlite3 import in package vfs. No private
// field and no production hook. The observer is a test-only forwarding VFS:
// it receives the engine's real *vfs.Filename and forwards every operation to
// the selected base named "os-ro". Returned Files are passed back unchanged.
// Read-only shm safety is exercised on a real engine-captured SharedMemory via
// the test-only clone seam (OSROShm*, from vfs/osro_export_test.go).

//go:build (linux || darwin) && !(sqlite3_flock || sqlite3_dotlk)

package vfs_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	"github.com/ncruces/go-sqlite3/internal/testcfg"
	"github.com/ncruces/go-sqlite3/vfs"
)

// osroBaseName is the fixed opt-in VFS name the observer forwards to.
const osroBaseName = "os-ro"

var (
	errOSROBaseMissing = errors.New("selected os-ro base VFS is not registered")
	errOSROBaseNoFile  = errors.New("selected base VFS does not implement VFSFilename")
)

type osroObservedFile struct {
	name  string
	flags vfs.OpenFlag
	file  vfs.File
}

// osroObserver is a test-only forwarding VFS. Every operation goes to the
// selected base. A nil base yields a typed SQLITE_CANTOPEN, never a silent
// fallback to the default writable VFS. FullPathname alone may resolve through
// the default VFS when the base is absent.
type osroObserver struct {
	baseName string
	mu       sync.Mutex
	files    []osroObservedFile
}

func (o *osroObserver) base() vfs.VFS { return vfs.Find(o.baseName) }

func osroNilBase() error { return vfs.SystemError(errOSROBaseMissing, sqlite3.CANTOPEN) }

func (o *osroObserver) Open(name string, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	b := o.base()
	if b == nil {
		return nil, flags, osroNilBase()
	}
	return b.Open(name, flags)
}

func (o *osroObserver) Delete(name string, syncDir bool) error {
	b := o.base()
	if b == nil {
		return osroNilBase()
	}
	return b.Delete(name, syncDir)
}

func (o *osroObserver) Access(name string, flags vfs.AccessFlag) (bool, error) {
	b := o.base()
	if b == nil {
		return false, osroNilBase()
	}
	return b.Access(name, flags)
}

func (o *osroObserver) FullPathname(name string) (string, error) {
	if b := o.base(); b != nil {
		return b.FullPathname(name)
	}
	return vfs.Find("").FullPathname(name)
}

// OpenFilename receives the engine's real Filename and forwards to the base.
func (o *osroObserver) OpenFilename(name *vfs.Filename, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	b := o.base()
	if b == nil {
		return nil, flags, osroNilBase()
	}
	bf, ok := b.(vfs.VFSFilename)
	if !ok {
		return nil, flags, vfs.SystemError(errOSROBaseNoFile, sqlite3.CANTOPEN)
	}
	f, outFlags, err := bf.OpenFilename(name, flags)
	if err != nil {
		return nil, outFlags, err
	}
	o.mu.Lock()
	o.files = append(o.files, osroObservedFile{name: name.String(), flags: flags, file: f})
	o.mu.Unlock()
	return f, outFlags, nil
}

func (o *osroObserver) observed() []osroObservedFile {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]osroObservedFile(nil), o.files...)
}

// osroRegister registers a uniquely named observer forwarding to baseName.
func osroRegister(t *testing.T, baseName string) (*osroObserver, string) {
	t.Helper()
	name := "osro-observe-" + strings.ReplaceAll(t.Name(), "/", "_")
	obs := &osroObserver{baseName: baseName}
	vfs.Register(name, obs)
	t.Cleanup(func() { vfs.Unregister(name) })
	return obs, name
}

func osroDSN(path, vfsName string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?mode=ro&vfs=" + vfsName
}

// osroFdAccessMode returns O_ACCMODE for a value exposing Fd(), or -1 if none.
func osroFdAccessMode(t *testing.T, f any) int {
	t.Helper()
	fdr, ok := f.(interface{ Fd() uintptr })
	if !ok {
		return -1
	}
	fd := fdr.Fd()
	if fd == ^uintptr(0) {
		return -1
	}
	fl, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fl & unix.O_ACCMODE
}

// osroMainSharedMemory returns the SharedMemory the engine attached to the
// observed main database file. It is the real captured capability.
func osroMainSharedMemory(t *testing.T, obs *osroObserver) vfs.SharedMemory {
	t.Helper()
	for _, of := range obs.observed() {
		if of.flags&vfs.OPEN_MAIN_DB == 0 {
			continue
		}
		sf, ok := of.file.(vfs.FileSharedMemory)
		if !ok {
			t.Fatal("observed main DB File does not expose FileSharedMemory")
		}
		shm := sf.SharedMemory()
		if shm == nil {
			t.Fatal("observed main DB File has no SharedMemory")
		}
		return shm
	}
	t.Fatal("no observed main DB file")
	return nil
}

func osroWriterDB(t *testing.T, path string, wal bool) *sqlite3.Conn {
	t.Helper()
	conn, err := sqlite3.OpenContext(testcfg.Context(t), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	queries := []string{
		`CREATE TABLE meta (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, value TEXT NOT NULL)`,
		`INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`,
	}
	if wal {
		queries = append([]string{`PRAGMA journal_mode=wal`}, queries...)
	}
	for _, q := range queries {
		if err := conn.Exec(q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	return conn
}

func osroSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	state := map[string]string{}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	state["."] = fmt.Sprintf("dir:%s:%d", di.Mode(), di.ModTime().UnixNano())
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		entry := fmt.Sprintf("%s:%d:%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
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

func osroAssertSame(t *testing.T, before, after map[string]string) {
	t.Helper()
	for name, want := range before {
		if got, ok := after[name]; !ok {
			t.Errorf("entry %s removed", name)
		} else if got != want {
			t.Errorf("entry %s changed: before %s after %s", name, want, got)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("entry %s created", name)
		}
	}
}

// osroReadCount runs the real engine read through the observer and requires the
// exact enabled-row count.
func osroReadCount(t *testing.T, path, name string) (*sql.DB, int) {
	t.Helper()
	db, err := driver.Open(osroDSN(path, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM meta WHERE enabled = 1`).Scan(&n); err != nil {
		t.Fatalf("observed read: %v", err)
	}
	return db, n
}

// Real engine query through the observer: main DB, WAL and -shm descriptors
// must all be O_RDONLY, and the exact committed row must be read.
// Baseline: RED, the os-ro base is absent and the observer returns CANTOPEN.
func TestOSROObservedDescriptorsReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "obs.db")
	osroWriterDB(t, path, true)

	obs, name := osroRegister(t, osroBaseName)
	_, n := osroReadCount(t, path, name)
	if n != 1 {
		t.Fatalf("enabled row count = %d, want 1", n)
	}

	var sawMain, sawWAL bool
	for _, of := range obs.observed() {
		switch {
		case of.flags&vfs.OPEN_WAL != 0:
			sawWAL = true
			if got := osroFdAccessMode(t, of.file); got != unix.O_RDONLY {
				t.Errorf("WAL accmode = %d, want O_RDONLY", got)
			}
		case of.flags&vfs.OPEN_MAIN_DB != 0:
			sawMain = true
			if got := osroFdAccessMode(t, of.file); got != unix.O_RDONLY {
				t.Errorf("main DB accmode = %d, want O_RDONLY", got)
			}
		}
	}
	if !sawMain || !sawWAL {
		t.Fatalf("observed main=%v wal=%v; want both", sawMain, sawWAL)
	}
	shm := osroMainSharedMemory(t, obs)
	if got := osroFdAccessMode(t, shm); got != unix.O_RDONLY {
		t.Errorf("engine SHM accmode = %d, want O_RDONLY", got)
	}
}

// Real Conn close with exact before/after snapshots of the directory, the main
// DB, the -wal and the -shm. Covers no-write and no-delete through a real close.
// Baseline: RED, the os-ro base is absent so the read cannot start.
func TestOSROObservedCloseLeavesSourceExact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "close.db")
	osroWriterDB(t, path, true)
	before := osroSnapshot(t, dir)

	_, name := osroRegister(t, osroBaseName)
	db, n := osroReadCount(t, path, name)
	if n != 1 {
		t.Fatalf("enabled row count = %d, want 1", n)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	osroAssertSame(t, before, osroSnapshot(t, dir))
}

// Absent-SHM no-create on the real captured capability. A non-WAL database is
// read through os-ro with exact rows; the captured SharedMemory then gets a
// clone shmOpen. The clone must refuse and must not create the -shm file.
// Baseline: RED, the os-ro read fails before capture.
// Expected after patch: refusal (OpenErr non-nil), no -shm on disk, no
// writable descriptor.
func TestOSROObservedAbsentSHMNoCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.db")
	conn := osroWriterDB(t, path, false)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	obs, name := osroRegister(t, osroBaseName)
	_, n := osroReadCount(t, path, name)
	if n != 1 {
		t.Fatalf("enabled row count = %d, want 1", n)
	}
	shm := osroMainSharedMemory(t, obs)

	obsShm, err := vfs.OSROShmCloneOpen(shm)
	if err != nil {
		t.Fatal(err)
	}
	if obsShm.PathAfterOpen {
		t.Fatalf("clone shmOpen created the absent -shm file")
	}
	if obsShm.OpenErr == nil {
		t.Fatal("clone shmOpen over absent -shm returned nil; want fail-closed refusal")
	}
	if obsShm.HasFile && obsShm.AccMode != unix.O_RDONLY {
		t.Fatalf("clone held a writable descriptor with accmode %d", obsShm.AccMode)
	}
	if _, err := os.Stat(filepath.Join(dir, "plain.db-shm")); err == nil {
		t.Fatal("-shm exists on disk after read-only probe")
	}
}

// Active-WAL source retention. A live writer keeps -wal and -shm. The reader
// reads through os-ro, the captured SharedMemory is cloned, and the clone is
// unmapped with delete=true. The source -shm must survive, and the delete
// property must have been exercised (the clone held a descriptor at unmap).
// Baseline: RED, the os-ro read fails before capture.
// Caveat: within one process the DMS lock is not visible to F_GETLK, so the
// clone's open may refuse; if a refusal closes the descriptor the delete
// property is not exercised and this test fails loudly rather than passing.
func TestOSROObservedActiveSHMUnmapDeleteRetainsSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "active.db")
	osroWriterDB(t, path, true)

	obs, name := osroRegister(t, osroBaseName)
	_, n := osroReadCount(t, path, name)
	if n != 1 {
		t.Fatalf("enabled row count = %d, want 1", n)
	}
	shm := osroMainSharedMemory(t, obs)

	hadFile, sourceExists, err := vfs.OSROShmCloneUnmapDelete(shm)
	if err != nil {
		t.Fatal(err)
	}
	if !hadFile {
		t.Fatal("clone held no descriptor at unmap; delete=true property not exercised")
	}
	if !sourceExists {
		t.Fatal("read-only unmap(delete=true) removed the source -shm")
	}
}

// Read-only clone over the live -shm must leave the directory state unchanged
// (names, mode, size, mtime, content). Atime is excluded.
// Baseline: RED, the os-ro read fails before capture.
func TestOSROObservedShmCloneLeavesSourceState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	osroWriterDB(t, path, true)

	obs, name := osroRegister(t, osroBaseName)
	osroReadCount(t, path, name)
	shm := osroMainSharedMemory(t, obs)

	before := osroSnapshot(t, dir)
	obsShm, err := vfs.OSROShmCloneOpen(shm)
	if err != nil {
		t.Fatal(err)
	}
	if obsShm.HasFile && obsShm.AccMode != unix.O_RDONLY {
		t.Fatalf("clone descriptor accmode = %d, want O_RDONLY", obsShm.AccMode)
	}
	osroAssertSame(t, before, osroSnapshot(t, dir))
}
