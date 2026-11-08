// Only the writable default control lives here. Read-only safety is tested
// through a real engine-captured SharedMemory in vfs/os_ro_ofd_test.go using
// the test-only clone seam in vfs/osro_export_test.go. NewSharedMemory with
// OPEN_READONLY is NOT used as the read-only intent: the chosen patch keeps the
// default constructor legacy and installs strict read-only on the os-ro
// instance only.
//
//go:build (linux || darwin) && !(sqlite3_flock || sqlite3_dotlk)

package vfs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// osroAccessMode returns the O_ACCMODE bits of an open descriptor.
func osroAccessMode(t *testing.T, f *os.File) int {
	t.Helper()
	fl, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fl & unix.O_ACCMODE
}

// Control that must pass on baseline and after patch: the default writable
// constructor keeps the -shm read-write, and unmap without delete keeps the
// file. This guards the legacy default path the patch must not change.
func TestOSROShmWritableDefaultUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meta.db")
	if err := os.WriteFile(path, []byte("synthetic-main"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, ok := NewSharedMemory(path+"-shm", OPEN_MAIN_DB).(*vfsShm)
	if !ok {
		t.Fatal("NewSharedMemory did not return *vfsShm")
	}
	if err := s.shmOpen(); err != nil {
		t.Fatalf("writable shmOpen: %v", err)
	}
	if got := osroAccessMode(t, s.File); got != unix.O_RDWR {
		t.Fatalf("writable shm accmode = %#x, want O_RDWR (%#x)", got, unix.O_RDWR)
	}
	s.shmUnmap(false)
	if _, err := os.Stat(path + "-shm"); err != nil {
		t.Fatalf("writable unmap without delete removed -shm: %v", err)
	}
}
