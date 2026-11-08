// Darwin Seatbelt control: deny all writes beneath the database directory
// while preserving read access and a writable temporary directory.

//go:build darwin

package tests

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/ncruces/go-sqlite3/driver"
)

const (
	osroSandboxBinary    = "/usr/bin/sandbox-exec"
	osroSandboxChildEnv  = "MYPP_OSRO_SANDBOX_CHILD"
	osroSandboxChildPath = "MYPP_OSRO_SANDBOX_DB"
	osroSandboxChildTmp  = "MYPP_OSRO_SANDBOX_TMP"
	// osroDarwinFGetPath is fcntl(2) F_GETPATH on macOS.
	osroDarwinFGetPath = 50
)

// osroSandboxProfile denies every file write under the canonical fixture
// directory only; reads and writes to the isolated TMPDIR stay allowed.
func osroSandboxProfile(dir string) string {
	return fmt.Sprintf("(version 1)\n(allow default)\n(deny file-write* (subpath %q))\n", dir)
}

// osroDarwinFDPath resolves an open descriptor to its path with F_GETPATH.
func osroDarwinFDPath(fd int) (string, bool) {
	var buf [1024]byte
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), osroDarwinFGetPath, uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return "", false
	}
	n := bytes.IndexByte(buf[:], 0)
	if n < 0 {
		n = len(buf)
	}
	return string(buf[:n]), true
}

// osroChildProbe attempts one write-intent open and reports its errno.
func osroChildProbe(name, target string, flags int) {
	f, err := os.OpenFile(target, flags, 0o644)
	if err == nil {
		f.Close()
		fmt.Fprintf(os.Stdout, "CHILD_PROBE name=%s errno=0\n", name)
		return
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fmt.Fprintf(os.Stdout, "CHILD_PROBE name=%s errno=%d\n", name, int(errno))
		return
	}
	fmt.Fprintf(os.Stdout, "CHILD_PROBE name=%s errno=unknown err=%v\n", name, err)
}

// osroChildProcess is executed only inside sandbox-exec by the parent test.
func TestOSROSandboxChildProcess(t *testing.T) {
	if os.Getenv(osroSandboxChildEnv) != "1" {
		t.Skip("child entry point; executed by TestOSROSandboxDenyChildReadOnly")
	}
	path := os.Getenv(osroSandboxChildPath)
	tmp := os.Getenv(osroSandboxChildTmp)
	dir := filepath.Dir(path)

	db, err := driver.Open(osroDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fmt.Fprintf(os.Stdout, "CHILD_ROWS=%s\n", osroEnabledRows(t, db))

	// Positive control: the isolated TMPDIR is writable inside the sandbox.
	if err := os.WriteFile(filepath.Join(tmp, "granted.txt"), []byte("granted"), 0o600); err != nil {
		fmt.Fprintf(os.Stdout, "CHILD_POSITIVE_WRITE=error %v\n", err)
	} else {
		fmt.Fprintf(os.Stdout, "CHILD_POSITIVE_WRITE=ok\n")
	}

	// Each probe must be refused by Seatbelt (EPERM or EACCES), not succeed.
	osroChildProbe("create", filepath.Join(dir, "probe-create"), os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	osroChildProbe("db-write", path, os.O_WRONLY)
	osroChildProbe("wal-write", path+"-wal", os.O_WRONLY)
	osroChildProbe("shm-write", path+"-shm", os.O_WRONLY)

	// Access mode of every descriptor the reader holds, enumerated from the
	// live descriptor table rather than a fixed range. Only paths under the
	// synthetic fixture directory are reported; no host file contents are read.
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil {
			continue
		}
		name, ok := osroDarwinFDPath(fd)
		if !ok || !strings.HasPrefix(name, dir+string(filepath.Separator)) {
			continue
		}
		fmt.Fprintf(os.Stdout, "CHILD_FD path=%s accmode=%d\n", name, fl&unix.O_ACCMODE)
	}
}

// osroProbeRefused reports whether the child output shows a Seatbelt refusal
// (EPERM or EACCES) for the named probe.
func osroProbeRefused(out, name string) bool {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EACCES} {
		if strings.Contains(out, fmt.Sprintf("CHILD_PROBE name=%s errno=%d\n", name, int(errno))) {
			return true
		}
	}
	return false
}

// Parent: a live, idle synthetic WAL writer stays open while a sandboxed child
// reads through os-ro. The child must read exact enabled rows, hold the three
// fixture files read-only, be refused every write probe under the fixture
// directory with EPERM/EACCES, and still write its isolated TMPDIR. The
// fixture directory, entries and content must be unchanged.
// Baseline: RED because the os-ro open in the child fails.
func TestOSROSandboxDenyChildReadOnly(t *testing.T) {
	if _, err := os.Stat(osroSandboxBinary); err != nil {
		t.Skipf("%s unavailable: %v; sandbox control not verified on this host", osroSandboxBinary, err)
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "db")
	home := filepath.Join(base, "home")
	tmp := filepath.Join(base, "tmp")
	for _, d := range []string{dir, home, tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "sandbox.db")

	w := osroWriter(t, path)
	osroExec(t, w, `INSERT INTO meta (id, enabled, value) VALUES (1, 1, 'v1')`)
	for _, name := range []string{"sandbox.db", "sandbox.db-wal", "sandbox.db-shm"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("precondition: active WAL file %s: %v", name, err)
		}
	}
	before := osroSnapshot(t, dir)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(osroSandboxBinary, "-p", osroSandboxProfile(dir), exe, "-test.run=^TestOSROSandboxChildProcess$")
	cmd.Dir = tmp
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + home,
		"TMPDIR=" + tmp,
		osroSandboxChildEnv + "=1",
		osroSandboxChildPath + "=" + path,
		osroSandboxChildTmp + "=" + tmp,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sandboxed child failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	out := stdout.String()

	if !strings.Contains(out, "CHILD_ROWS=1=v1;\n") {
		t.Errorf("child rows missing exact 1=v1;:\n%s", out)
	}
	if !strings.Contains(out, "CHILD_POSITIVE_WRITE=ok\n") {
		t.Errorf("positive TMPDIR write control failed:\n%s", out)
	}
	for _, probe := range []string{"create", "db-write", "wal-write", "shm-write"} {
		if !osroProbeRefused(out, probe) {
			t.Errorf("write probe %s not refused with EPERM/EACCES:\n%s", probe, out)
		}
	}
	for _, name := range []string{"sandbox.db", "sandbox.db-wal", "sandbox.db-shm"} {
		want := fmt.Sprintf("CHILD_FD path=%s accmode=%d\n", filepath.Join(dir, name), unix.O_RDONLY)
		if !strings.Contains(out, want) {
			t.Errorf("missing read-only descriptor line %q:\n%s", want, out)
		}
	}
	osroAssertSameState(t, before, osroSnapshot(t, dir))
}
