// Test-only seam consumed by the external vfs_test package (export_test idiom).
// Compiled only into the vfs test binary. It is not production API and adds no
// hook. It copies an engine-captured *vfsShm BY VALUE, resets the copy's
// descriptor, regions and lock state, and then drives the copy. The engine's
// original SharedMemory (and its mapped pointers) is never touched.

//go:build (linux || darwin) && !(sqlite3_flock || sqlite3_dotlk)

package vfs

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// OSROShmObservation reports one clone-based shmOpen probe.
type OSROShmObservation struct {
	OpenErr       error
	HasFile       bool
	AccMode       int
	PathAfterOpen bool
}

// osroClone copies the captured shm by value and resets per-open state.
// A field added to vfsShm (for example a strict read-only flag) is copied
// implicitly, so the clone exercises whatever capability the patch installed.
func osroClone(sm SharedMemory) (*vfsShm, error) {
	s, ok := sm.(*vfsShm)
	if !ok || s == nil {
		return nil, errors.New("captured SharedMemory is not *vfsShm")
	}
	c := *s
	c.File = nil
	c.regions = nil
	c.fileLock = false
	return &c, nil
}

// OSROShmCloneOpen runs shmOpen on a clone and reports the outcome. The
// descriptor access mode is read with F_GETFL when the clone holds a file.
func OSROShmCloneOpen(sm SharedMemory) (OSROShmObservation, error) {
	c, err := osroClone(sm)
	if err != nil {
		return OSROShmObservation{}, err
	}
	var obs OSROShmObservation
	obs.OpenErr = c.shmOpen()
	if c.File != nil {
		obs.HasFile = true
		fl, err := unix.FcntlInt(c.File.Fd(), unix.F_GETFL, 0)
		if err != nil {
			c.shmUnmap(false)
			return obs, err
		}
		obs.AccMode = fl & unix.O_ACCMODE
	}
	_, statErr := os.Stat(c.path)
	obs.PathAfterOpen = statErr == nil
	c.shmUnmap(false)
	return obs, nil
}

// OSROShmCloneUnmapDelete opens a clone and unmaps it with delete=true.
// hadFile reports whether the clone actually held a descriptor at unmap time;
// when false the delete property was not exercised and the caller must fail.
// sourceExists reports whether the source path still exists afterwards.
func OSROShmCloneUnmapDelete(sm SharedMemory) (hadFile, sourceExists bool, err error) {
	c, err := osroClone(sm)
	if err != nil {
		return false, false, err
	}
	_ = c.shmOpen()
	hadFile = c.File != nil
	c.shmUnmap(true)
	_, statErr := os.Stat(c.path)
	return hadFile, statErr == nil, nil
}
