//go:build (linux || darwin) && !(sqlite3_flock || sqlite3_dotlk)

package vfs

import (
	"io"
	"io/fs"
	"os"
)

// vfsROOS is the strict read-only VFS, selected by the reserved name "os-ro".
// It opens existing files read-only and never creates, writes, truncates,
// chmods, chowns, or unlinks anything.
// It is only available on Darwin and Linux with OFD locks; see os_ro_other.go.
type vfsROOS struct{ vfsOS }

func osROVFS() VFS { return vfsROOS{} }

func (vfsROOS) Open(name string, flags OpenFlag) (File, OpenFlag, error) {
	// Anonymous (temporary) files would be created; refuse them.
	return nil, 0, _CANTOPEN
}

func (vfsROOS) Delete(name string, syncDir bool) error {
	return _READONLY
}

func (vfsROOS) OpenFilename(name *Filename, flags OpenFlag) (File, OpenFlag, error) {
	if name.String() == "" || flags&OPEN_DELETEONCLOSE != 0 {
		return nil, flags, _CANTOPEN
	}
	// modeof would Chmod/Chown the descriptor, which is a mutation; refuse it
	// before anything is opened.
	if name.URIParameter("modeof") != "" {
		return nil, flags, _CANTOPEN
	}
	flags &^= OPEN_READWRITE | OPEN_CREATE | OPEN_EXCLUSIVE
	flags |= OPEN_READONLY

	osf, err := os.OpenFile(name.String(), os.O_RDONLY|_O_NOFOLLOW, 0)
	if err != nil {
		return nil, flags, sysError{err, _CANTOPEN}
	}

	// One allocation: vfsFile is embedded by value, so promoted pointer
	// methods remain available through the addressable embedded field.
	file := &vfsROFile{vfsFile: vfsFile{
		File:  osf,
		flags: flags,
		mmap:  NewMemoryMapper(osf, flags),
	}}
	if flags&(OPEN_MAIN_DB|OPEN_MEMORY) == OPEN_MAIN_DB {
		file.shm = &vfsShm{path: name.String() + "-shm", strictRO: true}
	}
	return file, flags, nil
}

// vfsROFile shadows every promoted *os.File method that can change the file
// or its metadata, so none of them reaches the operating system.
// Writes through the descriptor are also refused by the kernel (O_RDONLY),
// but Chmod and Chown are not, so they are shadowed explicitly.
// All other vfsFile behaviour, including optional interfaces, is promoted.
type vfsROFile struct{ vfsFile }

var (
	_ File                   = (*vfsROFile)(nil)
	_ FileHasMoved           = (*vfsROFile)(nil)
	_ FileSizeHint           = (*vfsROFile)(nil)
	_ FilePersistWAL         = (*vfsROFile)(nil)
	_ FilePowersafeOverwrite = (*vfsROFile)(nil)
	_ FileSharedMemory       = (*vfsROFile)(nil)
	_ FileMemoryMapper       = (*vfsROFile)(nil)
	_ FileLockState          = (*vfsROFile)(nil)
)

func (*vfsROFile) Write(p []byte) (int, error)              { return 0, _READONLY }
func (*vfsROFile) WriteString(s string) (int, error)        { return 0, _READONLY }
func (*vfsROFile) ReadFrom(r io.Reader) (int64, error)      { return 0, _READONLY }
func (*vfsROFile) WriteAt(p []byte, off int64) (int, error) { return 0, _READONLY }
func (*vfsROFile) Truncate(size int64) error                { return _READONLY }
func (*vfsROFile) Sync(flags SyncFlag) error                { return _READONLY }
func (*vfsROFile) SizeHint(size int64) error                { return _READONLY }
func (*vfsROFile) Chmod(mode fs.FileMode) error             { return _READONLY }
func (*vfsROFile) Chown(uid, gid int) error                 { return _READONLY }
