//go:build !((linux || darwin) && !(sqlite3_flock || sqlite3_dotlk))

package vfs

// osROVFS returns nil: the strict read-only VFS "os-ro" is not supported
// on this platform or build tag, so Find reports no match for it.
func osROVFS() VFS { return nil }
