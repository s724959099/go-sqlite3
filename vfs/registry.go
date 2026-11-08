package vfs

import "sync"

var (
	// +checklocks:vfsRegistryMtx
	vfsRegistry    map[string]VFS
	vfsRegistryMtx sync.RWMutex
)

// osROName names the strict read-only VFS. It is reserved and only
// matches on platforms where osROVFS returns a VFS.
const osROName = "os-ro"

// Find returns a VFS given its name.
// If there is no match, nil is returned.
// If name is empty or "os", the default VFS is returned.
// If name is "os-ro", the strict read-only VFS is returned where supported, else nil.
//
// https://sqlite.org/c3ref/vfs_find.html
func Find(name string) VFS {
	if name == "" || name == "os" {
		return vfsOS{}
	}
	if name == osROName {
		return osROVFS()
	}
	vfsRegistryMtx.RLock()
	defer vfsRegistryMtx.RUnlock()
	return vfsRegistry[name]
}

// Register registers a VFS.
// Empty, "os" and "os-ro" are reserved names.
//
// https://sqlite.org/c3ref/vfs_find.html
func Register(name string, vfs VFS) {
	if name == "" || name == "os" || name == osROName {
		return
	}
	vfsRegistryMtx.Lock()
	if vfsRegistry == nil {
		vfsRegistry = map[string]VFS{}
	}
	vfsRegistry[name] = vfs
	vfsRegistryMtx.Unlock()
}

// Unregister unregisters a VFS.
//
// https://sqlite.org/c3ref/vfs_find.html
func Unregister(name string) {
	vfsRegistryMtx.Lock()
	delete(vfsRegistry, name)
	vfsRegistryMtx.Unlock()
}
