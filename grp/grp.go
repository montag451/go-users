//go:build !windows && !android && cgo
// +build !windows,!android,cgo

// Package grp provides some functions to query the group database of
// a UNIX system.
package grp

// #include <stdlib.h>
// #include <sys/types.h>
// #include <grp.h>
import "C"
import (
	"sync"
	"unsafe"
)

// Group represents a record in the group database.
type Group struct {
	Name   string
	Passwd string
	Gid    int
	Mem    []string
}

func fromC(grp *C.struct_group) *Group {
	members := []string{}
	m := grp.gr_mem
	for *m != nil {
		members = append(members, C.GoString(*m))
		m = (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(m)) + unsafe.Sizeof(*m)))
	}
	return &Group{
		Name:   C.GoString(grp.gr_name),
		Passwd: C.GoString(grp.gr_passwd),
		Gid:    int(grp.gr_gid),
		Mem:    members,
	}
}

var mu sync.Mutex

// Getgrnam looks up the group database and returns the record
// matching the given group name. If no record is found, it returns
// (nil, nil). It is the equivalent of the C function getgrnam.
func Getgrnam(name string) (*Group, error) {
	mu.Lock()
	defer mu.Unlock()
	csName := C.CString(name)
	defer C.free(unsafe.Pointer(csName))
	grp, err := C.getgrnam(csName)
	if grp == nil {
		return nil, err
	}
	return fromC(grp), nil
}

// Getgrgid looks up the group database and returns the record
// matching the given GID. If no record is found, it returns (nil,
// nil). It is the equivalent of the C function getgrgid.
func Getgrgid(gid int) (*Group, error) {
	mu.Lock()
	defer mu.Unlock()
	grp, err := C.getgrgid(C.gid_t(gid))
	if grp == nil {
		return nil, err
	}
	return fromC(grp), nil
}

// Getgrall returns all the records in the group database.
func Getgrall() ([]*Group, error) {
	mu.Lock()
	defer mu.Unlock()
	C.setgrent()
	defer C.endgrent()
	grps := []*Group{}
	for {
		grp, err := C.getgrent()
		if grp == nil {
			if err != nil {
				return nil, err
			}
			return grps, nil
		}
		grps = append(grps, fromC(grp))
	}
}
