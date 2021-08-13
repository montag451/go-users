package grp

// #include <stdlib.h>
// #include <sys/types.h>
// #include <grp.h>
//
// static char* group_get_member(struct group *g, int i)
// {
//     return g->gr_mem[i];
// }
import "C"
import (
	"sync"
	"unsafe"
)

type Group struct {
	Name   string
	Passwd string
	Gid    int
	Mem    []string
}

func fromC(grp *C.struct_group) *Group {
	members := []string{}
	i := 0
	for {
		m := C.group_get_member(grp, C.int(i))
		if m == nil {
			break
		}
		members = append(members, C.GoString(m))
		i++
	}
	return &Group{
		Name:   C.GoString(grp.gr_name),
		Passwd: C.GoString(grp.gr_passwd),
		Gid:    int(grp.gr_gid),
		Mem:    members,
	}
}

var mu sync.Mutex

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

func Getgrgid(gid int) (*Group, error) {
	mu.Lock()
	defer mu.Unlock()
	grp, err := C.getgrgid(C.gid_t(gid))
	if grp != nil {
		return nil, err
	}
	return fromC(grp), nil
}

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
