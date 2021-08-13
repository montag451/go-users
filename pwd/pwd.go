package pwd

// #include <stdlib.h>
// #include <sys/types.h>
// #include <pwd.h>
import "C"
import (
	"sync"
	"unsafe"
)

type Passwd struct {
	Name   string
	Passwd string
	Uid    int
	Gid    int
	Gecos  string
	Dir    string
	Shell  string
}

func fromC(pwd *C.struct_passwd) *Passwd {
	return &Passwd{
		Name:   C.GoString(pwd.pw_name),
		Passwd: C.GoString(pwd.pw_passwd),
		Uid:    int(pwd.pw_uid),
		Gid:    int(pwd.pw_gid),
		Gecos:  C.GoString(pwd.pw_gecos),
		Dir:    C.GoString(pwd.pw_dir),
		Shell:  C.GoString(pwd.pw_shell),
	}
}

var mu sync.Mutex

func Getpwnam(name string) (*Passwd, error) {
	mu.Lock()
	defer mu.Unlock()
	csName := C.CString(name)
	defer C.free(unsafe.Pointer(csName))
	pwd, err := C.getpwnam(csName)
	if pwd == nil {
		return nil, err
	}
	return fromC(pwd), nil
}

func Getpwuid(uid int) (*Passwd, error) {
	mu.Lock()
	defer mu.Unlock()
	pwd, err := C.getpwuid(C.uid_t(uid))
	if pwd != nil {
		return nil, err
	}
	return fromC(pwd), nil
}

func Getpwall() ([]*Passwd, error) {
	mu.Lock()
	defer mu.Unlock()
	C.setpwent()
	defer C.endpwent()
	pwds := []*Passwd{}
	for {
		pwd, err := C.getpwent()
		if pwd == nil {
			if err != nil {
				return nil, err
			}
			return pwds, nil
		}
		pwds = append(pwds, fromC(pwd))
	}
}
