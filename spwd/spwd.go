// +build unix && !android && cgo

// Package spwd provides some functions to query the shadow database
// of a UNIX system.
package spwd

// #include <stdlib.h>
// #include <shadow.h>
import "C"
import (
	"sync"
	"time"
	"unsafe"
)

// Spwd represents a record in the shadow database.
type Spwd struct {
	Namp   string
	Pwdp   string
	Lstchg time.Time
	Min    int
	Max    int
	Warn   int
	Inact  int
	Expire time.Time
}

func fromC(spwd *C.struct_spwd) *Spwd {
	return &Spwd{
		Namp:   C.GoString(spwd.sp_namp),
		Pwdp:   C.GoString(spwd.sp_pwdp),
		Lstchg: time.Unix(int64(spwd.sp_lstchg), 0),
		Min:    int(spwd.sp_min),
		Max:    int(spwd.sp_max),
		Warn:   int(spwd.sp_warn),
		Inact:  int(spwd.sp_inact),
		Expire: time.Unix(int64(spwd.sp_expire), 0),
	}
}

var mu sync.Mutex

// Getspnam looks up the shadow database and returns the record
// matching the given user name. If no record is found, it returns
// (nil, nil). It is the equivalent of the C function getspnam.
func Getspnam(name string) (*Spwd, error) {
	mu.Lock()
	defer mu.Unlock()
	csName := C.CString(name)
	defer C.free(unsafe.Pointer(csName))
	spwd, err := C.getspnam(csName)
	if spwd == nil {
		return nil, err
	}
	return fromC(spwd), nil
}

// Getspall returns all the records in the shadow database.
func Getspall() ([]*Spwd, error) {
	mu.Lock()
	defer mu.Unlock()
	C.setspent()
	defer C.endspent()
	spwds := []*Spwd{}
	for {
		spwd, err := C.getspent()
		if spwd == nil {
			if err != nil {
				return nil, err
			}
			return spwds, nil
		}
		spwds = append(spwds, fromC(spwd))
	}
}
