//go:build cgo
// +build cgo

package sevguest

//#cgo CFLAGS: -Wall -D_FILE_OFFSET_BITS=64
//#cgo LDFLAGS: -luuid -lssl -lcrypto -Wl,--allow-multiple-definition
//#cgo pkg-config: fuse
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include "sev_guest_device.h"
import "C"
import (
	"unsafe"
)

type Device struct{}

func (*Device) Start() {
	args := []string{"sev-guest", "-f"}
	argv := make([]*C.char, len(args)+1)
	for i, arg := range args {
		argv[i] = C.CString(arg)
		defer C.free(unsafe.Pointer(argv[i]))
	}
	argv[len(args)] = nil
	C.initDevice(C.int(len(args)), &argv[0])
}
