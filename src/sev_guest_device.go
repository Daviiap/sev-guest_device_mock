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

type Device struct{}

func (*Device) Start() {
	C.initDevice()
}
