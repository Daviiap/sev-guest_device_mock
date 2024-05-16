//go:build cgo
// +build cgo

package sevguest

//#cgo CFLAGS: -D_FILE_OFFSET_BITS=64
//#cgo LDFLAGS: -luuid -lssl -lcrypto -Wl,--allow-multiple-definition
//#cgo pkg-config: fuse
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include "sev_guest_device.h"
import "C"

type device struct{}

func (d *device) Start() {
	if !d.IsRunning() {
		go C.init_device()
		for !d.IsRunning() {
		}
	}
}

func (d *device) Stop() {
	if d.IsRunning() {
		C.stop_device()
		for d.IsRunning() {
		}
	}
}

func (*device) IsRunning() bool {
	return C.device_is_running() == 1
}

func New() *device {
	return &device{}
}
