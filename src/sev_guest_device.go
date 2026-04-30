//go:build cgo

package sevguest

//#cgo CFLAGS: -D_FILE_OFFSET_BITS=64
//#cgo LDFLAGS: -luuid -lssl -lcrypto -Wl,--allow-multiple-definition
//#cgo pkg-config: fuse
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include "sev_guest_device.h"
import "C"

import (
	"time"
)

type device struct{}

func (d *device) Start() {
	errCh := make(chan int, 1)
	go func() {
		errCh <- int(C.init_device())
	}()
	for !d.IsRunning() {
		select {
		case err := <-errCh:
			if err != 0 {
				panic("failed to initialize sev-guest device mock")
			}
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (d *device) Stop() {
	C.stop_device()
	for d.IsRunning() {
		time.Sleep(10 * time.Millisecond)
	}
}

func (*device) IsRunning() bool {
	return C.device_is_running() == 1
}

func New() *device {
	return &device{}
}
