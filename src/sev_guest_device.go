//go:build cgo

package sevguest

//#cgo CFLAGS: -D_FILE_OFFSET_BITS=64
//#cgo LDFLAGS: -luuid -lssl -lcrypto -lpthread
//#cgo pkg-config: fuse
//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include "sev_guest_device.h"
import "C"

import (
	"time"
)

const (
	startTimeout = 5 * time.Second
	stopTimeout  = 5 * time.Second
	pollInterval = 10 * time.Millisecond
)

type device struct {
	// done is closed when the CUSE session loop returns.
	done chan struct{}
}

// Start creates /dev/sev-guest and returns once it is ready. It panics if the
// device cannot be started.
func (d *device) Start() {
	if d.IsRunning() {
		return
	}

	done := make(chan struct{})
	var res int
	go func() {
		res = int(C.init_device())
		close(done)
	}()
	d.done = done

	timeout := time.After(startTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for !d.IsRunning() {
		select {
		case <-done:
			if res != 0 {
				panic("failed to initialize sev-guest device mock")
			}
			panic("sev-guest device mock exited during startup")
		case <-timeout:
			panic("timeout waiting for sev-guest device to become ready")
		case <-ticker.C:
		}
	}
}

// Stop removes the device and waits for the session to end.
func (d *device) Stop() {
	if d.done == nil {
		return
	}
	C.stop_device()
	select {
	case <-d.done:
	case <-time.After(stopTimeout):
	}
	d.done = nil
}

// Done returns a channel that is closed when the device stops. It is nil if
// the device was never started.
func (d *device) Done() <-chan struct{} {
	return d.done
}

func (*device) IsRunning() bool {
	return C.device_is_running() == 1
}

func (d *device) SetMeasurement(measurement []byte) {
	if len(measurement) != 48 {
		panic("measurement must be exactly 48 bytes")
	}
	C.override_measurement((*C.uchar)(&measurement[0]))
}

func (d *device) SetPolicy(policy uint64) {
	C.override_policy(C.ulong(policy))
}

func New() *device {
	return &device{}
}
