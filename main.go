package main

import (
	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

func main() {
	device_mock := sevguest.Device{}
	device_mock.Start()
}
