package main

import (
	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

func main() {
	device_mock := sevguest.New()
	device_mock.Start()
	device_mock.Stop()
	device_mock.Start()
	device_mock.Stop()
}
