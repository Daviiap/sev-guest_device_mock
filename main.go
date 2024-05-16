package main

import (
	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

func main() {
	device_mock := sevguest.New()
	device_mock.Start()
	defer device_mock.Stop()
}
