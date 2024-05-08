package main

import (
	"fmt"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

func main() {
	device_mock := sevguest.Device{}
	go device_mock.Start()
	defer device_mock.Stop()
	fmt.Println("Device /dev/sev-guest running.")
	for {
	}
}
