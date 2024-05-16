package main

import (
	"fmt"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
)

func main() {
	device_mock := sevguest.New()
	device_mock.Start()
	defer device_mock.Stop()
	fmt.Println("device running on `/dev/sev-guest`")
	for device_mock.IsRunning() {
	}
}
