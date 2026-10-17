# SEV-GUEST DEVICE MOCK (Go Module)
This repository contains an implementation of a `sev-guest` character device mock using [CUSE (Character device in user space)](https://github.com/libfuse/libfuse/) to be used on Golang codes. The sev-guest character device is typically exposed inside AMD SEV-SNP guests VMs, allowing the guest to make requests to the AMD Secure Processor.

**Please note that this mock implementation does not interact with the actual AMD Secure Processor and is intended for testing or educational purposes only.**

## Implemented Requests

Currently, the following request is implemented in this mock `sev-guest` chardev:

- **GET_REPORT**: This request retrieves a report containing information about the AMD Secure Processor and the Guest VM. The implementation provides a mock report for testing purposes.

- **GET_EXT_REPORT**: This request retrieves a report containing information about the AMD Secure Processor and the Guest VM and the Certificate used to sign this report.

## Build Instructions

To build the code, follow these steps:

1. Clone this repository to your local machine:

```bash
git clone https://github.com/Daviiap/sev-guest_device_mock.git
```

2. Change into the cloned directory:

```bash
cd sev-guest_device_mock
```

3. Run the configure script:

```bash
./configure
```

To run the configure script, you need to have root privileges. This script will install the dependencies and generate dummy VCEK and VLEK, along with the respective cert_chain for both keys. Once generated, the script will move these files to the `/etc/sev-guest` directory.

The generated keys are written to `keys_gen/keys/` and installed in `/etc/sev-guest`:

| File | Content |
| --- | --- |
| `/etc/sev-guest/report.bin` | Base attestation report (copied from the repository root) |
| `/etc/sev-guest/{vcek,vlek}/private.pem` | Endorsement key used to sign the reports |
| `/etc/sev-guest/{vcek,vlek}/public.pem` | VCEK/VLEK certificate |
| `/etc/sev-guest/{vcek,vlek}/cert_chain.pem` | ASK (or ASVK) and ARK certificates, in the KDS `cert_chain` order |
| `/etc/sev-guest/{vcek,vlek}/crl.der` | CRL signed by the ARK |

The certificates follow the layout of the real AMD ones: the same distinguished names (UTF8String, in AMD's order), serial numbers, key usages and extensions. The VCEK/VLEK carries only the AMD extensions, with the raw chip ID in the HWID extension and the product name with the stepping (e.g. `Milan-B1`) taken from `report.bin`. The only intended differences are the CRL distribution points, which point to the mock KDS (`http://localhost:<kds_port>`), and the RSASSA-PSS parameters, which omit the default trailer field that AMD encodes explicitly.

The certificates are generated from the TCB, CPUID and chip ID of `report.bin`, so run `./configure` again whenever `report.bin` changes. When a VLEK is installed, requests with the default `key_sel` are signed with the VLEK.

`SNP_GET_EXT_REPORT` returns the certificates the way a host does: a GHCB certificate table followed by the DER-encoded VCEK/VLEK, ASK and ARK.

## Running the standalone mock

```bash
make
sudo ./bin/sev-guest -config config.json
```

`config.json` accepts:

| Field | Default | Description |
| --- | --- | --- |
| `kds_port` | `8080` | Port of the mock KDS HTTP server |
| `custom_report_path` | `report.json` | File with report overrides |
| `keys_dir` | `/etc/sev-guest` | Directory the mock KDS serves the certificates from |

Relative paths are resolved against the directory of the config file. `report.json` overrides fields of `report.bin`:

```json
{
    "measurement": "<96 hex chars>",
    "policy": 196608
}
```

The mock KDS (also available to Go code as `sevguest.KDSHandler`) serves `/vcek/v1/Milan/cert_chain`, `/vcek/v1/Milan/crl`, `/vcek/v1/Milan/{hwid}` (the VCEK in DER), `/vlek/v1/Milan/cert_chain` and `/vlek/v1/Milan/crl`.

## Usage
To use the package on your Golang code, you must get it running:

```sh
go get github.com/Daviiap/sev-guest_device_mock
```

An example of code using the mock:

```go
package main

import (
	"fmt"
	"log"

	sevguest "github.com/Daviiap/sev-guest_device_mock/src"
	"github.com/google/go-sev-guest/client"
)

func main() {
	device_mock := sevguest.New()
	device_mock.Start()
	defer device_mock.Stop()

	device, _ := client.OpenDevice()
	defer device.Close()

	rawReport, err := client.GetRawReport(device, [64]byte{})

	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rawReport)
}

```

## Tests

The integration tests in `test/` drive the mock through [go-sev-guest](https://github.com/google/go-sev-guest), including its full attestation verification (certificate schema, chain, CRL and signature) against the mock KDS. They need root and the keys installed by `./configure`:

```bash
cd test
go test -c -o device.test .
sudo ./device.test -test.v
```

## Ref

[SEV Secure Nested Paging Firmware ABI Specification](https://www.amd.com/system/files/TechDocs/56860.pdf)

## Future work

* Allow overriding more report fields through `report.json`;
* Support `SNP_GET_DERIVED_KEY`.
