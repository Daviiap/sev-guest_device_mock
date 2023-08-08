# SEV-GUEST DEVICE MOCK
This repository contains an implementation of a `sev-guest` character device mock using [CUSE (Character device in user space)](https://github.com/libfuse/libfuse/). The sev-guest character device is typically exposed inside AMD SEV-SNP guests VMs, allowing the guest to make requests to the AMD Secure Processor.

**Please note that this mock implementation does not interact with the actual AMD Secure Processor and is intended for testing or educational purposes only.**

## Implemented Requests

Currently, the following request is implemented in this mock `sev-guest` chardev:

- **GET_REPORT**: This request retrieves a report containing information about the AMD Secure Processor and the Guest VM. The implementation provides a mock report for testing purposes.

## Build Instructions

To build the code, follow these steps:

1. Ensure that you have `gcc`, `pkg-config`, `fuse` and `golang` installed on your system.

2. Clone this repository to your local machine:

```bash
git clone https://github.com/Daviiap/sev-guest_device_mock.git
```

3. Change into the cloned directory:

```bash
cd sev-guest_device_mock
```

4. Run the configure script:

```bash
./configure
```

To run the configure script, you need to have root privileges. This script will generate dummy VCEK and VLEK, along with the respective cert_chain for both keys. Once generated, the script will move these files to the /etc/sev-guest directory.

5. Now, you can build the code:

```bash
make
```

This command will use the provided Makefile to compile the code and generate the sev-guest binary inside the bin directory.

To verify the signature of the report, you can use the ./keys_gen/keys/vcek.crt file. It contains the essential certificate required for signature validation. Furthermore, you can rely on the ./keys_gen/keys/cert_chain.pem file to verify the signature of the vcek.crt certificate. This chain file guarantees the authenticity and integrity of the certificate by including all the necessary intermediate certificates in the validation process, similar to an authentic AMD environment.

## Usage
Once the code is successfully built, you can run the sev-guest binary. Make sure you have the necessary permissions to access and use cuse on your system.

To run the sev-guest mock, use the following command:

```bash
sudo ./bin/sev-guest
```

To see the options use:

```bash
sudo ./bin/sev-guest -h
```

## Cleaning Up
To clean up the compiled object files and the sev-guest binary, you can run the following command:

```bash
make clean
```

This command will remove the object files and the sev-guest binary from the bin directory.

## Ref

[SEV Secure Nested Paging Firmware ABI Specification](https://www.amd.com/system/files/TechDocs/56860.pdf)

## Future work

* Refactor the code;
* Use a configuration file to define the report fields;
* Enhance error handling;
* Allow extended attestation report requests;
