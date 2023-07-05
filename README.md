# SEV-GUEST DEVICE MOCK
This repository contains an implementation of a mock `sev-guest` character device using `cuse` (Character device in user space). The `sev-guest` character device is typically exposed inside AMD SEV-SNP guests VMs, allowing the guest to make requests to the AMD Secure Processor.

## Implemented Requests

Currently, the following request is implemented in this mock `sev-guest` chardev:

- **GET_REPORT**: This request retrieves a report containing information about the AMD Secure Processor and the Guest VM. The implementation provides a mock report for testing purposes.

Please note that this mock implementation does not interact with the actual AMD Secure Processor and is intended for testing or educational purposes only.

## Build Instructions

To build the code, follow these steps:

1. Ensure that you have `gcc`, `pkg-config` and `fuse` installed on your system.

2. Clone this repository to your local machine:

```bash
git clone https://github.com/Daviiap/sev-guest_device_mock.git
```

3. Change into the cloned directory:

```bash
cd sev-guest_device_mock
```

4. Now, you can build the code:

```bash
make
```

This command will use the provided Makefile to compile the code and generate the sev-guest binary inside the bin directory.

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
