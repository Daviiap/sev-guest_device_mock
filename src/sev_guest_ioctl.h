#define __SEV_GUEST_IOCTL_H__

#include "./snp/attestation.h"

void get_report(struct attestation_report* report);
void sign_attestation_report(struct attestation_report* report, __u32 key_sel);