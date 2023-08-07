#define __SEV_GUEST_IOCTL_H__

#include "./snp/attestation.h"

void get_report(struct attestation_report* report, uint8 report_data[64], uint8 report_id[32], __u32 signing_key_sel);
void sign_attestation_report(struct attestation_report* report, __u32 key_sel);