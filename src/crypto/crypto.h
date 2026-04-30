#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <linux/types.h>
#include "../snp/attestation.h"

int sign_attestation_report(struct attestation_report* report, __u32 key_sel);

#endif
