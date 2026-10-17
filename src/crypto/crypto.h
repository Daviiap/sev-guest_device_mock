#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <linux/types.h>
#include "../snp/attestation.h"

#define KEY_SEL_DEFAULT 0
#define KEY_SEL_VCEK 1
#define KEY_SEL_VLEK 2

extern char PRIVATE_VCEK_PATH[128];
extern char PRIVATE_VLEK_PATH[128];

/*
 * Maps the key_sel of a request to the endorsement key that will actually be
 * used (KEY_SEL_VCEK or KEY_SEL_VLEK). Returns -1 for an invalid key_sel.
 * KEY_SEL_DEFAULT resolves to the VLEK when one is installed, as the firmware
 * does when the hypervisor loaded a VLEK.
 */
int resolve_key_sel(__u32 key_sel);

/* Signs the report with the key selected by resolved_key_sel. */
int sign_attestation_report(struct attestation_report* report, int resolved_key_sel);

#endif
