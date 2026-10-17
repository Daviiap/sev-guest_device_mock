#ifndef __REPORT_H__
#define __REPORT_H__

#include <linux/types.h>
#include "attestation.h"

/* Loads the base report from report.bin and applies the overrides. Returns 0 on success. */
int get_report(struct attestation_report* report);
void override_measurement(const uint8* new_measurement);
void override_policy(uint64 new_policy);

#endif
