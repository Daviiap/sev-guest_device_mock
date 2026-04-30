#ifndef __REPORT_H__
#define __REPORT_H__

#include <linux/types.h>
#include "attestation.h"

void get_report(struct attestation_report* report);
void generate_random_array(uint8* array, int length);

#endif
