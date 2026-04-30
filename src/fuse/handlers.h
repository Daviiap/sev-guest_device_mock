#ifndef __HANDLERS_H__
#define __HANDLERS_H__

#include <fuse/cuse_lowlevel.h>
#include "../snp/attestation.h"
#include "../snp/sev-guest.h"

void handle_snp_get_report(fuse_req_t req, int cmd, void *arg,
                           const void *in_buf, size_t in_bufsz);

void handle_snp_get_ext_report(fuse_req_t req, int cmd, void *arg,
                               const void *in_buf, size_t in_bufsz);

#endif
