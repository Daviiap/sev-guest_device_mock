#define __SEV_GUEST_IOCTL_H__

#include <fuse/cuse_lowlevel.h>

void sev_guest_ioctl(fuse_req_t req, int cmd, void *arg, struct fuse_file_info *fi, unsigned flags, const void *in_buf, size_t in_bufsz, size_t out_bufsz);
