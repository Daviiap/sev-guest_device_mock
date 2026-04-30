#define FUSE_USE_VERSION 31

#include <errno.h>
#include <fcntl.h>
#include <fuse/cuse_lowlevel.h>
#include <fuse/fuse_opt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuse/handlers.h"
#include "snp/attestation.h"
#include "snp/cert-table.h"
#include "snp/report.h"
#include "snp/sev-guest.h"

static const char *usage =
    "usage: sev-guest [options]\n"
    "\n"
    "options:\n"
    "    --help|-h             print this help message\n"
    "    --maj=MAJ|-M MAJ      device major number\n"
    "    --min=MIN|-m MIN      device minor number\n"
    "    -d   -o debug         enable debug output (implies -f)\n"
    "    -f                    foreground operation\n"
    "    -s                    disable multi-threaded operation\n"
    "\n";

#define SEV_GUEST_OPT(t, p) \
    { t, offsetof(struct sev_guest_param, p), 1 }

static struct attestation_report report;
static struct fuse_session *se = NULL;

static void sev_guest_open(fuse_req_t req, struct fuse_file_info *fi) {
    fuse_reply_open(req, fi);
}

struct sev_guest_param {
    unsigned major;
    unsigned minor;
    int is_help;
};

static const struct fuse_opt sev_guest_opts[] = {
    SEV_GUEST_OPT("-M %u", major),
    SEV_GUEST_OPT("--maj=%u", major),
    SEV_GUEST_OPT("-m %u", minor),
    SEV_GUEST_OPT("--min=%u", minor),
    FUSE_OPT_KEY("-h", 0),
    FUSE_OPT_KEY("--help", 0),
    FUSE_OPT_END};

static int sev_guest_process_arg(void *data, const char *arg, int key,
                                 struct fuse_args *outargs) {
    struct sev_guest_param *param = data;

    (void)outargs;
    (void)arg;

    switch (key) {
        case 0:
            param->is_help = 1;
            fprintf(stderr, "%s", usage);
            return fuse_opt_add_arg(outargs, "-ho");
        default:
            return 1;
    }
}

void sev_guest_ioctl(fuse_req_t req, int cmd, void *arg,
                     struct fuse_file_info *fi, unsigned flags,
                     const void *in_buf, size_t in_bufsz, size_t out_bufsz) {
    (void)fi;
    (void)out_bufsz;

    if (flags & FUSE_IOCTL_COMPAT) {
        fuse_reply_err(req, ENOSYS);
        return;
    }

    switch (cmd) {
        case SNP_GET_REPORT:
            printf("[debug] IOCTL received: SNP_GET_REPORT (in_bufsz=%zu)\n", in_bufsz);
            handle_snp_get_report(req, cmd, arg, in_buf, in_bufsz);
            break;
        case SNP_GET_EXT_REPORT:
            printf("[debug] IOCTL received: SNP_GET_EXT_REPORT (in_bufsz=%zu)\n", in_bufsz);
            handle_snp_get_ext_report(req, cmd, arg, in_buf, in_bufsz);
            break;
        default:
            printf("[debug] IOCTL received: UNKNOWN cmd=0x%x\n", cmd);
            fuse_reply_err(req, EINVAL);
            return;
    }
}

static const struct cuse_lowlevel_ops sev_guest_clops = {
    .open = sev_guest_open,
    .ioctl = sev_guest_ioctl,
};

int device_is_running() {
    return se != NULL && access("/dev/sev-guest", F_OK) == 0 && !fuse_session_exited(se);
}

int init_device() {
    if (!device_is_running()) {
        int argc = 2;
        char *argv[] = {"sev-guest", "-f"};
        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        struct sev_guest_param param = {0, 0, 0};
        char dev_name[18] = "DEVNAME=sev-guest";
        const char *dev_info_argv[] = {dev_name};
        struct cuse_info dev_info;
        int ret = 1;

        if (fuse_opt_parse(&args, &param, sev_guest_opts,
                           sev_guest_process_arg)) {
            printf("failed to parse option\n");
            fuse_opt_free_args(&args);
            return ret;
        }

        get_report(&report);

        memset(&dev_info, 0x00, sizeof(dev_info));
        dev_info.dev_major = param.major;
        dev_info.dev_minor = param.minor;
        dev_info.dev_info_argc = 1;
        dev_info.dev_info_argv = dev_info_argv;
        dev_info.flags = CUSE_UNRESTRICTED_IOCTL;

        int multithreaded;
        int res;

        printf("[info] initializing sev-guest device mock...\n");
        se = cuse_lowlevel_setup(argc, argv, &dev_info, &sev_guest_clops,
                                 &multithreaded, NULL);
        if (se == NULL) {
            printf("[error] cuse_lowlevel_setup failed\n");
            return 1;
        }

        printf("[info] sev-guest device mock running (multithreaded=%d)\n", multithreaded);

        if (multithreaded) {
            res = fuse_session_loop_mt(se);
        } else {
            res = fuse_session_loop(se);
        }
        if (res == -1) {
            return 1;
        }
        cuse_lowlevel_teardown(se);
        se = NULL;
    }
    return 0;
}

void stop_device() {
    if (device_is_running()) {
        printf("[info] stopping sev-guest device mock...\n");
        fuse_session_exit(se);
    }
}

int main(int argc, char **argv) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct sev_guest_param param = {0, 0, 0};
    char dev_name[18] = "DEVNAME=sev-guest";
    const char *dev_info_argv[] = {dev_name};
    struct cuse_info dev_info;
    int ret = 1;

    if (fuse_opt_parse(&args, &param, sev_guest_opts, sev_guest_process_arg)) {
        printf("failed to parse option\n");
        fuse_opt_free_args(&args);
        return ret;
    }

    get_report(&report);

    memset(&dev_info, 0x00, sizeof(dev_info));
    dev_info.dev_major = param.major;
    dev_info.dev_minor = param.minor;
    dev_info.dev_info_argc = 1;
    dev_info.dev_info_argv = dev_info_argv;
    dev_info.flags = CUSE_UNRESTRICTED_IOCTL;

    return cuse_lowlevel_main(args.argc, args.argv, &dev_info, &sev_guest_clops,
                              NULL);
}
