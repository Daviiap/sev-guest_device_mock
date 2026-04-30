#define FUSE_USE_VERSION 31

#include <errno.h>
#include <fcntl.h>
#include <fuse/cuse_lowlevel.h>
#include <fuse/fuse_opt.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "./sev_guest_ioctl.h"
#include "handlers.h"
#include "snp/attestation.h"
#include "snp/cert-table.h"
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

    if (flags & FUSE_IOCTL_COMPAT) {
        fuse_reply_err(req, ENOSYS);
        return;
    }

    if (in_bufsz == 0) {
        struct iovec in_iov = {arg, sizeof(struct snp_guest_request_ioctl)};
        fuse_reply_ioctl_retry(req, &in_iov, 1, NULL, 0);
        return;
    }

    if (in_bufsz == sizeof(struct snp_guest_request_ioctl)) {
        const struct snp_guest_request_ioctl *ioctl_req =
            (const struct snp_guest_request_ioctl *)in_buf;

        size_t req_data_size;
        switch (cmd) {
            case SNP_GET_REPORT:
                req_data_size = sizeof(struct snp_report_req);
                break;
            case SNP_GET_EXT_REPORT:
                req_data_size = sizeof(struct snp_ext_report_req);
                break;
            default:
                fuse_reply_err(req, EINVAL);
                return;
        }

        struct iovec in_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->req_data, req_data_size},
        };
        struct iovec out_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->resp_data,
             sizeof(struct snp_report_resp)},
        };
        fuse_reply_ioctl_retry(req, in_iov, 2, out_iov, 2);
        return;
    }

    const struct snp_guest_request_ioctl *ioctl_req =
        (const struct snp_guest_request_ioctl *)in_buf;
    const void *req_data = (const char *)in_buf + sizeof(*ioctl_req);

    struct {
        struct snp_guest_request_ioctl ioctl_out;
        struct snp_report_resp resp_out;
    } out;
    memset(&out, 0, sizeof(out));
    memcpy(&out.ioctl_out, ioctl_req, sizeof(*ioctl_req));
    out.ioctl_out.fw_err = 0;

    struct msg_report_resp report_resp_msg;
    memset(&report_resp_msg, 0, sizeof(report_resp_msg));

    switch (cmd) {
        case SNP_GET_REPORT: {
            struct snp_report_req report_req;
            memcpy(&report_req, req_data, sizeof(report_req));

            memcpy(report.report_data, report_req.user_data,
                   sizeof(report_req.user_data));
            report.vmpl = report_req.vmpl;

            sign_attestation_report(&report, report_req.key_sel);

            report_resp_msg.report_size = (int)sizeof(report);
            memcpy(&report_resp_msg.report, &report, sizeof(report));
            memcpy(out.resp_out.data, &report_resp_msg,
                   sizeof(report_resp_msg));
            break;
        }
        case SNP_GET_EXT_REPORT: {
            struct snp_ext_report_req ext_report_req;
            memcpy(&ext_report_req, req_data, sizeof(ext_report_req));
            struct snp_report_req report_req = ext_report_req.data;

            memcpy(report.report_data, report_req.user_data,
                   sizeof(report_req.user_data));
            report.vmpl = report_req.vmpl;

            sign_attestation_report(&report, report_req.key_sel);

            report_resp_msg.report_size = (int)sizeof(report);
            memcpy(&report_resp_msg.report, &report, sizeof(report));
            memcpy(out.resp_out.data, &report_resp_msg,
                   sizeof(report_resp_msg));
            break;
        }
        default:
            fuse_reply_err(req, EINVAL);
            return;
    }

    fuse_reply_ioctl(req, 0, &out, sizeof(out));
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

        se = cuse_lowlevel_setup(argc, argv, &dev_info, &sev_guest_clops,
                                 &multithreaded, NULL);
        if (se == NULL) {
            return 1;
        }

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
    if (device_is_running()) fuse_session_exit(se);
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
