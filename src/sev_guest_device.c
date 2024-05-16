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
    if (flags & FUSE_IOCTL_COMPAT) {
        fuse_reply_err(req, ENOSYS);
        return;
    }

    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    pid_t pid = ctx->pid;
    off_t addr = (off_t)(uintptr_t)arg;

    struct snp_guest_request_ioctl ioctl_request;
    struct snp_report_req report_req;
    struct snp_report_resp report_resp;
    struct msg_report_resp report_resp_msg;
    struct snp_ext_report_req ext_report_req;
    char file[64];

    sprintf(file, "/proc/%ld/mem", (long)pid);
    int process_memfile_fd = open(file, O_RDWR);

    ptrace(PTRACE_SEIZE, pid, 0, 0);

    int ret =
        pread(process_memfile_fd, &ioctl_request, sizeof(ioctl_request), addr);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    ret = pread(process_memfile_fd, &report_resp, sizeof(report_resp),
                ioctl_request.resp_data);
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    switch (cmd) {
        case SNP_GET_REPORT:
            ret = pread(process_memfile_fd, &report_req, sizeof(report_req),
                        (ioctl_request).req_data);
            if (ret == -1) {
                exit(EXIT_FAILURE);
            }
            handle_get_report(process_memfile_fd, &report_req, &ioctl_request,
                              &report_resp_msg, &report_resp, &report);
            break;
        case SNP_GET_EXT_REPORT:
            ret = pread(process_memfile_fd, &ext_report_req,
                        sizeof(ext_report_req), (ioctl_request).req_data);
            if (ret == -1) {
                exit(EXIT_FAILURE);
            }
            report_req = (ext_report_req).data;
            handle_get_ext_report(process_memfile_fd, &report_req,
                                  &ioctl_request, &report_resp_msg,
                                  &ext_report_req, &report_resp, &report);
            break;
        default:
            close(process_memfile_fd);
            fuse_reply_err(req, EINVAL);
            return;
    }

    close(process_memfile_fd);

    fuse_reply_ioctl(req, 0, NULL, 0);

    ptrace(PTRACE_DETACH, pid, 0, 0);
    waitpid(pid, NULL, 0);
}

static const struct cuse_lowlevel_ops sev_guest_clops = {
    .open = sev_guest_open,
    .ioctl = sev_guest_ioctl,
};

int init_device() {
    int argc = 2;
    char *argv[] = {"sev-guest", "-f"};
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

    cuse_lowlevel_teardown(se);
    if (res == -1) {
        return 1;
    }

    return 0;
}

void stop_device() {
    fuse_session_exit(se);
}

int device_is_running() {
    return access("/dev/sev-guest", F_OK) == 0 && !fuse_session_exited(se);
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
