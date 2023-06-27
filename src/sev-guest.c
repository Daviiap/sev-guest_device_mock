/** @file
 *
 * This example demonstrates how to implement a character device in
 * userspace ("CUSE"). This is only allowed for root. The character
 * device should appear in /dev under the specified name. It can be
 * tested with the cuse_client.c program.
 *
 * Mount the file system with:
 *
 *     sev-guest -f --name=sev-guest
 *
 * You should now have a new /dev/sev-guest character device. To "unmount" it,
 * kill the "cuse" process.
 *
 * To compile this example, run
 *
 *     gcc -Wall sev-guest.c `pkg-config fuse3 --cflags --libs` -o sev-guest
 *
 * ## Source code ##
 * \include cuse.c
 */

#define FUSE_USE_VERSION 31

#include <fuse/cuse_lowlevel.h>
#include <fuse/fuse_opt.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "snp/attestation.h"
#include "snp/sev-guest.h"

static const char *usage =
	"usage: cusexmp [options]\n"
	"\n"
	"options:\n"
	"    --help|-h             print this help message\n"
	"    --maj=MAJ|-M MAJ      device major number\n"
	"    --min=MIN|-m MIN      device minor number\n"
	"    --name=NAME|-n NAME   device name (mandatory)\n"
	"    -d   -o debug         enable debug output (implies -f)\n"
	"    -f                    foreground operation\n"
	"    -s                    disable multi-threaded operation\n"
	"\n";

#define SEV_GUEST_OPT(t, p){t, offsetof(struct sev_guest_param, p), 1}

static void sev_guest_open(fuse_req_t req, struct fuse_file_info *fi)
{
	fuse_reply_open(req, fi);
}

void get_report(struct attestation_report *report)
{
    uint8 measurement[] = {0x72, 0xD9, 0x9E, 0x55, 0x0E, 0x7C, 0xB1, 0x2A,
                           0xBA, 0xB9, 0xC9, 0x61, 0xE4, 0x7F, 0x34, 0x3A,
                           0xCC, 0x8F, 0xF3, 0x0B, 0x6A, 0x62, 0xB4, 0x2B,
                           0x5B, 0x59, 0x3E, 0x78, 0xDD, 0xBD, 0x54, 0xDF,
                           0x6B, 0x09, 0x0B, 0x2F, 0x66, 0x29, 0x9A, 0x48,
                           0x0E, 0x52, 0x0A, 0xC9, 0xE2, 0x95, 0x5F, 0x70};

    uint8 report_id[] = {0x8A, 0xB1, 0xAA, 0xF1, 0x82, 0x65, 0x8E, 0x41,
                         0x62, 0x5E, 0x5E, 0x4F, 0x02, 0x30, 0x1B, 0xD4,
                         0x88, 0x8E, 0x66, 0xB8, 0xD0, 0xF3, 0x0C, 0xCE,
                         0x74, 0xD8, 0x05, 0xD9, 0xB0, 0xDA, 0x0D, 0x7B};

    uint8 chip_id[] = {0x20, 0x02, 0x8D, 0x46, 0x36, 0xC2, 0x68, 0xB3,
                       0xBD, 0x52, 0x5B, 0x42, 0x9D, 0x33, 0x3C, 0x28,
                       0x27, 0x3C, 0xFC, 0xB6, 0x38, 0x74, 0xF8, 0xCF,
                       0xF7, 0x8F, 0xA6, 0x13, 0x88, 0x70, 0x02, 0x99,
                       0x0E, 0xFE, 0xC7, 0x0C, 0x4C, 0x53, 0x8B, 0xAC,
                       0x5E, 0x08, 0x43, 0x71, 0xF3, 0xD7, 0x66, 0x59,
                       0x36, 0x0A, 0x8E, 0x51, 0x57, 0xD5, 0xE7, 0x58,
                       0x80, 0x57, 0xA7, 0x15, 0xA8, 0x27, 0x2D, 0xBA};

    uint8 signature_r[] = {0xF8, 0x7D, 0xEB, 0x17, 0xD8, 0x0E, 0xFA, 0x9B,
                           0x28, 0xEB, 0x9F, 0x1C, 0x52, 0x3E, 0xC6, 0xF5,
                           0x3C, 0x86, 0x99, 0xF6, 0x06, 0x4A, 0x4C, 0x43,
                           0x3A, 0xCB, 0x36, 0xA8, 0x0C, 0x67, 0xFD, 0x5E,
                           0x1B, 0x1E, 0x50, 0xA4, 0x6B, 0x03, 0x87, 0x49,
                           0x03, 0xC1, 0x0E, 0xBA, 0x20, 0x27, 0x5D, 0xB9,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8 signature_s[] = {0xA7, 0xCC, 0xD6, 0x23, 0x83, 0xF5, 0xC2, 0x37,
                           0x06, 0x8F, 0xA4, 0x3E, 0xBA, 0xA2, 0x10, 0x3F,
                           0x46, 0x84, 0x4C, 0xFC, 0x80, 0x38, 0x93, 0x1D,
                           0x0E, 0x6A, 0xEF, 0x38, 0x1F, 0x10, 0x36, 0x4C,
                           0x25, 0xC1, 0xD0, 0x77, 0xA3, 0x65, 0x8C, 0x7E,
                           0xBE, 0x51, 0x4A, 0x7D, 0x31, 0x5B, 0x3F, 0x74,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    report->version = 0x02;
    report->guest_svn = 0x00;
    report->policy = 0x30000;
    memset(&report->family_id, 0x00, sizeof(report->family_id));
    memset(&report->image_id, 0x00, sizeof(report->image_id));
    report->vmpl = 0x00;
    report->signature_algo = 0x01;
    report->platform_version.boot_loader = 0x03;
    report->platform_version.microcode = 0x73;
    memset(&report->platform_version.reserved, 0x00, sizeof(report->platform_version.reserved));
    report->platform_version.snp = 0x08;
    report->platform_version.tee = 0x00;
    report->platform_info = 0x03;
    report->flags = 0x00;
    report->reserved0 = 0x00;
    memset(&report->report_data, 0x00, sizeof(report->report_data));
    memcpy(report->measurement, &measurement, sizeof(measurement));
    memset(&report->host_data, 0x00, sizeof(report->host_data));
    memset(&report->id_key_digest, 0x00, sizeof(report->id_key_digest));
    memset(&report->author_key_digest, 0x00, sizeof(report->author_key_digest));
    memcpy(report->report_id, &report_id, sizeof(report_id));
    memset(&report->report_id_ma, 0xFF, sizeof(report->report_id_ma));
    report->reported_tcb.boot_loader = 0x03;
    report->reported_tcb.microcode = 0x73;
    memset(&report->reported_tcb.reserved, 0x00, sizeof(report->reported_tcb.reserved));
    report->reported_tcb.snp = 0x08;
    report->reported_tcb.tee = 0x00;
    memset(&report->reserved1, 0x00, sizeof(report->reserved1));
    memcpy(report->chip_id, &chip_id, sizeof(chip_id));
    report->current_build = 0x04;
    report->current_minor = 0x34;
    report->current_major = 0x01;
    report->reserved2 = 0x00;
    report->commited_build = 0x04;
    report->commited_minor = 0x34;
    report->commited_major = 0x01;
    report->reserved3 = 0x00;
    report->launch_tcb.boot_loader = 0x03;
    report->launch_tcb.microcode = 0x73;
    memset(&report->launch_tcb.reserved, 0x00, sizeof(report->launch_tcb.reserved));
    report->launch_tcb.snp = 0x08;
    report->launch_tcb.tee = 0x00;
    memset(&report->reserved4, 0x00, sizeof(report->reserved4));
    memcpy(report->signature.r, &signature_r, sizeof(signature_r));
    memcpy(report->signature.s, &signature_s, sizeof(signature_s));
    memset(&report->signature.reserved, 0x00, sizeof(report->signature.reserved));
}

static void sev_guest_ioctl(fuse_req_t req, int cmd, void *arg, struct fuse_file_info *fi, unsigned flags, const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	pid_t pid = ctx->pid;
	off_t addr = (off_t)(uintptr_t)arg;

	struct snp_guest_request_ioctl ioctl_request;
	memset(&ioctl_request, 0x00, sizeof(ioctl_request));

	struct snp_report_req report_req;
	memset(&report_req, 0x00, sizeof(report_req));

	struct snp_report_resp report_resp;
	memset(&report_resp, 0x00, sizeof(report_resp));

	struct msg_report_resp report_resp_msg;
	memset(&report_resp_msg, 0x00, sizeof(report_resp_msg));

	struct attestation_report report;
	memset(&report, 0x00, sizeof(report));

	(void)fi;

	if (flags & FUSE_IOCTL_COMPAT)
	{
		fuse_reply_err(req, ENOSYS);
		return;
	}

	char file[64];

	switch (cmd)
	{
	case SNP_GET_REPORT:
		sprintf(file, "/proc/%ld/mem", (long)pid);

		int fd = open(file, O_RDWR);

		ptrace(PTRACE_SEIZE, pid, 0, 0);

		pread(fd, &ioctl_request, sizeof(ioctl_request), addr);
		pread(fd, &report_req, sizeof(report_req), ioctl_request.req_data);
		pread(fd, &report_resp, sizeof(report_resp), ioctl_request.resp_data);

		memcpy(&report_resp_msg, &report_resp, sizeof(report_resp));

		get_report(&report);

		report_resp_msg.report_size = 1184;
		report_resp_msg.report = report;

		pwrite(fd, &report_resp_msg, sizeof(report_resp_msg), ioctl_request.resp_data);

		close(fd);

		fuse_reply_ioctl(req, 0, NULL, 0);

		ptrace(PTRACE_DETACH, pid, 0, 0);
		waitpid(pid, NULL, 0);
		break;
	default:
		fuse_reply_err(req, EINVAL);
	}
}

struct sev_guest_param
{
	unsigned major;
	unsigned minor;
	char *dev_name;
	int is_help;
};

static const struct fuse_opt sev_guest_opts[] = {
	SEV_GUEST_OPT("-M %u", major),
	SEV_GUEST_OPT("--maj=%u", major),
	SEV_GUEST_OPT("-m %u", minor),
	SEV_GUEST_OPT("--min=%u", minor),
	SEV_GUEST_OPT("-n %s", dev_name),
	SEV_GUEST_OPT("--name=%s", dev_name),
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	FUSE_OPT_END};

static int sev_guest_process_arg(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	struct sev_guest_param *param = data;

	(void)outargs;
	(void)arg;

	switch (key)
	{
	case 0:
		param->is_help = 1;
		fprintf(stderr, "%s", usage);
		return fuse_opt_add_arg(outargs, "-ho");
	default:
		return 1;
	}
}

static const struct cuse_lowlevel_ops sev_guest_clop = {
	.open = sev_guest_open,
	.ioctl = sev_guest_ioctl,
};

int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct sev_guest_param param = {0, 0, NULL, 0};
	char dev_name[128] = "DEVNAME=";
	const char *dev_info_argv[] = {dev_name};
	struct cuse_info ci;
	int ret = 1;

	if (fuse_opt_parse(&args, &param, sev_guest_opts, sev_guest_process_arg))
	{
		printf("failed to parse option\n");
		free(param.dev_name);
		goto out;
	}

	if (!param.is_help)
	{
		if (!param.dev_name)
		{
			fprintf(stderr, "Error: device name missing\n");
			goto out;
		}
		strncat(dev_name, param.dev_name, sizeof(dev_name) - sizeof("DEVNAME="));
		free(param.dev_name);
	}

	memset(&ci, 0, sizeof(ci));
	ci.dev_major = param.major;
	ci.dev_minor = param.minor;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = dev_info_argv;
	ci.flags = CUSE_UNRESTRICTED_IOCTL;

	ret = cuse_lowlevel_main(args.argc, args.argv, &ci, &sev_guest_clop, NULL);

out:
	fuse_opt_free_args(&args);
	return ret;
}
