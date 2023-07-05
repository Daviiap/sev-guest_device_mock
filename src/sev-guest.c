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
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include "snp/attestation.h"
#include "snp/sev-guest.h"
#include "./sev_guest_ioctl.h"

static const char *usage =
	"usage: cusexmp [options]\n"
	"\n"
	"options:\n"
	"    --help|-h             print this help message\n"
	"    --maj=MAJ|-M MAJ      device major number\n"
	"    --min=MIN|-m MIN      device minor number\n"
	"    -d   -o debug         enable debug output (implies -f)\n"
	"    -f                    foreground operation\n"
	"    -s                    disable multi-threaded operation\n"
	"\n";

#define SEV_GUEST_OPT(t, p) {t, offsetof(struct sev_guest_param, p), 1}

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
	FUSE_OPT_END
};

static int sev_guest_process_arg(void *data, const char *arg, int key, struct fuse_args *outargs) {
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

static const struct cuse_lowlevel_ops sev_guest_clops = {
	.open = sev_guest_open,
	.ioctl = sev_guest_ioctl,
};

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

	memset(&dev_info, 0, sizeof(dev_info));
	dev_info.dev_major = param.major;
	dev_info.dev_minor = param.minor;
	dev_info.dev_info_argc = 1;
	dev_info.dev_info_argv = dev_info_argv;
	dev_info.flags = CUSE_UNRESTRICTED_IOCTL;

	return cuse_lowlevel_main(args.argc, args.argv, &dev_info, &sev_guest_clops, NULL);
}
