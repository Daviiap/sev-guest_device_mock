#include <fuse/cuse_lowlevel.h>
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
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include "snp/attestation.h"
#include "snp/sev-guest.h"

EC_KEY* read_ecdsa_key_from_file(const char* key_file) {
    FILE* key_fp = fopen(key_file, "r");
    if (key_fp == NULL) {
        fprintf(stderr, "Error opening key file\n");
        return NULL;
    }

    EC_KEY* eckey = PEM_read_ECPrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (eckey == NULL) {
        fprintf(stderr, "Error reading ECDSA key from file\n");
        return NULL;
    }

    return eckey;
}

void sign_attestation_report(struct attestation_report* report) {
    // Convert attestation report (without the signature) to a byte array
    unsigned char* data = (unsigned char*)report;
    size_t data_len = offsetof(struct attestation_report, signature);

    // Create an EC_KEY object for ECDSA
    EC_KEY* eckey = read_ecdsa_key_from_file("/etc/sev-guest/vcek/private.pem");
    if (eckey == NULL) {
        fprintf(stderr, "Error generating ECDSA key pair\n");
        return;
    }
    
    // Create a SHA-384 context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Error creating SHA-384 context\n");
        EC_KEY_free(eckey);
        return;
    }

    // Initialize the SHA-384 context
    if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) != 1) {
        fprintf(stderr, "Error initializing SHA-384 context\n");
        EVP_MD_CTX_free(mdctx);
        EC_KEY_free(eckey);
        return;
    }

    // Update the SHA-384 context with the attestation report data
    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        fprintf(stderr, "Error updating SHA-384 context\n");
        EVP_MD_CTX_free(mdctx);
        EC_KEY_free(eckey);
        return;
    }

    // Get the SHA-384 hash value
    unsigned char hash[SHA384_DIGEST_LENGTH];
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "Error finalizing SHA-384 context\n");
        EVP_MD_CTX_free(mdctx);
        EC_KEY_free(eckey);
        return;
    }

    // Create an ECDSA signature
    ECDSA_SIG* ecdsa_signature = ECDSA_do_sign(hash, hash_len, eckey);
    if (ecdsa_signature == NULL) {
        fprintf(stderr, "Error creating ECDSA signature\n");
        EVP_MD_CTX_free(mdctx);
        EC_KEY_free(eckey);
        return;
    }

    // Convert the r and s values to byte arrays and save them in the signature structure
    BIGNUM* r_bn;
    BIGNUM* s_bn;
    ECDSA_SIG_get0(ecdsa_signature, (const BIGNUM**)&r_bn, (const BIGNUM**)&s_bn);
    BN_bn2lebinpad(r_bn, report->signature.r, sizeof(report->signature.r));
    BN_bn2lebinpad(s_bn, report->signature.s, sizeof(report->signature.s));

    // Clean up
    ECDSA_SIG_free(ecdsa_signature);
    EVP_MD_CTX_free(mdctx);
    EC_KEY_free(eckey);
}

/*
    Build an attestation report with mocked data
*/
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

void sev_guest_ioctl(fuse_req_t req, int cmd, void *arg, struct fuse_file_info *fi, unsigned flags, const void *in_buf, size_t in_bufsz, size_t out_bufsz)
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

	if (flags & FUSE_IOCTL_COMPAT) {
		fuse_reply_err(req, ENOSYS);
		return;
	}

	char file[64];

	switch (cmd) {
	    case SNP_GET_REPORT:
	    	sprintf(file, "/proc/%ld/mem", (long)pid);

	    	int fd = open(file, O_RDWR);

	    	ptrace(PTRACE_SEIZE, pid, 0, 0);

	    	pread(fd, &ioctl_request, sizeof(ioctl_request), addr);
	    	pread(fd, &report_req, sizeof(report_req), ioctl_request.req_data);
	    	pread(fd, &report_resp, sizeof(report_resp), ioctl_request.resp_data);

	    	memcpy(&report_resp_msg, &report_resp, sizeof(report_resp));

	    	get_report(&report);

	    	sign_attestation_report(&report);

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
