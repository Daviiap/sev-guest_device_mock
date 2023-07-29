#include <errno.h>
#include <fcntl.h>
#include <fuse/cuse_lowlevel.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "snp/attestation.h"
#include "snp/sev-guest.h"

char PRIVATE_VCEK_PATH[128] = "/etc/sev-guest/vcek/private.pem";
char PRIVATE_VLEK_PATH[128] = "/etc/sev-guest/vlek/private.pem";

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

void sign_attestation_report(struct attestation_report* report, __u32 key_sel) {
  unsigned char* data = (unsigned char*)report;
  size_t data_len = offsetof(struct attestation_report, signature);

  EC_KEY* eckey;
  switch (key_sel) {
    case 0:
      eckey = read_ecdsa_key_from_file(PRIVATE_VLEK_PATH);
      if (eckey == NULL) {
        eckey = read_ecdsa_key_from_file(PRIVATE_VCEK_PATH);
      }
      break;
    case 1:
      eckey = read_ecdsa_key_from_file(PRIVATE_VCEK_PATH);
      break;
    case 2:
      eckey = read_ecdsa_key_from_file(PRIVATE_VLEK_PATH);
      break;
  }

  if (eckey == NULL) {
    fprintf(stderr, "Error generating ECDSA key pair\n");
    return;
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "Error creating SHA-384 context\n");
    EC_KEY_free(eckey);
    return;
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) != 1) {
    fprintf(stderr, "Error initializing SHA-384 context\n");
    EVP_MD_CTX_free(mdctx);
    EC_KEY_free(eckey);
    return;
  }

  if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
    fprintf(stderr, "Error updating SHA-384 context\n");
    EVP_MD_CTX_free(mdctx);
    EC_KEY_free(eckey);
    return;
  }

  unsigned char hash[SHA384_DIGEST_LENGTH];
  unsigned int hash_len;
  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
    fprintf(stderr, "Error finalizing SHA-384 context\n");
    EVP_MD_CTX_free(mdctx);
    EC_KEY_free(eckey);
    return;
  }

  ECDSA_SIG* ecdsa_signature = ECDSA_do_sign(hash, hash_len, eckey);
  if (ecdsa_signature == NULL) {
    fprintf(stderr, "Error creating ECDSA signature\n");
    EVP_MD_CTX_free(mdctx);
    EC_KEY_free(eckey);
    return;
  }

  BIGNUM* r_bn;
  BIGNUM* s_bn;
  ECDSA_SIG_get0(ecdsa_signature, (const BIGNUM**)&r_bn, (const BIGNUM**)&s_bn);
  BN_bn2lebinpad(r_bn, report->signature.r, sizeof(report->signature.r));
  BN_bn2lebinpad(s_bn, report->signature.s, sizeof(report->signature.s));

  ECDSA_SIG_free(ecdsa_signature);
  EVP_MD_CTX_free(mdctx);
  EC_KEY_free(eckey);
}

/*
    Build an attestation report with mocked data
*/
void get_report(struct attestation_report* report, uint8 report_data[64],
                uint8 report_id[32], __u32 signing_key_sel) {
  uint8 measurement[] = {
      0x72, 0xD9, 0x9E, 0x55, 0x0E, 0x7C, 0xB1, 0x2A, 0xBA, 0xB9, 0xC9, 0x61,
      0xE4, 0x7F, 0x34, 0x3A, 0xCC, 0x8F, 0xF3, 0x0B, 0x6A, 0x62, 0xB4, 0x2B,
      0x5B, 0x59, 0x3E, 0x78, 0xDD, 0xBD, 0x54, 0xDF, 0x6B, 0x09, 0x0B, 0x2F,
      0x66, 0x29, 0x9A, 0x48, 0x0E, 0x52, 0x0A, 0xC9, 0xE2, 0x95, 0x5F, 0x70};

  uint8 chip_id[] = {0x20, 0x02, 0x8D, 0x46, 0x36, 0xC2, 0x68, 0xB3, 0xBD, 0x52,
                     0x5B, 0x42, 0x9D, 0x33, 0x3C, 0x28, 0x27, 0x3C, 0xFC, 0xB6,
                     0x38, 0x74, 0xF8, 0xCF, 0xF7, 0x8F, 0xA6, 0x13, 0x88, 0x70,
                     0x02, 0x99, 0x0E, 0xFE, 0xC7, 0x0C, 0x4C, 0x53, 0x8B, 0xAC,
                     0x5E, 0x08, 0x43, 0x71, 0xF3, 0xD7, 0x66, 0x59, 0x36, 0x0A,
                     0x8E, 0x51, 0x57, 0xD5, 0xE7, 0x58, 0x80, 0x57, 0xA7, 0x15,
                     0xA8, 0x27, 0x2D, 0xBA};

  /*  Set to 2h for SNP specification */
  report->version = 0x02;
  report->guest_svn = 0x00;
  report->policy = 0x30000;
  memset(&report->family_id, 0x00, sizeof(report->family_id));
  memset(&report->image_id, 0x00, sizeof(report->image_id));
  report->vmpl = 0x00;
  report->signature_algo = 0x01;
  report->platform_version.boot_loader = 0x03;
  report->platform_version.microcode = 0x73;
  memset(&report->platform_version.reserved, 0x00,
         sizeof(report->platform_version.reserved));
  report->platform_version.snp = 0x08;
  report->platform_version.tee = 0x00;
  report->platform_info = 0x03;
  report->flags = 0x00;
  report->reserved0 = 0x00;
  memcpy(report->measurement, &measurement, sizeof(measurement));
  memcpy(report->report_data, report_data, sizeof(report->report_data));
  memcpy(report->report_id, report_id, sizeof(report->report_id));
  memset(&report->host_data, 0x00, sizeof(report->host_data));
  memset(&report->id_key_digest, 0x00, sizeof(report->id_key_digest));
  memset(&report->author_key_digest, 0x00, sizeof(report->author_key_digest));
  memset(&report->report_id_ma, 0xFF, sizeof(report->report_id_ma));
  report->reported_tcb.boot_loader = 0x03;
  report->reported_tcb.microcode = 0x73;
  memset(&report->reported_tcb.reserved, 0x00,
         sizeof(report->reported_tcb.reserved));
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
  memset(&report->launch_tcb.reserved, 0x00,
         sizeof(report->launch_tcb.reserved));
  report->launch_tcb.snp = 0x08;
  report->launch_tcb.tee = 0x00;
  memset(&report->reserved4, 0x00, sizeof(report->reserved4));
  memset(&report->signature.reserved, 0x00, sizeof(report->signature.reserved));

  sign_attestation_report(report, signing_key_sel);
}
