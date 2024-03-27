#ifndef ATTESTATION_H
#define ATTESTATION_H

#define SIG_ALGO_ECDSA_P384_SHA384 0x1

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;
typedef unsigned long int uint64;

union tcb_version
{
    struct
    {
        uint8 boot_loader;
        uint8 tee;
        uint8 reserved[4];
        uint8 snp;
        uint8 microcode;
    };
    uint64 raw;
};

struct signature
{
    uint8 r[72];
    uint8 s[72];
    uint8 reserved[512 - 144];
};

struct attestation_report
{
    uint32 version;
    uint32 guest_svn;
    uint64 policy;
    uint8 family_id[16];
    uint8 image_id[16];
    uint32 vmpl;
    uint32 signature_algo;
    union tcb_version platform_version;
    uint64 platform_info;
    uint32 flags;
    uint32 reserved0;
    uint8 report_data[64];
    uint8 measurement[48];
    uint8 host_data[32];
    uint8 id_key_digest[48];
    uint8 author_key_digest[48];
    uint8 report_id[32];
    uint8 report_id_ma[32];
    union tcb_version reported_tcb;
    uint8 reserved1[24];
    uint8 chip_id[64];
    union tcb_version commited_tcb;
    uint8 current_build;
    uint8 current_minor;
    uint8 current_major;
    uint8 reserved2;
    uint8 commited_build;
    uint8 commited_minor;
    uint8 commited_major;
    uint8 reserved3;
    union tcb_version launch_tcb;
    uint8 reserved4[168];
    struct signature signature;
};

struct msg_report_resp {
    uint32 status;
    uint32 report_size;
    uint8 reserved[0x20 - 0x8];
    struct attestation_report report;
};

#endif