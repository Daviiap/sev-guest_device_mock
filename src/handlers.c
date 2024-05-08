#include "handlers.h"

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
#include "snp/attestation.h"
#include "snp/cert-table.h"
#include "snp/sev-guest.h"

char PUBLIC_VCEK_PATH[128] = "/etc/sev-guest/vcek/public.pem";
char PUBLIC_VLEK_PATH[128] = "/etc/sev-guest/vlek/public.pem";

void handle_get_report(int process_memfile_fd,
                       struct snp_report_req *report_req,
                       struct snp_guest_request_ioctl *ioctl_request,
                       struct msg_report_resp *report_resp_msg,
                       struct snp_report_resp *report_resp,
                       struct attestation_report *report) {
    memcpy(report_resp_msg, report_resp, sizeof(*report_resp));

    memcpy(report->report_data, report_req->user_data,
           sizeof(report_req->user_data));
    report->vmpl = report_req->vmpl;

    sign_attestation_report(report, report_req->key_sel);

    memcpy(&report_resp_msg->report, report, sizeof(*report));
    report_resp_msg->report_size = (int)sizeof(*report);

    int ret = pwrite(process_memfile_fd, report_resp_msg,
                     sizeof(*report_resp_msg), ioctl_request->resp_data);

    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
}

void handle_get_ext_report(int process_memfile_fd,
                           struct snp_report_req *report_req,
                           struct snp_guest_request_ioctl *ioctl_request,
                           struct msg_report_resp *report_resp_msg,
                           struct snp_ext_report_req *ext_report_req,
                           struct snp_report_resp *report_resp,
                           struct attestation_report *report) {
    int cert_fd;
    switch (report_req->key_sel) {
        case 0:
            cert_fd = open(PUBLIC_VLEK_PATH, O_RDWR);
            if (cert_fd == -1) {
                cert_fd = open(PUBLIC_VCEK_PATH, O_RDWR);
            }
            break;
        case 1:
            cert_fd = open(PUBLIC_VCEK_PATH, O_RDWR);
            break;
        case 2:
            cert_fd = open(PUBLIC_VLEK_PATH, O_RDWR);
            break;
    }
    struct stat stat_buf;
    if (fstat(cert_fd, &stat_buf) == -1) {
        perror("fstat");
    }

    uint32 certs_len = (uint32)stat_buf.st_size;
    uint8 certs[(int)certs_len];

    int ret = read(cert_fd, certs, sizeof(certs));
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    struct cert_table table;

    cert_table_alloc(&table, 1);
    cert_table_add_entry(&table, vcek_guid, certs_len);

    size_t table_size = cert_table_get_size(&table);
    size_t total_size = table_size + certs_len;
    uint8 *buffer = calloc(sizeof(uint8), total_size);
    memset(buffer, 0x00, total_size);
    memcpy(buffer, &table.entry[0], sizeof(struct cert_table_entry));

    cert_table_append_cert(&table, buffer, total_size, vcek_guid, certs,
                           certs_len);

    int page_size = sysconf(_SC_PAGESIZE);
    ext_report_req->certs_len = page_size;

    ret = pwrite(process_memfile_fd, ext_report_req, sizeof(*ext_report_req),
                 ioctl_request->req_data);

    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /*
        Do not return error on this pwrite call due to the extended report
       flow. The initial request is made solely to determine the size of the
       certificates. Consequently, ext_report_req->certs_address will point to
       an invalid memory address, resulting in an error on the pwrite call.
    */
    ret = pwrite(process_memfile_fd, buffer, total_size,
                 ext_report_req->certs_address);

    if (ret == -1) {
        printf("[warning] certs write error.\n");
    }

    cert_table_free(&table);
    free(buffer);

    handle_get_report(process_memfile_fd, report_req, ioctl_request,
                      report_resp_msg, report_resp, report);
}
