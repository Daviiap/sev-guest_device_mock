#ifndef __HANDLERS_H__
#define __HANDLERS_H__

#include "snp/attestation.h"
#include "snp/sev-guest.h"

void handle_get_ext_report(int process_memfile_fd,
                           struct snp_report_req *report_req,
                           struct snp_guest_request_ioctl *ioctl_request,
                           struct msg_report_resp *report_resp_msg,
                           struct snp_ext_report_req *ext_report_req,
                           struct snp_report_resp *report_resp,
                           struct attestation_report *report);

void handle_get_report(int process_memfile_fd,
                       struct snp_report_req *report_req,
                       struct snp_guest_request_ioctl *ioctl_request,
                       struct msg_report_resp *report_resp_msg,
                       struct snp_report_resp *report_resp,
                       struct attestation_report *report);

#endif
