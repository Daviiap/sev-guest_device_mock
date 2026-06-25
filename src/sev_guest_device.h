#ifndef __SEV_GUEST_DEVICE_H__
#define __SEV_GUEST_DEVICE_H__

int device_is_running();
int init_device();
void stop_device();
void override_measurement(const unsigned char* new_measurement);
void override_policy(unsigned long int new_policy);

#endif
