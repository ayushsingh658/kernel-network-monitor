#ifndef DETECTION_H
#define DETECTION_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include "packet.h"

#define MAX_SIGNATURES 64
#define MAX_PORTS_PER_SOURCE 1024

enum alert_severity {
    ALERT_INFO = 0,
    ALERT_WARNING = 1,
    ALERT_CRITICAL = 2,
};

enum alert_type {
    ALERT_NONE = 0,
    ALERT_PORT_SCAN = 1,
    ALERT_BURST_DETECTION = 2,
    ALERT_SIGNATURE_MATCH = 3,
};

struct detection_config {
    __u32 port_scan_threshold;
    __u32 port_scan_window_ms;
    __u32 burst_threshold;
    __u32 burst_window_ms;
    bool port_scan_enabled;
    bool burst_detection_enabled;
    bool signature_matching_enabled;
    spinlock_t lock;
};

struct portScanEntry {
    __be32 src_ip;
    __be16 ports[MAX_PORTS_PER_SOURCE];
    __u16 port_count;
    __u64 first_seen;
    __u64 last_update;
    struct hlist_node node;
};

struct burstEntry {
    __be32 src_ip;
    __u64 packet_count;
    __u64 window_start;
    __u64 last_packet;
    spinlock_t lock;
    struct hlist_node node;
};

struct alert {
    __u64 id;
    __u64 timestamp;
    __be32 src_ip;
    __be32 dst_ip;
    enum alert_type type;
    enum alert_severity severity;
    char message[256];
    struct alert *next;
};

struct signature {
    __u32 id;
    char name[64];
    __u8 protocol;
    __be16 src_port_min;
    __be16 src_port_max;
    __be16 dst_port_min;
    __be16 dst_port_max;
    __u8 tcp_flags_mask;
    __u8 tcp_flags_value;
    bool enabled;
};

int detection_init(void);
void detection_exit(void);
void detection_reset(void);
int detection_check_packet(struct packet_info *pkt);
struct alert *detection_get_next_alert(void);
void detection_config_set(struct detection_config *cfg);
void detection_config_get(struct detection_config *cfg);

#endif