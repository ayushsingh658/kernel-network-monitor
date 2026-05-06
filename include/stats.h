#ifndef STATS_H
#define STATS_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include "packet.h"

#define MAX_TOP_CONNECTIONS 256

struct traffic_stats {
    atomic64_t total_packets;
    atomic64_t total_bytes;
    atomic64_t tcp_packets;
    atomic64_t udp_packets;
    atomic64_t icmp_packets;
    atomic64_t other_packets;
    atomic64_t alerts_triggered;
    atomic64_t dropped_packets;
};

int stats_init(void);
void stats_exit(void);
void stats_reset(void);
void stats_update(struct packet_info *pkt);
void stats_inc_alerts(void);
void stats_inc_dropped(void);
void stats_get_global(struct traffic_stats *buf);
void stats_format_output(struct seq_file *m);

#endif