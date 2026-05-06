#include "detection.h"
#include "packet.h"

#define IP_STATS_TABLE_SIZE 16384
#define CONNECTION_TABLE_SIZE 16384

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/seq_file.h>
#include <linux/jhash.h>

static atomic64_t total_packets;
static atomic64_t total_bytes;
static atomic64_t tcp_packets;
static atomic64_t udp_packets;
static atomic64_t icmp_packets;
static atomic64_t other_packets;
static atomic64_t alerts_triggered;
static atomic64_t dropped_packets;

struct ip_stats_entry {
    __be32 ip;
    atomic64_t packet_count;
    atomic64_t byte_count;
    atomic64_t alert_count;
    __u64 last_seen;
    struct ip_stats_entry *next;
};

struct connection_entry {
    __be32 src_ip;
    __be32 dst_ip;
    atomic64_t packet_count;
    atomic64_t byte_count;
    atomic64_t alert_count;
    __u64 first_seen;
    __u64 last_seen;
    struct connection_entry *next;
};

static struct ip_stats_entry *ip_stats_table[IP_STATS_TABLE_SIZE];
static struct connection_entry *conn_stats_table[CONNECTION_TABLE_SIZE];
static int ip_stats_count = 0;
static int conn_stats_count = 0;
static DEFINE_SPINLOCK(ip_stats_lock);
static DEFINE_SPINLOCK(conn_stats_lock);

static inline int get_ip_bucket(__be32 ip)
{
    return jhash_1word((__u32)ip, 0) % IP_STATS_TABLE_SIZE;
}

static inline int get_conn_bucket(__be32 src_ip, __be32 dst_ip)
{
    return jhash_1word(((__u32)src_ip << 16) | (__u32)dst_ip, 0) % CONNECTION_TABLE_SIZE;
}

int stats_init(void)
{
    int i;

    for (i = 0; i < IP_STATS_TABLE_SIZE; i++)
        ip_stats_table[i] = NULL;

    for (i = 0; i < CONNECTION_TABLE_SIZE; i++)
        conn_stats_table[i] = NULL;

    atomic64_set(&total_packets, 0);
    atomic64_set(&total_bytes, 0);
    atomic64_set(&tcp_packets, 0);
    atomic64_set(&udp_packets, 0);
    atomic64_set(&icmp_packets, 0);
    atomic64_set(&other_packets, 0);
    atomic64_set(&alerts_triggered, 0);
    atomic64_set(&dropped_packets, 0);

    pr_info("net_traffic_monitor: Statistics subsystem initialized\n");
    return 0;
}

void stats_exit(void)
{
    struct ip_stats_entry *entry, *next;
    struct connection_entry *conn, *cnext;
    int i;

    for (i = 0; i < IP_STATS_TABLE_SIZE; i++) {
        entry = ip_stats_table[i];
        while (entry) {
            next = entry->next;
            kfree(entry);
            entry = next;
        }
    }

    for (i = 0; i < CONNECTION_TABLE_SIZE; i++) {
        conn = conn_stats_table[i];
        while (conn) {
            cnext = conn->next;
            kfree(conn);
            conn = cnext;
        }
    }

    pr_info("net_traffic_monitor: Statistics subsystem exited\n");
}

void stats_reset(void)
{
    struct ip_stats_entry *entry, *next;
    struct connection_entry *conn, *cnext;
    int i;

    spin_lock(&ip_stats_lock);
    for (i = 0; i < IP_STATS_TABLE_SIZE; i++) {
        entry = ip_stats_table[i];
        while (entry) {
            next = entry->next;
            kfree(entry);
            entry = next;
        }
        ip_stats_table[i] = NULL;
    }
    ip_stats_count = 0;
    spin_unlock(&ip_stats_lock);

    spin_lock(&conn_stats_lock);
    for (i = 0; i < CONNECTION_TABLE_SIZE; i++) {
        conn = conn_stats_table[i];
        while (conn) {
            cnext = conn->next;
            kfree(conn);
            conn = cnext;
        }
        conn_stats_table[i] = NULL;
    }
    conn_stats_count = 0;
    spin_unlock(&conn_stats_lock);

    atomic64_set(&total_packets, 0);
    atomic64_set(&total_bytes, 0);
    atomic64_set(&tcp_packets, 0);
    atomic64_set(&udp_packets, 0);
    atomic64_set(&icmp_packets, 0);
    atomic64_set(&other_packets, 0);
    atomic64_set(&alerts_triggered, 0);
    atomic64_set(&dropped_packets, 0);
}

static struct ip_stats_entry *get_or_create_ip_stats(__be32 ip)
{
    struct ip_stats_entry *entry;
    int bkt;

    bkt = get_ip_bucket(ip);

    spin_lock(&ip_stats_lock);
    entry = ip_stats_table[bkt];

    while (entry) {
        if (entry->ip == ip) {
            entry->last_seen = ktime_get_real_ns();
            spin_unlock(&ip_stats_lock);
            return entry;
        }
        entry = entry->next;
    }
    spin_unlock(&ip_stats_lock);

    if (ip_stats_count > 100000)
        return NULL;

    entry = kzalloc(sizeof(struct ip_stats_entry), GFP_ATOMIC);
    if (!entry)
        return NULL;

    entry->ip = ip;
    atomic64_set(&entry->packet_count, 0);
    atomic64_set(&entry->byte_count, 0);
    atomic64_set(&entry->alert_count, 0);
    entry->last_seen = ktime_get_real_ns();

    spin_lock(&ip_stats_lock);
    entry->next = ip_stats_table[bkt];
    ip_stats_table[bkt] = entry;
    ip_stats_count++;
    spin_unlock(&ip_stats_lock);

    return entry;
}

void stats_update(struct packet_info *pkt)
{
    struct ip_stats_entry *ip_entry;
    struct connection_entry *conn_entry;
    int bkt;

    if (!pkt)
        return;

    atomic64_inc(&total_packets);
    atomic64_add((s64)pkt->pkt_len, &total_bytes);

    switch (pkt->protocol) {
    case PROTOCOL_TCP:
        atomic64_inc(&tcp_packets);
        break;
    case PROTOCOL_UDP:
        atomic64_inc(&udp_packets);
        break;
    case PROTOCOL_ICMP:
        atomic64_inc(&icmp_packets);
        break;
    default:
        atomic64_inc(&other_packets);
        break;
    }

    ip_entry = get_or_create_ip_stats(pkt->src_ip);
    if (ip_entry) {
        atomic64_inc(&ip_entry->packet_count);
        atomic64_add((s64)pkt->pkt_len, &ip_entry->byte_count);
    }

    bkt = get_conn_bucket(pkt->src_ip, pkt->dst_ip);

    spin_lock(&conn_stats_lock);
    conn_entry = conn_stats_table[bkt];

    while (conn_entry) {
        if (conn_entry->src_ip == pkt->src_ip && conn_entry->dst_ip == pkt->dst_ip) {
            atomic64_inc(&conn_entry->packet_count);
            atomic64_add(pkt->pkt_len, &conn_entry->byte_count);
            conn_entry->last_seen = ktime_get_real_ns();
            spin_unlock(&conn_stats_lock);
            return;
        }
        conn_entry = conn_entry->next;
    }
    spin_unlock(&conn_stats_lock);

    if (conn_stats_count > 100000)
        return;

    conn_entry = kzalloc(sizeof(struct connection_entry), GFP_ATOMIC);
    if (!conn_entry)
        return;

    conn_entry->src_ip = pkt->src_ip;
    conn_entry->dst_ip = pkt->dst_ip;
    atomic64_set(&conn_entry->packet_count, 1);
    atomic64_set(&conn_entry->byte_count, pkt->pkt_len);
    atomic64_set(&conn_entry->alert_count, 0);
    conn_entry->first_seen = ktime_get_real_ns();
    conn_entry->last_seen = conn_entry->first_seen;

    spin_lock(&conn_stats_lock);
    conn_entry->next = conn_stats_table[bkt];
    conn_stats_table[bkt] = conn_entry;
    conn_stats_count++;
    spin_unlock(&conn_stats_lock);
}

void stats_inc_alerts(void)
{
    atomic64_inc(&alerts_triggered);
}

void stats_inc_dropped(void)
{
    atomic64_inc(&dropped_packets);
}

static char *format_ip(__be32 addr)
{
    static char buffer[16];
    unsigned char *p = (unsigned char *)&addr;

    scnprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
             p[0], p[1], p[2], p[3]);
    return buffer;
}

void stats_format_output(struct seq_file *m)
{
    struct ip_stats_entry *entry;
    int i, count = 0;

    seq_printf(m, "=== Global Traffic Statistics ===\n");
    seq_printf(m, "Total Packets: %lld\n", (s64)atomic64_read(&total_packets));
    seq_printf(m, "Total Bytes: %lld\n", (s64)atomic64_read(&total_bytes));
    seq_printf(m, "TCP Packets: %lld\n", (s64)atomic64_read(&tcp_packets));
    seq_printf(m, "UDP Packets: %lld\n", (s64)atomic64_read(&udp_packets));
    seq_printf(m, "ICMP Packets: %lld\n", (s64)atomic64_read(&icmp_packets));
    seq_printf(m, "Other Packets: %lld\n", (s64)atomic64_read(&other_packets));
    seq_printf(m, "Alerts Triggered: %lld\n", (s64)atomic64_read(&alerts_triggered));
    seq_printf(m, "Dropped Packets: %lld\n\n", (s64)atomic64_read(&dropped_packets));

    seq_printf(m, "=== Top Source IPs ===\n");
    seq_printf(m, "%-15s %12s %12s %8s\n", "IP", "Packets", "Bytes", "Alerts");
    seq_printf(m, "===========================================\n");

    spin_lock(&ip_stats_lock);
    for (i = 0; i < IP_STATS_TABLE_SIZE && count < 50; i++) {
        entry = ip_stats_table[i];
        while (entry && count < 50) {
            seq_printf(m, "%-15s %12lld %12lld %8lld\n",
                       format_ip(entry->ip),
                       (s64)atomic64_read(&entry->packet_count),
                       (s64)atomic64_read(&entry->byte_count),
                       (s64)atomic64_read(&entry->alert_count));
            entry = entry->next;
            count++;
        }
    }
    spin_unlock(&ip_stats_lock);
}