#include "net_traffic_monitor.h"
#include "packet.h"
#include "detection.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/jhash.h>
#include <linux/string.h>

#define PORT_SCAN_TABLE_SIZE 4096
#define BURST_TABLE_SIZE 4096

static DEFINE_SPINLOCK(port_scan_lock);
static DEFINE_SPINLOCK(burst_lock);

static struct detection_config default_config;
static spinlock_t alert_lock;

static struct alert alert_queue[MAX_ALERT_QUEUE_SIZE];
static __u64 alert_id_counter = 0;
static __u32 alert_read_index = 0;
static __u32 alert_write_index = 0;

static spinlock_t signature_lock;
static struct signature signatures[MAX_SIGNATURES];
static __u32 signature_count = 0;

struct port_scan_entry {
    __be32 src_ip;
    __be16 ports[MAX_PORTS_PER_SOURCE];
    __u16 port_count;
    __u64 first_seen;
    __u64 last_update;
    struct port_scan_entry *next;
};

struct burst_entry {
    __be32 src_ip;
    atomic64_t packet_count;
    __u64 window_start;
    __u64 last_packet;
    struct burst_entry *next;
};

static struct port_scan_entry *port_scan_table[PORT_SCAN_TABLE_SIZE];
static struct burst_entry *burst_table[BURST_TABLE_SIZE];
static int port_scan_table_entries = 0;
static int burst_table_entries = 0;

static inline int get_port_scan_bucket(__be32 ip)
{
    return jhash_1word((__u32)ip, 0) % PORT_SCAN_TABLE_SIZE;
}

static inline int get_burst_bucket(__be32 ip)
{
    return jhash_1word((__u32)ip, 0) % BURST_TABLE_SIZE;
}

int detection_init(void)
{
    int i;

    spin_lock_init(&alert_lock);
    spin_lock_init(&default_config.lock);
    spin_lock_init(&signature_lock);

    for (i = 0; i < PORT_SCAN_TABLE_SIZE; i++)
        port_scan_table[i] = NULL;

    for (i = 0; i < BURST_TABLE_SIZE; i++)
        burst_table[i] = NULL;

    default_config.port_scan_threshold = DEFAULT_PORT_SCAN_THRESHOLD;
    default_config.port_scan_window_ms = DEFAULT_PORT_SCAN_WINDOW_MS;
    default_config.burst_threshold = DEFAULT_BURST_THRESHOLD;
    default_config.burst_window_ms = DEFAULT_BURST_WINDOW_MS;
    default_config.port_scan_enabled = true;
    default_config.burst_detection_enabled = true;
    default_config.signature_matching_enabled = true;

    memset(alert_queue, 0, sizeof(alert_queue));
    memset(signatures, 0, sizeof(signatures));

    pr_info("net_traffic_monitor: Detection engine initialized\n");
    return 0;
}

void detection_exit(void)
{
    struct port_scan_entry *entry, *next;
    struct burst_entry *bentry, *bnext;
    int i;

    for (i = 0; i < PORT_SCAN_TABLE_SIZE; i++) {
        entry = port_scan_table[i];
        while (entry) {
            next = entry->next;
            kfree(entry);
            entry = next;
        }
        port_scan_table[i] = NULL;
    }

    for (i = 0; i < BURST_TABLE_SIZE; i++) {
        bentry = burst_table[i];
        while (bentry) {
            bnext = bentry->next;
            kfree(bentry);
            bentry = bnext;
        }
        burst_table[i] = NULL;
    }

    port_scan_table_entries = 0;
    burst_table_entries = 0;

    pr_info("net_traffic_monitor: Detection engine exited\n");
}

void detection_reset(void)
{
    struct port_scan_entry *entry, *next;
    struct burst_entry *bentry, *bnext;
    int i;

    spin_lock(&port_scan_lock);
    for (i = 0; i < PORT_SCAN_TABLE_SIZE; i++) {
        entry = port_scan_table[i];
        while (entry) {
            next = entry->next;
            kfree(entry);
            entry = next;
        }
        port_scan_table[i] = NULL;
    }
    port_scan_table_entries = 0;
    spin_unlock(&port_scan_lock);

    spin_lock(&burst_lock);
    for (i = 0; i < BURST_TABLE_SIZE; i++) {
        bentry = burst_table[i];
        while (bentry) {
            bnext = bentry->next;
            kfree(bentry);
            bentry = bnext;
        }
        burst_table[i] = NULL;
    }
    burst_table_entries = 0;
    spin_unlock(&burst_lock);

    alert_read_index = 0;
    alert_write_index = 0;
    alert_id_counter = 0;

    default_config.port_scan_threshold = DEFAULT_PORT_SCAN_THRESHOLD;
    default_config.port_scan_window_ms = DEFAULT_PORT_SCAN_WINDOW_MS;
    default_config.burst_threshold = DEFAULT_BURST_THRESHOLD;
    default_config.burst_window_ms = DEFAULT_BURST_WINDOW_MS;
}

static bool check_port_scan_simple(struct packet_info *pkt)
{
    struct port_scan_entry *entry;
    int bkt;
    __u64 now = ktime_get_real_ns();
    __u64 window_ns = default_config.port_scan_window_ms * 1000000ULL;
    bool should_alert = false;
    __u16 i;

    if (!pkt || pkt->protocol != PROTOCOL_TCP)
        return false;

    bkt = get_port_scan_bucket(pkt->src_ip);

    spin_lock(&port_scan_lock);
    entry = port_scan_table[bkt];

    while (entry) {
        if (entry->src_ip == pkt->src_ip) {
            if (now - entry->last_update > window_ns) {
                entry->port_count = 0;
                entry->last_update = now;
                spin_unlock(&port_scan_lock);
                return false;
            }

            for (i = 0; i < entry->port_count; i++) {
                if (entry->ports[i] == pkt->dst_port) {
                    spin_unlock(&port_scan_lock);
                    return false;
                }
            }

            if (entry->port_count >= default_config.port_scan_threshold - 1) {
                should_alert = true;
            } else if (entry->port_count < MAX_PORTS_PER_SOURCE) {
                entry->ports[entry->port_count++] = pkt->dst_port;
                entry->last_update = now;
            }

            spin_unlock(&port_scan_lock);
            return should_alert;
        }
        entry = entry->next;
    }
    spin_unlock(&port_scan_lock);

    if (port_scan_table_entries > 50000)
        return false;

    entry = kzalloc(sizeof(struct port_scan_entry), GFP_ATOMIC);
    if (!entry)
        return false;

    entry->src_ip = pkt->src_ip;
    entry->ports[0] = pkt->dst_port;
    entry->port_count = 1;
    entry->first_seen = now;
    entry->last_update = now;

    spin_lock(&port_scan_lock);
    entry->next = port_scan_table[bkt];
    port_scan_table[bkt] = entry;
    port_scan_table_entries++;
    spin_unlock(&port_scan_lock);

    return false;
}

static bool check_burst_detection_simple(struct packet_info *pkt)
{
    struct burst_entry *entry;
    int bkt;
    __u64 now = ktime_get_real_ns();
    __u64 window_ns = default_config.burst_window_ms * 1000000ULL;

    bkt = get_burst_bucket(pkt->src_ip);

    spin_lock(&burst_lock);
    entry = burst_table[bkt];

    while (entry) {
        if (entry->src_ip == pkt->src_ip) {
            if (now - entry->window_start > window_ns) {
                atomic64_set(&entry->packet_count, 1);
                entry->window_start = now;
            } else {
                atomic64_inc(&entry->packet_count);
            }

            entry->last_packet = now;

            if (atomic64_read(&entry->packet_count) > default_config.burst_threshold) {
                spin_unlock(&burst_lock);
                return true;
            }

            spin_unlock(&burst_lock);
            return false;
        }
        entry = entry->next;
    }
    spin_unlock(&burst_lock);

    if (burst_table_entries > 50000)
        return false;

    entry = kzalloc(sizeof(struct burst_entry), GFP_ATOMIC);
    if (!entry)
        return false;

    entry->src_ip = pkt->src_ip;
    atomic64_set(&entry->packet_count, 1);
    entry->window_start = now;
    entry->last_packet = now;

    spin_lock(&burst_lock);
    entry->next = burst_table[bkt];
    burst_table[bkt] = entry;
    burst_table_entries++;
    spin_unlock(&burst_lock);

    return false;
}

static bool check_signature_match(struct packet_info *pkt)
{
    __u32 i;
    bool matched = false;

    if (!default_config.signature_matching_enabled)
        return false;

    if (!pkt)
        return false;

    spin_lock(&signature_lock);
    for (i = 0; i < signature_count; i++) {
        struct signature *sig = &signatures[i];

        if (!sig->enabled)
            continue;

        if (sig->protocol && sig->protocol != pkt->protocol)
            continue;

        if (sig->dst_port_min && pkt->dst_port < sig->dst_port_min)
            continue;
        if (sig->dst_port_max && pkt->dst_port > sig->dst_port_max)
            continue;

        if ((pkt->tcp_flags & sig->tcp_flags_mask) == sig->tcp_flags_value) {
            matched = true;
            break;
        }
    }
    spin_unlock(&signature_lock);

    return matched;
}

static void create_alert(enum alert_type type, enum alert_severity severity,
                        struct packet_info *pkt, const char *message)
{
    struct alert *alert;
    __u32 next_index;

    spin_lock(&alert_lock);

    next_index = (alert_write_index + 1) % MAX_ALERT_QUEUE_SIZE;
    if (next_index == alert_read_index) {
        alert_read_index = (alert_read_index + 1) % MAX_ALERT_QUEUE_SIZE;
    }

    alert = &alert_queue[alert_write_index];
    alert->id = ++alert_id_counter;
    alert->timestamp = ktime_get_real_ns();
    alert->type = type;
    alert->severity = severity;

    if (pkt) {
        alert->src_ip = pkt->src_ip;
        alert->dst_ip = pkt->dst_ip;
    }

    strscpy(alert->message, message, sizeof(alert->message) - 1);

    alert_write_index = next_index;

    spin_unlock(&alert_lock);

    switch (severity) {
    case ALERT_CRITICAL:
        pr_warn("net_traffic_monitor: [CRITICAL] %s\n", message);
        break;
    case ALERT_WARNING:
        pr_warn("net_traffic_monitor: [WARNING] %s\n", message);
        break;
    case ALERT_INFO:
    default:
        pr_info("net_traffic_monitor: [INFO] %s\n", message);
        break;
    }
}

int detection_check_packet(struct packet_info *pkt)
{
    int alert_count = 0;
    char message[256];

    if (!pkt || !net_traffic_monitor_is_running())
        return 0;

    if (default_config.port_scan_enabled && check_port_scan_simple(pkt)) {
        scnprintf(message, sizeof(message), "Port scan detected from %s",
                 ip_to_str(pkt->src_ip));
        create_alert(ALERT_PORT_SCAN, ALERT_WARNING, pkt, message);
        alert_count++;
    }

    if (default_config.burst_detection_enabled && check_burst_detection_simple(pkt)) {
        scnprintf(message, sizeof(message), "Burst traffic detected from %s",
                 ip_to_str(pkt->src_ip));
        create_alert(ALERT_BURST_DETECTION, ALERT_WARNING, pkt, message);
        alert_count++;
    }

    if (default_config.signature_matching_enabled && check_signature_match(pkt)) {
        scnprintf(message, sizeof(message), "Signature match from %s to %s",
                 ip_to_str(pkt->src_ip), ip_to_str(pkt->dst_ip));
        create_alert(ALERT_SIGNATURE_MATCH, ALERT_CRITICAL, pkt, message);
        alert_count++;
    }

    return alert_count;
}

struct alert *detection_get_next_alert(void)
{
    struct alert *alert;

    spin_lock(&alert_lock);

    if (alert_read_index == alert_write_index) {
        spin_unlock(&alert_lock);
        return NULL;
    }

    alert = &alert_queue[alert_read_index];
    alert_read_index = (alert_read_index + 1) % MAX_ALERT_QUEUE_SIZE;

    spin_unlock(&alert_lock);

    return alert;
}

void detection_config_set(struct detection_config *cfg)
{
    if (!cfg)
        return;

    spin_lock(&default_config.lock);

    default_config.port_scan_threshold = cfg->port_scan_threshold;
    default_config.port_scan_window_ms = cfg->port_scan_window_ms;
    default_config.burst_threshold = cfg->burst_threshold;
    default_config.burst_window_ms = cfg->burst_window_ms;
    default_config.port_scan_enabled = cfg->port_scan_enabled;
    default_config.burst_detection_enabled = cfg->burst_detection_enabled;
    default_config.signature_matching_enabled = cfg->signature_matching_enabled;

    spin_unlock(&default_config.lock);
}

void detection_config_get(struct detection_config *cfg)
{
    if (!cfg)
        return;

    spin_lock(&default_config.lock);
    memcpy(cfg, &default_config, sizeof(struct detection_config));
    spin_unlock(&default_config.lock);
}