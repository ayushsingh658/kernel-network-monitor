#ifndef NET_TRAFFIC_MONITOR_H
#define NET_TRAFFIC_MONITOR_H

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>

#include "packet.h"
#include "detection.h"
#include "stats.h"

#define MODULE_NAME "net_traffic_monitor"
#define MODULE_VERSION_STR "1.0.0"

#define PROC_DIR_NAME "net_traffic_monitor"
#define MAX_PROC_STRING_SIZE 4096
#define MAX_ALERT_QUEUE_SIZE 1024
#define MAX_IP_TRACKED 65536

#define DEFAULT_PORT_SCAN_THRESHOLD 10
#define DEFAULT_PORT_SCAN_WINDOW_MS 5000
#define DEFAULT_BURST_THRESHOLD 100
#define DEFAULT_BURST_WINDOW_MS 1000

extern int net_traffic_monitor_init(void);
extern void net_traffic_monitor_exit(void);
extern int net_traffic_monitor_start(void);
extern void net_traffic_monitor_stop(void);
extern bool net_traffic_monitor_is_running(void);

extern int procfs_init(void);
extern void procfs_exit(void);

#endif