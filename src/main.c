#include "net_traffic_monitor.h"
#include "packet.h"
#include "stats.h"
#include "detection.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static atomic_t module_state = ATOMIC_INIT(0);
static struct nf_hook_ops *nf_hook_ops_registered = NULL;

static int process_packet(struct sk_buff *skb)
{
    struct packet_info *pkt;

    if (!skb)
        return NF_ACCEPT;

    if (!net_traffic_monitor_is_running())
        return NF_ACCEPT;

    pkt = packet_parse(skb);
    if (!pkt)
        return NF_ACCEPT;

    stats_update(pkt);
    detection_check_packet(pkt);

    kfree(pkt);
    return NF_ACCEPT;
}

static unsigned int nf_hook_handler(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    return process_packet(skb);
}

static struct nf_hook_ops nf_hook_template = {
    .hook     = nf_hook_handler,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

int net_traffic_monitor_init(void)
{
    int ret;

    ret = procfs_init();
    if (ret) {
        pr_err("net_traffic_monitor: Failed to initialize procfs: %d\n", ret);
        return ret;
    }

    ret = stats_init();
    if (ret) {
        pr_err("net_traffic_monitor: Failed to initialize stats: %d\n", ret);
        goto cleanup_procfs;
    }

    ret = detection_init();
    if (ret) {
        pr_err("net_traffic_monitor: Failed to initialize detection: %d\n", ret);
        goto cleanup_stats;
    }

    nf_hook_ops_registered = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!nf_hook_ops_registered) {
        ret = -ENOMEM;
        goto cleanup_detection;
    }

    memcpy(nf_hook_ops_registered, &nf_hook_template, sizeof(struct nf_hook_ops));

    ret = nf_register_net_hook(&init_net, nf_hook_ops_registered);
    if (ret) {
        pr_err("net_traffic_monitor: Failed to register netfilter hook: %d\n", ret);
        goto cleanup_nf_hook;
    }

    pr_info("net_traffic_monitor: Module initialized successfully\n");
    return 0;

cleanup_nf_hook:
    kfree(nf_hook_ops_registered);
    nf_hook_ops_registered = NULL;
cleanup_detection:
    detection_exit();
cleanup_stats:
    stats_exit();
cleanup_procfs:
    procfs_exit();
    return ret;
}

void net_traffic_monitor_exit(void)
{
    if (nf_hook_ops_registered) {
        nf_unregister_net_hook(&init_net, nf_hook_ops_registered);
        kfree(nf_hook_ops_registered);
        nf_hook_ops_registered = NULL;
    }

    detection_exit();
    stats_exit();
    procfs_exit();

    pr_info("net_traffic_monitor: Module exited\n");
}

int net_traffic_monitor_start(void)
{
    atomic_set(&module_state, 1);
    pr_info("net_traffic_monitor: Monitoring started\n");
    return 0;
}

void net_traffic_monitor_stop(void)
{
    atomic_set(&module_state, 0);
    pr_info("net_traffic_monitor: Monitoring stopped\n");
}

bool net_traffic_monitor_is_running(void)
{
    return atomic_read(&module_state) == 1;
}

static int __init net_traffic_monitor_module_init(void)
{
    int ret;

    ret = net_traffic_monitor_init();
    if (ret)
        return ret;

    net_traffic_monitor_start();

    pr_info(MODULE_NAME " v%s loaded\n", MODULE_VERSION_STR);
    return 0;
}

static void __exit net_traffic_monitor_module_exit(void)
{
    net_traffic_monitor_stop();
    net_traffic_monitor_exit();
}

module_init(net_traffic_monitor_module_init);
module_exit(net_traffic_monitor_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Developer");
MODULE_DESCRIPTION("Linux Kernel Network Traffic Monitor");
MODULE_VERSION(MODULE_VERSION_STR);