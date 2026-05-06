#include "net_traffic_monitor.h"
#include "stats.h"
#include "detection.h"
#include "packet.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/version.h>

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_stats;
static struct proc_dir_entry *proc_alerts;
static struct proc_dir_entry *proc_config;
static struct proc_dir_entry *proc_control;

static ssize_t control_write(struct file *file, const char __user *buffer,
                            size_t count, loff_t *pos)
{
    char buf[32];

    if (count >= sizeof(buf))
        count = sizeof(buf) - 1;

    if (copy_from_user(buf, buffer, count))
        return -EFAULT;

    buf[count] = '\0';

    if (strncmp(buf, "start", 5) == 0) {
        net_traffic_monitor_start();
        pr_info("net_traffic_monitor: Started via procfs\n");
    } else if (strncmp(buf, "stop", 4) == 0) {
        net_traffic_monitor_stop();
        pr_info("net_traffic_monitor: Stopped via procfs\n");
    } else if (strncmp(buf, "reset", 5) == 0) {
        stats_reset();
        detection_reset();
        pr_info("net_traffic_monitor: Reset via procfs\n");
    }

    return count;
}

static int control_show(struct seq_file *m, void *v)
{
    seq_printf(m, "status: %s\n",
              net_traffic_monitor_is_running() ? "running" : "stopped");
    return 0;
}

static int control_open(struct inode *inode, struct file *file)
{
    return single_open(file, control_show, NULL);
}

static const struct proc_ops control_fops = {
    .proc_open = control_open,
    .proc_read = seq_read,
    .proc_write = control_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int stats_show(struct seq_file *m, void *v)
{
    stats_format_output(m);
    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_fops = {
    .proc_open = stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int alerts_show(struct seq_file *m, void *v)
{
    struct alert *alert;

    seq_printf(m, "=== Recent Alerts ===\n");
    seq_printf(m, "%-8s %-20s %-15s %-15s %s\n",
               "ID", "Timestamp", "Source IP", "Dest IP", "Message");
    seq_printf(m, "========================================================================\n");

    while ((alert = detection_get_next_alert()) != NULL) {
        seq_printf(m, "%-8llu %-20llu %-15s %-15s %s\n",
                  alert->id,
                  alert->timestamp,
                  ip_to_str(alert->src_ip),
                  ip_to_str(alert->dst_ip),
                  alert->message);
    }

    return 0;
}

static int alerts_open(struct inode *inode, struct file *file)
{
    return single_open(file, alerts_show, NULL);
}

static const struct proc_ops alerts_fops = {
    .proc_open = alerts_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static ssize_t config_write(struct file *file, const char __user *buffer,
                          size_t count, loff_t *pos)
{
    struct detection_config cfg;
    char buf[256];

    if (count >= sizeof(buf))
        count = sizeof(buf) - 1;

    if (copy_from_user(buf, buffer, count))
        return -EFAULT;

    buf[count] = '\0';

    detection_config_get(&cfg);

    if (sscanf(buf, "port_scan_threshold %u", &cfg.port_scan_threshold) == 1) {
        pr_info("net_traffic_monitor: port_scan_threshold set to %u\n",
               cfg.port_scan_threshold);
    } else if (sscanf(buf, "port_scan_window %u", &cfg.port_scan_window_ms) == 1) {
        pr_info("net_traffic_monitor: port_scan_window set to %u ms\n",
               cfg.port_scan_window_ms);
    } else if (sscanf(buf, "burst_threshold %u", &cfg.burst_threshold) == 1) {
        pr_info("net_traffic_monitor: burst_threshold set to %u\n",
               cfg.burst_threshold);
    } else if (sscanf(buf, "burst_window %u", &cfg.burst_window_ms) == 1) {
        pr_info("net_traffic_monitor: burst_window set to %u ms\n",
               cfg.burst_window_ms);
    } else if (strncmp(buf, "port_scan enable", 14) == 0) {
        cfg.port_scan_enabled = true;
    } else if (strncmp(buf, "port_scan disable", 15) == 0) {
        cfg.port_scan_enabled = false;
    } else if (strncmp(buf, "burst_detection enable", 22) == 0) {
        cfg.burst_detection_enabled = true;
    } else if (strncmp(buf, "burst_detection disable", 22) == 0) {
        cfg.burst_detection_enabled = false;
    }

    detection_config_set(&cfg);

    return count;
}

static int config_show(struct seq_file *m, void *v)
{
    struct detection_config cfg;

    detection_config_get(&cfg);

    seq_printf(m, "=== Detection Configuration ===\n");
    seq_printf(m, "port_scan_threshold = %u\n", cfg.port_scan_threshold);
    seq_printf(m, "port_scan_window_ms = %u\n", cfg.port_scan_window_ms);
    seq_printf(m, "burst_threshold = %u\n", cfg.burst_threshold);
    seq_printf(m, "burst_window_ms = %u\n", cfg.burst_window_ms);
    seq_printf(m, "port_scan_enabled = %s\n",
               cfg.port_scan_enabled ? "true" : "false");
    seq_printf(m, "burst_detection_enabled = %s\n",
               cfg.burst_detection_enabled ? "true" : "false");
    seq_printf(m, "signature_matching_enabled = %s\n\n",
               cfg.signature_matching_enabled ? "true" : "false");

    seq_printf(m, "=== Configuration Commands ===\n");
    seq_printf(m, "echo 'port_scan_threshold <value>' > /proc/net_traffic_monitor/config\n");
    seq_printf(m, "echo 'port_scan_window <ms>' > /proc/net_traffic_monitor/config\n");
    seq_printf(m, "echo 'burst_threshold <value>' > /proc/net_traffic_monitor/config\n");
    seq_printf(m, "echo 'burst_window <ms>' > /proc/net_traffic_monitor/config\n");
    seq_printf(m, "echo 'port_scan enable/disable' > /proc/net_traffic_monitor/config\n");
    seq_printf(m, "echo 'burst_detection enable/disable' > /proc/net_traffic_monitor/config\n");

    return 0;
}

static int config_open(struct inode *inode, struct file *file)
{
    return single_open(file, config_show, NULL);
}

static const struct proc_ops config_fops = {
    .proc_open = config_open,
    .proc_read = seq_read,
    .proc_write = config_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

int procfs_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
    proc_root = proc_mkdir(PROC_DIR_NAME, init_net.proc_net);
#else
    proc_root = proc_mkdir(PROC_DIR_NAME, init_net.proc_net);
#endif
    if (!proc_root) {
        pr_err("net_traffic_monitor: Failed to create proc directory\n");
        return -ENOMEM;
    }

    proc_stats = proc_create("stats", 0444, proc_root, &stats_fops);
    if (!proc_stats) {
        pr_err("net_traffic_monitor: Failed to create stats file\n");
        goto cleanup;
    }

    proc_alerts = proc_create("alerts", 0444, proc_root, &alerts_fops);
    if (!proc_alerts) {
        pr_err("net_traffic_monitor: Failed to create alerts file\n");
        goto cleanup_stats;
    }

    proc_config = proc_create("config", 0644, proc_root, &config_fops);
    if (!proc_config) {
        pr_err("net_traffic_monitor: Failed to create config file\n");
        goto cleanup_alerts;
    }

    proc_control = proc_create("control", 0644, proc_root, &control_fops);
    if (!proc_control) {
        pr_err("net_traffic_monitor: Failed to create control file\n");
        goto cleanup_config;
    }

    pr_info("net_traffic_monitor: Procfs interface initialized\n");
    return 0;

cleanup_config:
    proc_remove(proc_config);
cleanup_alerts:
    proc_remove(proc_alerts);
cleanup_stats:
    proc_remove(proc_stats);
cleanup:
    proc_remove(proc_root);
    return -ENOMEM;
}

void procfs_exit(void)
{
    if (proc_control)
        proc_remove(proc_control);
    if (proc_config)
        proc_remove(proc_config);
    if (proc_alerts)
        proc_remove(proc_alerts);
    if (proc_stats)
        proc_remove(proc_stats);
    if (proc_root)
        proc_remove(proc_root);

    pr_info("net_traffic_monitor: Procfs interface exited\n");
}