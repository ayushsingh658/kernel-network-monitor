#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PROC_STATS_PATH "/proc/net_traffic_monitor/stats"
#define PROC_ALERTS_PATH "/proc/net_traffic_monitor/alerts"
#define PROC_CONFIG_PATH "/proc/net_traffic_monitor/config"
#define PROC_CONTROL_PATH "/proc/net_traffic_monitor/control"

#define BUFFER_SIZE 8192

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -s, --stats          Show traffic statistics\n");
    printf("  -a, --alerts         Show recent alerts\n");
    printf("  -c, --config        Show detection configuration\n");
    printf("  -t, --top N         Show top N source IPs\n");
    printf("      --start          Start monitoring\n");
    printf("      --stop           Stop monitoring\n");
    printf("      --reset          Reset statistics and alerts\n");
    printf("  -d, --details=FILE   Show details for specific proc file\n");
    printf("  -h, --help          Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -s                  # View global statistics\n", prog_name);
    printf("  %s -a                  # View recent alerts\n", prog_name);
    printf("  %s --start             # Start the monitor\n", prog_name);
    printf("  %s -t 20               # View top 20 IPs\n", prog_name);
}

static int read_proc_file(const char *path)
{
    char buffer[BUFFER_SIZE];
    int fd;
    ssize_t bytes_read;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open proc file");
        return -1;
    }

    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }

    close(fd);
    return 0;
}

static int write_proc_file(const char *path, const char *value)
{
    int fd;
    ssize_t bytes_written;

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open proc file");
        return -1;
    }

    bytes_written = write(fd, value, strlen(value));
    if (bytes_written < 0) {
        perror("Failed to write to proc file");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int show_stats(void)
{
    return read_proc_file(PROC_STATS_PATH);
}

static int show_alerts(void)
{
    return read_proc_file(PROC_ALERTS_PATH);
}

static int show_config(void)
{
    return read_proc_file(PROC_CONFIG_PATH);
}

static int show_control(void)
{
    return read_proc_file(PROC_CONTROL_PATH);
}

static int start_monitor(void)
{
    return write_proc_file(PROC_CONTROL_PATH, "start\n");
}

static int stop_monitor(void)
{
    return write_proc_file(PROC_CONTROL_PATH, "stop\n");
}

static int reset_monitor(void)
{
    return write_proc_file(PROC_CONTROL_PATH, "reset\n");
}

static int show_top(int count)
{
    FILE *fp;
    char buffer[BUFFER_SIZE];
    char line[BUFFER_SIZE];
    char **lines = NULL;
    int line_count = 0;
    int i;

    fp = fopen(PROC_STATS_PATH, "r");
    if (!fp) {
        perror("Failed to open stats file");
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "===") || strstr(buffer, "IP") ||
            strstr(buffer, "---") || buffer[0] == '\n' ||
            strstr(buffer, "Total") || strstr(buffer, "global")) {
            printf("%s", buffer);
        } else if (strchr(buffer, '.')) {
            lines = realloc(lines, (line_count + 1) * sizeof(char *));
            lines[line_count] = strdup(buffer);
            line_count++;
        }
    }

    fclose(fp);

    printf("\n=== Top %d Source IPs ===\n", count);
    printf("%-15s %12s %12s %8s\n", "IP", "Packets", "Bytes", "Alerts");
    printf("===========================================\n");

    for (i = 0; i < line_count && i < count; i++) {
        printf("%s", lines[i]);
        free(lines[i]);
    }

    free(lines);

    return 0;
}

int main(int argc, char *argv[])
{
    int option;
    int stats_flag = 0;
    int alerts_flag = 0;
    int config_flag = 0;
    int control_flag = 0;
    int top_count = 0;
    int start_flag = 0;
    int stop_flag = 0;
    int reset_flag = 0;

    static struct option long_options[] = {
        {"stats", no_argument, 0, 's'},
        {"alerts", no_argument, 0, 'a'},
        {"config", no_argument, 0, 'c'},
        {"control", no_argument, 0, 'C'},
        {"top", required_argument, 0, 't'},
        {"start", no_argument, 0, 1},
        {"stop", no_argument, 0, 2},
        {"reset", no_argument, 0, 3},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((option = getopt_long(argc, argv, "sact:Cvh", long_options, NULL)) != -1) {
        switch (option) {
        case 's':
            stats_flag = 1;
            break;
        case 'a':
            alerts_flag = 1;
            break;
        case 'c':
            config_flag = 1;
            break;
        case 'C':
            control_flag = 1;
            break;
        case 't':
            top_count = atoi(optarg);
            break;
        case 1:
            start_flag = 1;
            break;
        case 2:
            stop_flag = 1;
            break;
        case 3:
            reset_flag = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return option == 'h' ? 0 : 1;
        }
    }

    if (stats_flag) {
        return show_stats();
    }

    if (alerts_flag) {
        return show_alerts();
    }

    if (config_flag) {
        return show_config();
    }

    if (control_flag) {
        return show_control();
    }

    if (top_count > 0) {
        return show_top(top_count);
    }

    if (start_flag) {
        return start_monitor();
    }

    if (stop_flag) {
        return stop_monitor();
    }

    if (reset_flag) {
        return reset_monitor();
    }

    printf("=== net_traffic_monitor CLI ===\n");
    printf("\nGlobal Stats:\n");
    show_stats();
    printf("\nRecent Alerts:\n");
    show_alerts();
    printf("\nConfiguration:\n");
    show_config();

    return 0;
}