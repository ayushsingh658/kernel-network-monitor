# Linux Kernel Network Traffic Monitor

A production-grade Linux kernel module designed to monitor and analyze network traffic in real-time. Built with netfilter hooks and procfs for efficient data capture and reporting.

## Features

- **Real-time Packet Capture**: Intercepts network packets at the netfilter PRE_ROUTING hook
- **Multi-Protocol Support**: Handles TCP, UDP, and ICMP protocols
- **Suspicious Activity Detection**:
  - Port scan detection (multiple ports accessed from single source)
  - Traffic burst detection (DDoS prevention)
  - Signature-based pattern matching
- **Statistics Tracking**:
  - Global traffic counters (packets, bytes, protocol breakdown)
  - Per-source IP statistics
  - Connection-level tracking
- **Procfs Interface**: User-friendly access via `/proc/net_traffic_monitor/`

## Architecture

```
┌─────────────────────────────────────────┐
│       Linux Kernel Space                 │
├─────────────────────────────────────────┤
│  ┌─────────┐   ┌─────────────────┐     │
│  │ Netfilter│──▶│ Packet Processor│     │
│  │ Hook    │   │                │     │
│  └─────────┘   └────────┬────────┘     │
│                         │              │
│         ┌──────────────┼──────────┐   │
│         ▼              ▼          ▼   │
│  ┌───────────┐ ┌────────────┐ ┌────┐  │
│  │ Detection │ │ Statistics │ │Proc│  │
│  │ Engine   │ │           │ │fs  │  │
│  └───────────┘ └───────────┘ └────┘  │
│           │          │         │        │
│           ▼          ▼         ▼      │
│  ┌────────────────────────────────┐ │
│  │     /proc/net_traffic_monitor/    │ │
│  │  stats | alerts | config       │ │
│  └────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

## File Structure

```
kernel-net-monitor/
├── Makefile                 # Build system
├── README.md                # This file
├── include/
│   ├── net_traffic_monitor.h
│   ├── packet.h
│   ├── detection.h
│   └── stats.h
├── src/
│   ├── main.c             # Module init/exit
│   ├── packet_processor.c  # Packet parsing
│   ├── detection_engine.c # Threat detection
│   ├── stats.c          # Statistics
│   └── procfs.c         # Procfs interface
└── userspace/
    └── monitor_ctl.c     # CLI control tool
```

## Building

### Prerequisites
```bash
sudo apt install linux-headers-$(uname -r)
```

### Build Module
```bash
make
```

### Build CLI Tool
```bash
cd userspace
gcc -o monitor_ctl monitor_ctl.c -Wall
```

## Loading/Unloading

### Load Module
```bash
sudo insmod net_traffic_monitor.ko
```

### Check Loaded
```bash
lsmod | grep net_traffic_monitor
dmesg | tail
```

### Unload Module
```bash
sudo rmmod net_traffic_monitor
```

## Usage

### View Statistics
```bash
# Via procfs
cat /proc/net_traffic_monitor/stats

# Via CLI tool
./monitor_ctl -s
```

### View Alerts
```bash
cat /proc/net_traffic_monitor/alerts
./monitor_ctl -a
```

### View Configuration
```bash
cat /proc/net_traffic_monitor/config
./monitor_ctl -c
```

### Module Control
```bash
# Start monitoring
echo "start" | sudo tee /proc/net_traffic_monitor/control

# Stop monitoring
echo "stop" | sudo tee /proc/net_traffic_monitor/control

# Reset statistics
echo "reset" | sudo tee /proc/net_traffic_monitor/control
```

### Configure Detection Parameters
```bash
# Set port scan threshold
echo "port_scan_threshold 20" | sudo tee /proc/net_traffic_monitor/config

# Set burst threshold
echo "burst_threshold 500" | sudo tee /proc/net_traffic_monitor/config

# Disable port scan detection
echo "port_scan disable" | sudo tee /proc/net_traffic_monitor/config
```

## Procfs Interface

| File | Description | Access |
|------|-------------|--------|
| `stats` | Global traffic statistics | Read |
| `alerts` | Recent security alerts | Read |
| `config` | Detection configuration | R/W |
| `control` | Module control | W |

## Technical Details

### Netfilter Hook
- Hook point: `NF_INET_PRE_ROUTING`
- Priority: `NF_IP_PRI_FIRST`
- Returns: `NF_ACCEPT` (monitoring only, non-blocking)

### Detection Algorithms

1. **Port Scan Detection**
   - Tracks unique destination ports accessed by each source IP
   - Sliding window: configurable (default 5 seconds)
   - Threshold: configurable (default 10 ports)

2. **Burst Detection**
   - Monitors packet rate per source IP
   - Window: configurable (default 1 second)
   - Threshold: configurable (default 100 packets)

### Memory Management
- Fixed-size hash tables with bounded entries
- Automatic cleanup of stale entries
- Lock-free reads, spinlock-protected writes

### Concurrency
- Per-CPU statistics aggregation
- RCU-safe hash table lookups
- Atomic64 counters for stats

## Resume-Worthy Highlights

- **Kernel Programming**: Demonstrates deep understanding of Linux kernel internals
- **Netfilter Hooks**: Real-world experience with packet processing at kernel level
- **Procfs**: User-kernel communication interface
- **Lock-Free Design**: atomic64 operations, RCU patterns
- **Production Code**: Proper error handling, cleanup, modular design

## License

GPL v2

## Author

Kernel Developer