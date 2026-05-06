#ifndef PACKET_H
#define PACKET_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#define PACKET_INFO_MAGIC 0x504b5454

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN   0x02
#define TCP_FLAG_RST   0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

enum packet_protocol {
    PROTOCOL_UNKNOWN = 0,
    PROTOCOL_TCP = 1,
    PROTOCOL_UDP = 2,
    PROTOCOL_ICMP = 3,
};

struct packet_info {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 tcp_flags;
    __u32 pkt_len;
    __u64 timestamp;
    __u16 ip_hdr_len;
};

struct packet_info *packet_parse(const struct sk_buff *skb);
const char *protocol_to_str(__u8 protocol);
const char *ip_to_str(__be32 ip);
void packet_info_free(struct packet_info *pkt);

#endif