#include "packet.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/errno.h>

static DEFINE_SPINLOCK(packet_info_lock);

unsigned char *ntoa_helper(__be32 addr)
{
    static unsigned char buffer[16];
    unsigned char *p = (unsigned char *)&addr;

    snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u",
             p[0], p[1], p[2], p[3]);
    return buffer;
}

const char *protocol_to_str(__u8 protocol)
{
    switch (protocol) {
    case PROTOCOL_TCP:
        return "TCP";
    case PROTOCOL_UDP:
        return "UDP";
    case PROTOCOL_ICMP:
        return "ICMP";
    default:
        return "UNKNOWN";
    }
}

const char *ip_to_str(__be32 ip)
{
    return ntoa_helper(ip);
}

const char *tcp_flags_to_str(__u8 flags)
{
    static char buffer[32];
    int offset = 0;

    buffer[0] = '\0';

    if (flags & TCP_FLAG_FIN)
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "FIN ");
    if (flags & TCP_FLAG_SYN)
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "SYN ");
    if (flags & TCP_FLAG_RST)
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "RST ");
    if (flags & TCP_FLAG_PSH)
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "PSH ");
    if (flags & TCP_FLAG_ACK)
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "ACK ");
    if (flags & TCP_FLAG_URG)
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "URG ");

    if (offset == 0)
        return "NONE";

    buffer[offset - 1] = '\0';
    return buffer;
}

static __u8 parse_tcp_flags(struct tcphdr *tcph)
{
    __u8 flags = 0;

    if (!tcph)
        return 0;

    if (tcph->fin)
        flags |= TCP_FLAG_FIN;
    if (tcph->syn)
        flags |= TCP_FLAG_SYN;
    if (tcph->rst)
        flags |= TCP_FLAG_RST;
    if (tcph->psh)
        flags |= TCP_FLAG_PSH;
    if (tcph->ack)
        flags |= TCP_FLAG_ACK;
    if (tcph->urg)
        flags |= TCP_FLAG_URG;

    return flags;
}

static struct packet_info *extract_transport_info(struct sk_buff *skb,
                                                   struct iphdr *iph,
                                                   struct packet_info *pkt)
{
    unsigned int transport_offset;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;

    transport_offset = iph->ihl * 4;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = (struct tcphdr *)((unsigned char *)iph + transport_offset);
        pkt->src_port = ntohs(tcph->source);
        pkt->dst_port = ntohs(tcph->dest);
        pkt->tcp_flags = parse_tcp_flags(tcph);
        break;

    case IPPROTO_UDP:
        udph = (struct udphdr *)((unsigned char *)iph + transport_offset);
        pkt->src_port = ntohs(udph->source);
        pkt->dst_port = ntohs(udph->dest);
        break;

    case IPPROTO_ICMP:
        icmph = (struct icmphdr *)((unsigned char *)iph + transport_offset);
        pkt->src_port = 0;
        pkt->dst_port = icmph->type;
        break;

    default:
        pkt->src_port = 0;
        pkt->dst_port = 0;
        break;
    }

    return pkt;
}

struct packet_info *packet_parse(const struct sk_buff *skb)
{
    struct iphdr *iph;
    struct packet_info *pkt;
    unsigned int ip_len;

    if (!skb)
        return NULL;

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NULL;

    iph = ip_hdr(skb);
    if (!iph)
        return NULL;

    if (iph->version != 4)
        return NULL;

    ip_len = iph->ihl * 4;
    if (!pskb_may_pull(skb, ip_len))
        return NULL;

    if (skb->len < ip_len)
        return NULL;

    pkt = kzalloc(sizeof(struct packet_info), GFP_ATOMIC);
    if (!pkt)
        return NULL;

    pkt->src_ip = iph->saddr;
    pkt->dst_ip = iph->daddr;
    pkt->pkt_len = ntohs(iph->tot_len);
    pkt->ip_hdr_len = ip_len;
    pkt->timestamp = ktime_get_real_ns();

    switch (iph->protocol) {
    case IPPROTO_TCP:
        pkt->protocol = PROTOCOL_TCP;
        break;
    case IPPROTO_UDP:
        pkt->protocol = PROTOCOL_UDP;
        break;
    case IPPROTO_ICMP:
        pkt->protocol = PROTOCOL_ICMP;
        break;
    default:
        pkt->protocol = PROTOCOL_UNKNOWN;
        break;
    }

    if (pskb_may_pull(skb, ip_len + sizeof(struct tcphdr))) {
        extract_transport_info(skb, iph, pkt);
    }

    return pkt;
}

void packet_info_free(struct packet_info *pkt)
{
    if (pkt)
        kfree(pkt);
}