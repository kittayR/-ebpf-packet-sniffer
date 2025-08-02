#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

struct data_t {
    u32 saddr;
    u32 daddr;
    u16 protocol;
    u32 size;
};

BPF_PERF_OUTPUT(events);

int packet_monitor(struct __sk_buff *skb) {
    struct data_t data = {};
    u8 *cursor = 0;

    // Start parsing packet
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    if (ethernet->type != 0x0800) {
        return 0; // Only IPv4
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    data.saddr = ip->src;
    data.daddr = ip->dst;
    data.protocol = ip->nextp;
    data.size = ip->tlen;

    // Submit only the struct data_t, not the whole packet
    events.perf_submit(skb, &data, sizeof(data));
    return 0;
}
