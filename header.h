#include <stdint.h>
struct ethernet_header {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed));

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} __attribute__((packed));

struct ipv4_header {
    uint8_t version_headerLength;
    uint8_t service_type;
    uint16_t packet_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
} __attribute__((packed));

// struct ipv6_header{
//     uint32_t version_priority_flow;
//     uint16_t payload_length;
//     uint8_t next_header;
//     uint8_t hop_limit;
//     uint8_t src_addr[16];
//     uint8_t dest_addr[16];
// } __attribute__((packed));

struct tcp_pseudo_header {
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
} __attribute__((packed));


struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

struct udp_pseudo_header {
    uint8_t src_ip[4];
    uint8_t dest_ip[4];
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_length;
} __attribute__((packed));

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
} __attribute__((packed));


