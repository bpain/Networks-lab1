#include "./header.h"
#include "pcap/pcap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "checksum.h"


FILE *fptr; 


pcap_t* open_pcap_file(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* file = pcap_open_offline(filename, errbuf);
    if (file == NULL) {
        fprintf(stderr, "Error opening file: %s\n", errbuf);
        exit(EXIT_FAILURE); 
    }
    return file;
}

void parse_IPV6(const void* addr, u_int16_t len){
    fprintf(fptr, "    IP Header\n");
    //struct ipv6_header* ipv6 = (struct ipv6_header*)malloc(sizeof(struct ipv6_header));
    //memcpy(ipv6, addr, sizeof(struct ipv6_header));

    //...
}

void print_flags(uint8_t flags) {
    if(flags & 0x02){
        fprintf(fptr, "\t\tSYN Flag: Yes\n");
    }
    else {
        fprintf(fptr, "\t\tSYN Flag: No\n");
    }
    if(flags & 0x04){
        fprintf(fptr, "\t\tRST Flag: Yes\n");
    }
    else {
        fprintf(fptr, "\t\tRST Flag: No\n");
    }
    if(flags & 0x01){
        fprintf(fptr, "\t\tFIN Flag: Yes\n");
    }
    else {
        fprintf(fptr, "\t\tFIN Flag: No\n");
    }
    if(flags & 0x10){
        fprintf(fptr, "\t\tACK Flag: Yes\n");
    }
    else {
        fprintf(fptr, "\t\tACK Flag: No\n");
    }
}

void print_source_port(struct tcp_header* tcp) {
    u_int16_t src_port = ntohs(tcp->src_port);
    if(src_port == 80) {
        fprintf(fptr, "\t\tSource Port: HTTP\n");
    } 
    else if(src_port == 992) {
        fprintf(fptr, "\t\tSource Port: Telnet\n");
    } 
    else if (src_port == 21) {
        fprintf(fptr, "\t\tSource Port: FTP\n");
    }
    else if(src_port == 110) {
        fprintf(fptr, "\t\tSource Port: POP3\n");
    }
    else if(src_port == 25) {
        fprintf(fptr, "\t\tSource Port: SMTP\n");
    }
    else {
        fprintf(fptr, "\t\tSource Port: %d\n", src_port);
    }
}
void print_dest_port(struct tcp_header* tcp) {
    u_int16_t dest_port = ntohs(tcp->dest_port);
    if(dest_port == 80) {
        fprintf(fptr, "\t\tDest Port: HTTP\n");
    } 
    else if(dest_port == 992) {
        fprintf(fptr, "\t\tDest Port: Telnet\n");
    } 
    else if (dest_port == 21) {
        fprintf(fptr, "\t\tDest Port: FTP\n");
    }
    else if(dest_port == 110) {
        fprintf(fptr, "\t\tDest Port: POP3\n");
    }
    else if(dest_port == 25) {
        fprintf(fptr, "\t\tDest Port: SMTP\n");
    }
    else {
        fprintf(fptr, "\t\tDest Port: %d\n", dest_port);
    }
}

void parse_TCP(const void* addr, u_int16_t len, struct tcp_pseudo_header* pseudo_header){
    fprintf(fptr, "\tTCP Header\n");
    struct tcp_header* tcp = (struct tcp_header*)malloc(sizeof(struct tcp_header));
    memcpy(tcp, addr, sizeof(struct tcp_header));
    char* raw_data = (char*)malloc(len + sizeof(struct tcp_pseudo_header));
    memcpy(raw_data, pseudo_header, sizeof(struct tcp_pseudo_header));
    memcpy(raw_data + sizeof(struct tcp_pseudo_header), addr, len);
    fprintf(fptr, "\t\tSegment Length: %d\n", len);
    print_source_port(tcp);
    print_dest_port(tcp);
    fprintf(fptr, "\t\tSequence Number: %u\n", ntohl(tcp->seq_num));
    fprintf(fptr, "\t\tACK Number: %u\n", ntohl(tcp->ack_num));
    print_flags(tcp->flags);
    fprintf(fptr, "\t\tWindow Size: %d\n", ntohs(tcp->window_size));
    unsigned short checksum_valid = in_cksum((unsigned short*)raw_data, len + 12); 
    if(checksum_valid == 0) {
        fprintf(fptr, "\t\tChecksum: Correct (0x%04x)\n", ntohs(tcp->checksum));
    } else {
        fprintf(fptr, "\t\tChecksum: Incorrect (0x%04x)\n", ntohs(tcp->checksum));
    }
    free(tcp);
    free(raw_data);
    return;
}


void print_udp_source_port(struct udp_header* udp) {
    u_int16_t src_port = ntohs(udp->src_port);
    if(src_port == 80) {
        fprintf(fptr, "\t\tSource Port: HTTP\n");
    } 
    else if(src_port == 992) {
        fprintf(fptr, "\t\tSource Port: Telnet\n");
    } 
    else if (src_port == 21) {
        fprintf(fptr, "\t\tSource Port: FTP\n");
    }
    else if(src_port == 110) {
        fprintf(fptr, "\t\tSource Port: POP3\n");
    }
    else if(src_port == 25) {
        fprintf(fptr, "\t\tSource Port: SMTP\n");
    }
    else if(src_port == 53) {
        fprintf(fptr, "\t\tSource Port: DNS\n");
    }
    else {
        fprintf(fptr, "\t\tSource Port: %d\n", src_port);
    }
}
void print_udp_dest_port(struct udp_header* udp) {
    u_int16_t dest_port = ntohs(udp->dest_port);
    if(dest_port == 80) {
        fprintf(fptr, "\t\tDest Port: HTTP\n");
    } 
    else if(dest_port == 992) {
        fprintf(fptr, "\t\tDest Port: Telnet\n");
    } 
    else if (dest_port == 21) {
        fprintf(fptr, "\t\tDest Port: FTP\n");
    }
    else if(dest_port == 110) {
        fprintf(fptr, "\t\tDest Port: POP3\n");
    }
    else if(dest_port == 25) {
        fprintf(fptr, "\t\tDest Port: SMTP\n");
    }
    else if(dest_port == 53) {
        fprintf(fptr, "\t\tDest Port: DNS\n");
    }
    else {
        fprintf(fptr, "\t\tDest Port: %d\n", dest_port);
    }
}

struct udp_pseudo_header* create_udp_pseudo_header(struct ipv4_header* ipv4, uint16_t udp_length) {
    struct udp_pseudo_header* pseudo_header = (struct udp_pseudo_header*)malloc(sizeof(struct udp_pseudo_header));
    memcpy(pseudo_header->src_ip, ipv4->src_ip, 4);
    memcpy(pseudo_header->dest_ip, ipv4->dest_ip, 4);
    pseudo_header->reserved = 0;
    pseudo_header->protocol = ipv4->protocol;
    pseudo_header->udp_length = ntohs(udp_length); 
    return pseudo_header;
}

void parse_UDP( const void* addr, u_int16_t len, struct udp_pseudo_header* pseudo_header){
    fprintf(fptr, "\tUDP Header\n");
    struct udp_header* udp_header = (struct udp_header*)malloc(sizeof(struct udp_header)+ sizeof(struct udp_pseudo_header));
    memcpy(udp_header, addr, sizeof(struct udp_header));
    char* raw_data = (char*)malloc(len + sizeof(struct udp_pseudo_header));
    memcpy(raw_data, pseudo_header, sizeof(struct udp_pseudo_header));
    memcpy(raw_data + sizeof(struct udp_pseudo_header), addr, len);
    if(in_cksum((unsigned short*)raw_data, len + 12) != 0) {
        fprintf(fptr, "\t\tChecksum Incorrect:packet dropped\n");
        free(udp_header);
        return;
    }
    print_udp_source_port(udp_header);
    print_udp_dest_port(udp_header);
    free(udp_header);
    return;
}

void parse_ICMP(const void* addr, u_int16_t len ){
    struct icmp_header* icmp_header = (struct icmp_header*)malloc(sizeof(struct icmp_header));
    memcpy(icmp_header, addr, sizeof(struct icmp_header));
    if(in_cksum((unsigned short*)addr, len) != 0) {
        // fprintf(fptr, "\t\tChecksum Incorrect:packet dropped\n");
        // free(icmp_header);
        // return;
    }
    fprintf(fptr, "\tICMP Header\n");
    switch(icmp_header->type) {
        case 0:
            fprintf(fptr, "\t\tType: Reply\n");
            break;
        case 8:
            fprintf(fptr, "\t\tType: Request\n");
            break;
        default:
            fprintf(fptr, "\t\tType: %d\n", icmp_header->type);
    }
    free(icmp_header);
    return;
}

void print_back_half(struct ipv4_header* ipv4) {
    char* raw_data = (char*)ipv4; //stupid solution to get rid of warning 
    if(in_cksum((unsigned short*)raw_data, (ipv4->version_headerLength & 0x0F) * 4)  == 0) {
        fprintf(fptr, "\t\tChecksum: Correct (0x%04x)\n", ntohs(ipv4->header_checksum));
    } else {
        fprintf(fptr, "\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ipv4->header_checksum));
    }
    fprintf(fptr, "\t\tSender IP: %u.%u.%u.%u\n", (ipv4->src_ip[0]), (ipv4->src_ip[1]), (ipv4->src_ip[2]), ipv4->src_ip[3]);
    fprintf(fptr, "\t\tDest IP: %u.%u.%u.%u\n\n", (ipv4->dest_ip[0]), (ipv4->dest_ip[1]), (ipv4->dest_ip[2]), ipv4->dest_ip[3]);
    return; 
}

struct tcp_pseudo_header* create_tcp_pseudo_header(struct ipv4_header* ipv4, uint16_t tcp_length) {
    struct tcp_pseudo_header* pseudo_header = (struct tcp_pseudo_header*)malloc(sizeof(struct tcp_pseudo_header));
    memcpy(pseudo_header->src_ip, ipv4->src_ip, 4);
    memcpy(pseudo_header->dest_ip, ipv4->dest_ip, 4);
    pseudo_header->reserved = 0;
    pseudo_header->protocol = ipv4->protocol;
    pseudo_header->tcp_length = ntohs(tcp_length); 
    return pseudo_header;
}

void parse_IPV4(const void* addr){
    fprintf(fptr, "\tIP Header\n");
    struct ipv4_header* ipv4 = (struct ipv4_header*)malloc(sizeof(struct ipv4_header));
    memcpy(ipv4, addr, sizeof(struct ipv4_header));
    struct ipv4_header* full_ipv4 = (struct ipv4_header*)malloc((ipv4->version_headerLength & 0x0F) * 4);
    memcpy(full_ipv4, addr, (ipv4->version_headerLength & 0x0F) * 4);
    free(ipv4); 
    //print relevant fields from ipv4 header 
    uint16_t offset = (full_ipv4->version_headerLength & 0x0F) * 4;
    uint16_t len = ntohs(full_ipv4->packet_length) - offset;
    fprintf(fptr, "\t\tIP PDU Len: %d\n", ntohs(full_ipv4->packet_length));
    fprintf(fptr, "\t\tHeader Len (bytes): %d\n", offset);
    fprintf(fptr, "\t\tTTL: %d\n", full_ipv4->ttl);
    switch(full_ipv4->protocol) {
        case 1:
            fprintf(fptr, "\t\tProtocol: ICMP\n");
            print_back_half(full_ipv4);
            parse_ICMP((char*)addr + offset, len);
            break;
        case 6:
            fprintf(fptr, "\t\tProtocol: TCP\n");
            print_back_half(full_ipv4);
            struct tcp_pseudo_header* pseudo_header = create_tcp_pseudo_header(full_ipv4, len - offset);
            parse_TCP((char*)addr + offset, len,  pseudo_header);
            free(pseudo_header);
            break;
        case 17:
            fprintf(fptr, "\t\tProtocol: UDP\n");
            print_back_half(full_ipv4);
            struct udp_pseudo_header* udp_pseudo_header= create_udp_pseudo_header(full_ipv4, len - offset);
            parse_UDP((char*)addr + offset, len, udp_pseudo_header);
            free(udp_pseudo_header);
            break;
        default:
            fprintf(fptr, "\t\tProtocol: Unknown\n");
            print_back_half(full_ipv4);
            break;
    }
    free(full_ipv4);
    return; 
}


void parse_ARP(const void* addr){
    fprintf(fptr, "    ARP header\n");
    struct arp_header* arp_head = (struct arp_header*)malloc(sizeof(struct arp_header));
    memcpy(arp_head, addr, sizeof(struct arp_header));
    if(ntohs(arp_head->opcode) == 1) {
        fprintf(fptr, "        Opcode: Request\n");
    } else if(ntohs(arp_head->opcode) == 2) {
        fprintf(fptr, "        Opcode: Reply\n");
    } else {
        fprintf(fptr, "        Opcode: Unknown (0x%04x)\n", ntohs(arp_head->opcode));
    }
    fprintf(fptr, "\t\tSender MAC: %x:%x:%x:%x:%x:%x\n", arp_head->sender_mac[0], arp_head->sender_mac[1], arp_head->sender_mac[2], arp_head->sender_mac[3], arp_head->sender_mac[4], arp_head->sender_mac[5]);
    fprintf(fptr, "\t\tSender IP: %u.%u.%u.%u\n", (arp_head->sender_ip[0]), (arp_head->sender_ip[1]), (arp_head->sender_ip[2]), arp_head ->sender_ip[3]);
    fprintf(fptr, "\t\tTarget MAC: %x:%x:%x:%x:%x:%x\n", arp_head->target_mac[0], arp_head->target_mac[1], arp_head->target_mac[2], arp_head->target_mac[3], arp_head->target_mac[4], arp_head->target_mac[5]);
    fprintf(fptr, "\t\tTarget IP: %u.%u.%u.%u\n\n", (arp_head->target_ip[0]), (arp_head->target_ip[1]), (arp_head->target_ip[2]), arp_head ->target_ip[3]);
    free(arp_head);
    return; 
}


struct ethernet_header* get_ethernet_header(const unsigned char* data) {
    struct ethernet_header* eth_header = (struct ethernet_header*)malloc(sizeof(struct ethernet_header));
    memcpy(eth_header, data, sizeof(struct ethernet_header));
    fprintf(fptr, "\tEthernet Header\n");
    fprintf(fptr, "\t\tDest MAC: %x:%x:%x:%x:%x:%x\n", eth_header->dest[0], eth_header->dest[1], eth_header->dest[2], eth_header->dest[3], eth_header->dest[4], eth_header->dest[5]);
    fprintf(fptr, "\t\tSource MAC: %x:%x:%x:%x:%x:%x\n", eth_header->src[0], eth_header->src[1], eth_header->src[2], eth_header->src[3], eth_header->src[4], eth_header->src[5]);
    if(ntohs(eth_header->type) == 0x0800) {
        fprintf(fptr, "\t\tType: IP\n\n");
    } 
    else if(ntohs(eth_header->type) == 0x86DD) {
        fprintf(fptr, "\t\tType: IP\n\n");
    } 
    else if(ntohs(eth_header->type) == 0x0806) {
        fprintf(fptr, "\t\tType: ARP\n\n");
    } 
    else {
        fprintf(fptr, "\t\tType: 0x%04x\n\n", ntohs(eth_header->type));
    }
    return eth_header;
}


void parse_layer_2(const unsigned char* data, struct ethernet_header* eth_header) {
    switch(ntohs(eth_header->type)) {
        case 0x0800: // IPv4
            parse_IPV4( data + sizeof(struct ethernet_header));
            break;
        case 0x86DD: // IPv6
            printf("IPv6 packet detected\n");
            break;
        case 0x0806: // ARP
            parse_ARP(data + sizeof(struct ethernet_header));
            break;
        default:
            printf("Unknown Ethernet type: 0x%04x\n", ntohs(eth_header->type));
    }
    return; 
}





int main(int argc, char *argv[]) {
    struct pcap_pkthdr *garbage_data;
    const unsigned char* data;
    if(argc  < 2) {
        printf("no args provided\n");
        return 1;
    }
    pcap_t* file = open_pcap_file(argv[1]);
    fptr = fopen("output.txt", "w");
    struct ethernet_header* eth_header; 
    fprintf(fptr, "\n");
    int counter  = 1; 
    //iterate through packets 
    while(pcap_next_ex(file, &garbage_data, &data) == 1) {
        fprintf(fptr, "Packet number: %d  Packet Len: %d\n\n", counter, garbage_data->len);
        eth_header = get_ethernet_header(data);
        counter++; 
        parse_layer_2(data, eth_header);
        free(eth_header);
        fprintf(fptr, "\n");
    }
    pcap_close(file);
    fclose(fptr);
    return 0;
}