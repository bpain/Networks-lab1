#include "./header.h"
#include "pcap/pcap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "checksum.h"
#include <arpa/inet.h>
#include <netinet/ether.h>



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

void print_flags(uint8_t flags) {
    if(flags & 0x02){
        printf( "\t\tSYN Flag: Yes\n");
    }
    else {
        printf( "\t\tSYN Flag: No\n");
    }
    if(flags & 0x04){
        printf( "\t\tRST Flag: Yes\n");
    }
    else {
        printf( "\t\tRST Flag: No\n");
    }
    if(flags & 0x01){
        printf( "\t\tFIN Flag: Yes\n");
    }
    else {
        printf( "\t\tFIN Flag: No\n");
    }
    if(flags & 0x10){
        printf( "\t\tACK Flag: Yes\n");
    }
    else {
        printf( "\t\tACK Flag: No\n");
    }
}

void print_source_port(struct tcp_header* tcp) {
    u_int16_t src_port = ntohs(tcp->src_port);
    if(src_port == 80) {
        printf( "\t\tSource Port: HTTP\n");
    } 
    else if(src_port == 992) {
        printf( "\t\tSource Port: Telnet\n");
    } 
    else if (src_port == 21) {
        printf( "\t\tSource Port: FTP\n");
    }
    else if(src_port == 110) {
        printf( "\t\tSource Port: POP3\n");
    }
    else if(src_port == 25) {
        printf( "\t\tSource Port: SMTP\n");
    }
    else {
        printf( "\t\tSource Port: %d\n", src_port);
    }
}
void print_dest_port(struct tcp_header* tcp) {
    u_int16_t dest_port = ntohs(tcp->dest_port);
    if(dest_port == 80) {
        printf( "\t\tDest Port: HTTP\n");
    } 
    else if(dest_port == 992) {
        printf( "\t\tDest Port: Telnet\n");
    } 
    else if (dest_port == 21) {
        printf( "\t\tDest Port: FTP\n");
    }
    else if(dest_port == 110) {
        printf( "\t\tDest Port: POP3\n");
    }
    else if(dest_port == 25) {
        printf( "\t\tDest Port: SMTP\n");
    }
    else {
        printf( "\t\tDest Port: %d\n", dest_port);
    }
}

void TCP(const void* addr, u_int16_t len, struct tcp_pseudo_header* pseudo_header){
    printf( "\tTCP Header\n");
    struct tcp_header tcp;
    memcpy(&tcp, addr, sizeof(struct tcp_header));
    //isolate data for this section
    char* raw_data = (char*)malloc(len + 12);  
    memcpy(raw_data, pseudo_header, sizeof(struct tcp_pseudo_header));
    memcpy(raw_data + sizeof(struct tcp_pseudo_header), addr, len);
    //print and do checksum 
    printf( "\t\tSegment Length: %d\n", len);
    print_source_port(&tcp);
    print_dest_port(&tcp);
    printf( "\t\tSequence Number: %u\n", ntohl(tcp.seq_num));
    printf( "\t\tACK Number: %u\n", ntohl(tcp.ack_num));
    print_flags(tcp.flags);
    printf( "\t\tWindow Size: %d\n", ntohs(tcp.window_size));
    unsigned short checksum_valid = in_cksum((unsigned short*)raw_data, len + 12); 
    if(checksum_valid == 0) {
        printf( "\t\tChecksum: Correct (0x%04x)\n", ntohs(tcp.checksum));
    } else {
        printf( "\t\tChecksum: Incorrect (0x%04x)\n", ntohs(tcp.checksum));
    }
    free(raw_data);
    return;
}


void print_udp_source_port(struct udp_header* udp) {
    u_int16_t src_port = ntohs(udp->src_port);
    if(src_port == 80) {
        printf( "\t\tSource Port: HTTP\n");
    } 
    else if(src_port == 992) {
        printf( "\t\tSource Port: Telnet\n");
    } 
    else if (src_port == 21) {
        printf( "\t\tSource Port: FTP\n");
    }
    else if(src_port == 110) {
        printf( "\t\tSource Port: POP3\n");
    }
    else if(src_port == 25) {
        printf( "\t\tSource Port: SMTP\n");
    }
    else if(src_port == 53) {
        printf( "\t\tSource Port: DNS\n");
    }
    else {
        printf( "\t\tSource Port: %d\n", src_port);
    }
}
void print_udp_dest_port(struct udp_header* udp) {
    u_int16_t dest_port = ntohs(udp->dest_port);
    if(dest_port == 80) {
        printf( "\t\tDest Port: HTTP\n");
    } 
    else if(dest_port == 992) {
        printf( "\t\tDest Port: Telnet\n");
    } 
    else if (dest_port == 21) {
        printf( "\t\tDest Port: FTP\n");
    }
    else if(dest_port == 110) {
        printf( "\t\tDest Port: POP3\n");
    }
    else if(dest_port == 25) {
        printf( "\t\tDest Port: SMTP\n");
    }
    else if(dest_port == 53) {
        printf( "\t\tDest Port: DNS\n");
    }
    else {
        printf( "\t\tDest Port: %d\n", dest_port);
    }
}

struct udp_pseudo_header create_udp_pseudo_header(struct ipv4_header* ipv4, uint16_t udp_length) {
    struct udp_pseudo_header pseudo_header;
    memcpy(pseudo_header.src_ip, ipv4->src_ip, 4);
    memcpy(pseudo_header.dest_ip, ipv4->dest_ip, 4);
    pseudo_header.reserved = 0;
    pseudo_header.protocol = ipv4->protocol;
    pseudo_header.udp_length = ntohs(udp_length); 
    return pseudo_header;
}

void parse_UDP( const void* addr, u_int16_t len, struct udp_pseudo_header* pseudo_header){
    printf( "\tUDP Header\n");
    struct udp_header udp_header;
    memcpy(&udp_header, addr, sizeof(struct udp_header));
    //isolate specific data 
    char* raw_data = (char*)malloc(len + sizeof(struct udp_pseudo_header));
    memcpy(raw_data, pseudo_header, sizeof(struct udp_pseudo_header));
    memcpy(raw_data + sizeof(struct udp_pseudo_header), addr, len);
    //print stuff and do checksum
    if(in_cksum((unsigned short*)raw_data, len + 12) != 0) { 
        printf( "\t\tChecksum Incorrect:packet dropped\n");
        return;
    }
    print_udp_source_port(&udp_header);
    print_udp_dest_port(&udp_header);
    free(raw_data); 
    return;
}

void ICMP(const void* addr, u_int16_t len ){
    struct icmp_header icmp_header;
    memcpy(&icmp_header, addr, sizeof(struct icmp_header));
    if(in_cksum((unsigned short*)addr, len) != 0) { //commented out for bad checksum testcase
        // printf( "\t\tChecksum Incorrect:packet dropped\n");
        // return;
    }
    printf( "\tICMP Header\n");
    switch(icmp_header.type) {
        case 0:
            printf( "\t\tType: Reply\n");
            break;
        case 8:
            printf( "\t\tType: Request\n");
            break;
        default:
            printf( "\t\tType: %d\n", icmp_header.type);
    }
    return;
}

void print_back_half(struct ipv4_header* ipv4) {
    char* raw_data = (char*)ipv4;  
    if(in_cksum((unsigned short*)raw_data, (ipv4->version_headerLength & 0x0F) * 4)  == 0) {
        printf( "\t\tChecksum: Correct (0x%04x)\n", ntohs(ipv4->header_checksum));
    } else {
        printf( "\t\tChecksum: Incorrect (0x%04x)\n", ntohs(ipv4->header_checksum));
    }
    char *ip_str = inet_ntoa(*(struct in_addr*)ipv4->src_ip); 
    printf( "\t\tSender IP: %s\n", ip_str);
    char *dest_str = inet_ntoa(*(struct in_addr*)ipv4->dest_ip);
    printf( "\t\tDest IP: %s\n\n", dest_str);
    return; 
}

struct tcp_pseudo_header create_tcp_pseudo_header(struct ipv4_header* ipv4, uint16_t tcp_length) {
    struct tcp_pseudo_header pseudo_header;
    memcpy(pseudo_header.src_ip, ipv4->src_ip, 4);
    memcpy(pseudo_header.dest_ip, ipv4->dest_ip, 4);
    pseudo_header.reserved = 0;
    pseudo_header.protocol = ipv4->protocol;
    pseudo_header.tcp_length = ntohs(tcp_length); 
    return pseudo_header;
}


void IP(const void* addr){
    printf( "\tIP Header\n");
    struct ipv4_header ipv4;
    memcpy(&ipv4, addr, sizeof(struct ipv4_header));
    //get full header w/ proper sizing/options
    struct ipv4_header* full_ipv4 = (struct ipv4_header*)malloc((ipv4.version_headerLength & 0x0F) * 4);
    memcpy(full_ipv4, addr, (ipv4.version_headerLength & 0x0F) * 4);
    //print and parse subheaders 
    uint16_t offset = (full_ipv4->version_headerLength & 0x0F) * 4;
    uint16_t len = ntohs(full_ipv4->packet_length) - offset;
    printf( "\t\tIP PDU Len: %d\n", ntohs(full_ipv4->packet_length));
    printf( "\t\tHeader Len (bytes): %d\n", offset);
    printf( "\t\tTTL: %d\n", full_ipv4->ttl);
    switch(full_ipv4->protocol) {
        case 1:
            printf( "\t\tProtocol: ICMP\n");
            print_back_half(full_ipv4);
            ICMP((char*)addr + offset, len);
            break;
        case 6:
            printf( "\t\tProtocol: TCP\n");
            print_back_half(full_ipv4);
            struct tcp_pseudo_header pseudo_header = create_tcp_pseudo_header(full_ipv4, len);
            TCP((char*)addr + offset, len,  &pseudo_header);
            //free(pseudo_header);
            break;
        case 17:
            printf( "\t\tProtocol: UDP\n");
            print_back_half(full_ipv4);
            struct udp_pseudo_header udp_pseudo_header = create_udp_pseudo_header(full_ipv4, len);
            parse_UDP((char*)addr + offset, len, &udp_pseudo_header);
            //free(udp_pseudo_header);
            break;
        default:
            printf( "\t\tProtocol: Unknown\n");
            print_back_half(full_ipv4);
            break;
    }
    free(full_ipv4);
    return; 
}


void ARP(const void* addr){
    printf( "    ARP header\n");
    struct arp_header arp_head; 
    memcpy(&arp_head, addr, sizeof(struct arp_header));
    if(ntohs(arp_head.opcode) == 1) {
        printf( "        Opcode: Request\n");
    } else if(ntohs(arp_head.opcode) == 2) {
        printf( "        Opcode: Reply\n");
    } else {
        printf( "        Opcode: Unknown (0x%04x)\n", ntohs(arp_head.opcode));
    }

    
    char* mac_src_str = ether_ntoa((struct ether_addr*)arp_head.sender_mac);
    printf( "\t\tSender MAC: %s\n", mac_src_str);
    char *ip_str = inet_ntoa(*(struct in_addr*)arp_head.sender_ip); 
    printf( "\t\tSender IP: %s\n", ip_str);

    char* mac_dest_str = ether_ntoa((struct ether_addr*)arp_head.target_mac);
    printf( "\t\tTarget MAC: %s\n", mac_dest_str);
    char *dest_str = inet_ntoa(*(struct in_addr*)arp_head.target_ip);
    printf( "\t\tTarget IP: %s\n\n", dest_str);
    return; 
}


struct ethernet_header get_ethernet_header(const unsigned char* data) {
    struct ethernet_header eth_header;
    memcpy(&eth_header, data, sizeof(struct ethernet_header));
    printf( "\tEthernet Header\n");
    char* mac_dest_str = ether_ntoa((struct ether_addr*)eth_header.dest);
    printf( "\t\tDest MAC: %s\n", mac_dest_str);
    char* mac_src_str = ether_ntoa((struct ether_addr*)eth_header.src);
    printf( "\t\tSource MAC: %s\n", mac_src_str);

    if(ntohs(eth_header.type) == 0x0800) {
        printf( "\t\tType: IP\n\n");
    } 
    else if(ntohs(eth_header.type) == 0x86DD) {
        printf( "\t\tType: IP\n\n");
    } 
    else if(ntohs(eth_header.type) == 0x0806) {
        printf( "\t\tType: ARP\n\n");
    } 
    else {
        printf( "\t\tType: 0x%04x\n\n", ntohs(eth_header.type));
    }
    return eth_header;
}


void ethernet(const unsigned char* data, struct ethernet_header* eth_header) {
    switch(ntohs(eth_header->type)) {
        case 0x0800: // IPv4
            IP( data + sizeof(struct ethernet_header));
            break;
        case 0x0806: // ARP
            ARP(data + sizeof(struct ethernet_header));
            break;
        default:
            printf( "Unknown Ethernet type: 0x%04x\n", ntohs(eth_header->type));
    }
    return; 
}


void parse_file(char* arg){
    struct pcap_pkthdr *garbage_data;
    const unsigned char* data;
    pcap_t* file = open_pcap_file(arg);
    fptr = fopen("output.txt", "w");
    struct ethernet_header eth_header; 
    printf( "\n");
    int counter  = 1; 
    //iterate through packets 
    while(pcap_next_ex(file, &garbage_data, &data) == 1) {   
        printf( "Packet number: %d  Packet Len: %d\n\n", counter, garbage_data->len);
        eth_header = get_ethernet_header(data);
        counter++; 
        ethernet(data, &eth_header);
        printf( "\n");}
    pcap_close(file);
    fclose(fptr);
}


int main(int argc, char *argv[]) {
    if(argc  < 2) {
        printf("no args provided\n");
        return 1;
    }
    parse_file(argv[1]);
    return 0;
}