#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <netinet/udp.h>

#include "dns-monitor.h"

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){

    arguments_t *arguments = (arguments_t *)args;

    char time_buffer[100];
    struct tm *tm_info;
    tm_info = localtime(&(header->ts.tv_sec));
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *)(packet);
    struct udphdr *udp_header;
    char ip_src[INET6_ADDRSTRLEN];
    char ip_dst[INET6_ADDRSTRLEN];
    int port_dst;
    int port_src;
    char dns_type[2];
    dns_header_t *dns_header;
    unsigned char *dns_data;

    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP){

        struct ip *ip_header;
        ip_header = (struct ip *)(packet + ETHERNET_LEN);
        inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), ip_dst, INET6_ADDRSTRLEN);

        if (ip_header->ip_p == IPPROTO_UDP){

            udp_header = (struct udphdr *)(packet + ETHERNET_LEN + ip_header->ip_hl * 4);
            port_dst = ntohs(udp_header->uh_dport);
            port_src = ntohs(udp_header->uh_sport);

            dns_header = (dns_header_t *)(packet + ETHERNET_LEN + ip_header->ip_hl * 4 + sizeof(struct udphdr));

            dns_header->flags = ntohs(dns_header->flags);
            dns_header->ancount = ntohs(dns_header->ancount);
            dns_header->arcount = ntohs(dns_header->arcount);
            dns_header->id = ntohs(dns_header->id);
            dns_header->nscount = ntohs(dns_header->nscount);
            dns_header->qdcount = ntohs(dns_header->qdcount);

            if ((dns_header->flags & DNS_TYPE_MASK) == DNS_TYPE_MASK){
                dns_type[0] = 'R';
            }
            else{
                dns_type[0] = 'Q';
            }

            dns_data = (unsigned char *)(packet + ETHERNET_LEN + ip_header->ip_hl * 4 + sizeof(struct udphdr) + sizeof(dns_header_t));

        }
        
    }
    else if (ntohs(ethernet_header->ether_type == ETHERTYPE_IPV6)){
        printf("ipv6\n");
    }
    else{
        exit(1);
    }

    if (arguments->verbose){
        uint16_t qr = (dns_header->flags >> 15) & 1;
        uint16_t opcode = (dns_header->flags >> 11) & 15;
        uint16_t aa = (dns_header->flags >> 10) & 1;
        uint16_t tc = (dns_header->flags >> 9) & 1;
        uint16_t rd = (dns_header->flags >> 8) & 1;
        uint16_t ra = (dns_header->flags >> 7) & 1;
        uint16_t ad = (dns_header->flags >> 5) & 1;
        uint16_t cd = (dns_header->flags >> 4) & 1;
        uint16_t rcode = dns_header->flags & 15;

        fprintf(stdout, "Timestamp: %s\n", time_buffer);
        fprintf(stdout, "SrcIP: %s\n", ip_src);
        fprintf(stdout, "DstIP: %s\n", ip_dst);
        fprintf(stdout, "SrcPort: UDP/%d\n", port_src);
        fprintf(stdout, "DestPort: UDP/%d\n", port_dst);
        fprintf(stdout, "Identifier: 0x%X\n", dns_header->id);
        fprintf(stdout, "Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n", qr, opcode, aa, tc, rd, ra, ad, cd, rcode);

        uint16_t data_len = 0;
        if (dns_header->qdcount > 0){
            for (int i = 0; i < dns_header->qdcount; i++){
                while (dns_data[data_len] != 0){
                    uint16_t segment_len = dns_data[data_len];
                    data_len++;

                    for (int j = 0; j < segment_len; j++){
                        fprintf(stdout, "%c", dns_data[data_len]);
                        data_len++;
                    }

                    if (dns_data[data_len] != 0){
                        fprintf(stdout, ".");
                    }

                }

                data_len++;

                uint16_t qtype = ntohs(*(uint16_t *)(dns_data + data_len));
                data_len += 2;

                switch (qtype) {
                    case 1: 
                        fprintf(stdout, " A");
                        break;
                    case 2:
                        fprintf(stdout, " NS");
                        break;
                    case 5:
                        fprintf(stdout, " CNAME");
                        break;
                    case 6:
                        fprintf(stdout, " SOA");
                        break;
                    case 15:
                        fprintf(stdout, " MX");
                        break;
                    case 28:
                        fprintf(stdout, " AAAA");
                        break;
                    case 33:
                        fprintf(stdout, " SRV");
                        break;
                    default:
                        fprintf(stdout, " UNKNOWN");
                }

                uint16_t qclass = ntohs(*(uint16_t *)(dns_data + data_len));
                data_len += 2;

                if (qclass == 1){
                    fprintf(stdout, " IN\n");
                }
                else{
                    fprintf(stdout, " UNKNOWN");
                }

            }
        }
        if (dns_header->ancount > 0){
            for (int i = 0; i < dns_header->ancount; i++){
                
            }
        }
        if (dns_header->nscount > 0){

        }
        if (dns_header->arcount > 0){

        }
    }
    else{
        fprintf(stdout, "%s %s->%s (%s %d/%d/%d/%d)\n", time_buffer, ip_src, ip_dst, dns_type, dns_header->qdcount, dns_header->ancount, dns_header->nscount, dns_header->arcount);


    }
    fprintf(stdout, "\n");
}

int main(int argc, char **argv){
    int opt;

    arguments_t arguments;
    memset(arguments.domains_file, 0, INPUT_LEN);
    memset(arguments.interface, 0, INPUT_LEN);
    memset(arguments.pcap_file, 0, INPUT_LEN);
    memset(arguments.translation_file, 0, INPUT_LEN);
    arguments.verbose = false;

    while((opt = getopt(argc, argv, "hi:r:vd:t:")) != -1){
        switch (opt){
            case 'h':
                fprintf(stdout, "how to use:\n./dns-monitor (-i interface | -r pcap file) [-v verbose output] [-d domains file] [-t translation file]\n");
                exit(0);
            case 'i':
                strncpy(arguments.interface, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.interface);
                break;
            case 'r':
                strncpy(arguments.pcap_file, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.pcap_file);
                break;
            case 'v':
                arguments.verbose = true;
                fprintf(stdout, "Verbose set to true\n");
                break;
            case 'd':
                strncpy(arguments.domains_file, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.domains_file);
                break;
            case 't':
                strncpy(arguments.translation_file, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.translation_file);
                break;
            default:
                exit(1);
        }
    }


    char errbuff[PCAP_ERRBUF_SIZE];

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    if (pcap_lookupnet(arguments.interface, &netp, &maskp, errbuff) == -1){
        fprintf(stderr, "Error: %s \n", errbuff);
        exit(1);
    }

    pcap_t *handle;
    handle = pcap_open_live(arguments.interface, BUFSIZ, 1, 1000, errbuff);
    if (handle == NULL){
        fprintf(stderr, "Interface couldnt be opened. Error: %s \n", errbuff);
        exit(1);
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp port 53", 1, netp) == -1){
        fprintf(stderr, "DNS port filter couldnt be compiled.\n");
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "DNS port filter coulndt be applyed.\n");
        exit(1);
    }

    pcap_loop(handle, 2, packet_handler, (unsigned char *)&arguments);

    pcap_close(handle);

    return 0;
}