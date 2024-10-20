/*
 * login: xpalen06
 * ISA project: DNS Monitor
*/

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
#include <signal.h>

#include "dns-monitor.h"

// global declaration of variable, which needs to be handled when interrupt comes
pcap_t *handle;

void signal_handler(int sig){
    if (handle != NULL && (sig == SIGINT || sig == SIGTERM || sig == SIGQUIT)){
        pcap_close(handle);
    }

    fprintf(stderr, "\nINTERRUPTED - shutting down\n");
    exit(1);
}


// function for finding entry in  file
bool find_in_file(char *file_name, char *domain_name){
    FILE *file = fopen(file_name, "r");
    if (file == NULL){
        return false;
    }

    char file_line[NAME_LENGTH];
    while(fgets(file_line, NAME_LENGTH, file) != NULL){
        file_line[strcspn(file_line, "\n")] = '\0';

        if (strncmp(file_line, domain_name, NAME_LENGTH) == 0){
            fclose(file);
            return true;
        }
    }

    fclose(file);
    return false;
}

// function for adding entry
void append_file(char *file_name, char *string){
    FILE *file = fopen(file_name, "a");
    if (file == NULL){
        fprintf(stderr, "Error: file couldtn be opened\n");

        pcap_close(handle);

        exit(1);
    }

    fprintf(file, "%s\n", string);
    fclose(file);
}


// function for parsing name segment from dns packet 
uint16_t dns_name_parse(unsigned char *dns_data, uint16_t data_len, arguments_t *arguments, char *domain_name){
    // variables for compression jump
    bool jumped = false;
    uint16_t jump_backup;

    // length of domain name
    uint16_t domain_len = 0;

    // while there is some segment to be parsed
    while (dns_data[data_len] != 0){
        uint16_t segment_len = dns_data[data_len];

        // chcek if there will be jump to another part of packet - segment value is 0xC0
        if ((segment_len & DNS_NAME_JUMP) == DNS_NAME_JUMP){
            // calculate where to jump
            uint16_t jump_target = ((dns_data[data_len] & 0x3F) << 8) | dns_data[data_len + 1];

            // if not yet jumped, save the current address
            if (!jumped){
                jumped = true;
                jump_backup = data_len + 2;
            }

            // overwrite current address
            data_len = jump_target - sizeof(dns_header_t);
        }

        // no jump needed
        else{
            data_len++;

            // print the whole segment and store it in array
            for (int j = 0; j < segment_len; j++){
                fprintf(stdout, "%c", dns_data[data_len]);
                domain_name[domain_len] = dns_data[data_len];
                domain_len++;
                data_len++;
            }

            // when there is another segment, print .
            if (dns_data[data_len] != 0){
                fprintf(stdout, ".");
                domain_name[domain_len] = '.';
                domain_len++;
            }
        }

    }

    // if name needs to be written in file, find if it is already there and if not, append the file with it
    if (arguments->set_domains){
        domain_name[domain_len] = '\0';

        if (!find_in_file(arguments->domains_file, domain_name)){
            append_file(arguments->domains_file, domain_name);
        }

    }

    // restore original address if needed
    if (jumped){
        data_len = jump_backup;
        jumped = false;
    }

    return data_len;
}


// function for printig ANSWER, AUTHORITY and ADDITIONAL parts of dns packet 
uint16_t dns_printout(unsigned char *dns_data, uint16_t data_len, arguments_t *arguments, bool is_answer){

    // array for domain name for writing in file
    char domain_name[NAME_LENGTH];

    // parse the domain name
    data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);

    // extract type
    uint16_t type = ntohs(*(uint16_t *)(dns_data + data_len));
    data_len += 2;

    // extract class
    uint16_t class = ntohs(*(uint16_t *)(dns_data + data_len));
    data_len += 2;

    // extract time to live
    uint32_t ttl = ntohl(*(uint32_t *)(dns_data + data_len));
    data_len += 4;

    // extract length of data
    uint16_t rdlength = ntohs(*(uint16_t *)(dns_data + data_len));
    data_len += 2;

    // print time to live
    fprintf(stdout, " %d ", ttl);


    // print IN as internet or UNKNOWN for other class
    if (class == 1){
        fprintf(stdout, "IN ");
    }
    else{
        fprintf(stdout, "UNKNOWN ");
    }

    // pointer to start of data
    unsigned char *dns_addr = &dns_data[data_len];


    // if type is A as ipv4 address
    if (type == 1) { 
        // extract the address
        char rdata[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, dns_addr, rdata, INET_ADDRSTRLEN);

        // print the address
        fprintf(stdout, "A %s\n", rdata);

        // if translations file is needed, find if domain name and ip address is alreaady in the file. If not, add it there
        if (arguments->set_translations && is_answer){
            char translation[NAME_LENGTH + INET_ADDRSTRLEN + 1];
            snprintf(translation, NAME_LENGTH + INET_ADDRSTRLEN + 1,"%s %s", domain_name, rdata);

            if (!find_in_file(arguments->translation_file, translation)){
                append_file(arguments->translation_file, translation);
            }
        }

        // add lenght of the data
        data_len += rdlength;

    } 

    // if type is NS
    else if (type == 2){
        fprintf(stdout, "NS ");

        // print name server and dont print it in file
        bool set_domain_copy = arguments->set_domains;
        arguments->set_domains = false;
        data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);
        
        arguments->set_domains = set_domain_copy;

        fprintf(stdout, "\n");
    }

    // if type is CNAME
    else if (type == 5){
        fprintf(stdout, "CNAME ");

        data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);

        fprintf(stdout, "\n");
    }

    // if type is SOA
    else if (type == 6){
        fprintf(stdout, "SOA ");

        // print primary name server and dont print it in file
        bool set_domain_copy = arguments->set_domains;
        arguments->set_domains = false;
        data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);
        fprintf(stdout, " ");

        // print primary email of responsible person and dont print it in file
        data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);

        arguments->set_domains = set_domain_copy;

        // extract serial number
        uint32_t serial_number = ntohl(*(uint32_t *)(dns_data + data_len));
        data_len += 4;

        // extract refresh
        uint32_t refresh = ntohl(*(uint32_t *)(dns_data + data_len));
        data_len += 4;

        // extract retry
        uint32_t retry = ntohl(*(uint32_t *)(dns_data + data_len));
        data_len += 4;

        // extract expire
        uint32_t expire = ntohl(*(uint32_t *)(dns_data + data_len));
        data_len += 4;

        // extract minimum ttl
        uint32_t minimum_ttl = ntohl(*(uint32_t *)(dns_data + data_len));
        data_len += 4;

        fprintf(stdout, " %d %d %d %d %d\n", serial_number, refresh, retry, expire, minimum_ttl);
    }

    // if type is MX
    else if (type == 15){
        
        // extract priority
        uint16_t priority = ntohs(*(uint16_t *)(dns_data + data_len));
        data_len += 2;
        
        fprintf(stdout, "MX %d ", priority);

        // print mail server and dont print it in file
        bool set_domain_copy = arguments->set_domains;
        arguments->set_domains = false;
        data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);
        arguments->set_domains = set_domain_copy;

        fprintf(stdout, "\n");
    }

    // if type is AAAA as ipv6 address
    else if (type == 28) { 
        // extract the address
        char rdata[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, dns_addr, rdata, INET6_ADDRSTRLEN);

        // print the address
        fprintf(stdout, "AAAA %s\n", rdata);

        // if translations file is needed, find if domain name and ip address is alreaady in the file. If not, add it there
        if (arguments->set_translations && is_answer){
            char translation[NAME_LENGTH + INET6_ADDRSTRLEN + 1];
            snprintf(translation, NAME_LENGTH + INET6_ADDRSTRLEN + 1, "%s %s", domain_name, rdata);

            if (!find_in_file(arguments->translation_file, translation)){
                append_file(arguments->translation_file, translation);
            }
        }

        // add lenght of the data
        data_len += rdlength;
    }

    // if type is SRV
    else if (type == 33){

        // extract priority
        uint16_t priority = ntohs(*(uint16_t *)(dns_data + data_len));
        data_len += 2;

        // extract weight
        uint16_t weight = ntohs(*(uint16_t *)(dns_data + data_len));
        data_len += 2;

        // extract priority
        uint16_t port = ntohs(*(uint16_t *)(dns_data + data_len));
        data_len += 2;

        fprintf(stdout, "SRV %d %d %d ", priority, weight, port);

        // print server and dont print it in file
        bool set_domain_copy = arguments->set_domains;
        arguments->set_domains = false;
        data_len = dns_name_parse(dns_data, data_len, arguments, domain_name);
        arguments->set_domains = set_domain_copy;

        fprintf(stdout, "\n");
    }

    

    return data_len;
}


// pcap function for handling captured packets
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){

    // user given arguments
    arguments_t *arguments = (arguments_t *)args;

    // find the time of packet capture
    char time_buffer[100];
    struct tm *tm_info;
    tm_info = localtime(&(header->ts.tv_sec));
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    // extract ethernet header from packet, only needed for type of next header
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header *)(packet);

    // variable for udp header
    struct udphdr *udp_header;

    // variables for source/destination ip addresses
    char ip_src[INET6_ADDRSTRLEN];
    char ip_dst[INET6_ADDRSTRLEN];

    // variables for source/destination ports
    int port_dst;
    int port_src;
    char dns_type;

    // variable for dns header
    dns_header_t *dns_header;
    unsigned char *dns_data;

    // if packet is ipv4
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP){

        // extract the source and destination addresses
        struct ip *ip_header;
        ip_header = (struct ip *)(packet + ETHERNET_LEN);
        inet_ntop(AF_INET, &(ip_header->ip_src.s_addr), ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst.s_addr), ip_dst, INET6_ADDRSTRLEN);

        if (ip_header->ip_p == IPPROTO_UDP){

            // extract source and destination ports
            udp_header = (struct udphdr *)(packet + ETHERNET_LEN + ip_header->ip_hl * 4);
            port_dst = ntohs(udp_header->uh_dport);
            port_src = ntohs(udp_header->uh_sport);

            // extract the dns header
            dns_header = (dns_header_t *)(packet + ETHERNET_LEN + ip_header->ip_hl * 4 + sizeof(struct udphdr));

            // change the byte order
            dns_header->flags = ntohs(dns_header->flags);
            dns_header->ancount = ntohs(dns_header->ancount);
            dns_header->arcount = ntohs(dns_header->arcount);
            dns_header->id = ntohs(dns_header->id);
            dns_header->nscount = ntohs(dns_header->nscount);
            dns_header->qdcount = ntohs(dns_header->qdcount);

            // find the type of dns message - Response or Question
            if ((dns_header->flags & DNS_TYPE_MASK) == DNS_TYPE_MASK){
                dns_type = 'R';
            }
            else{
                dns_type = 'Q';
            }

            // pointer which points after the dns header 
            dns_data = (unsigned char *)(packet + ETHERNET_LEN + ip_header->ip_hl * 4 + sizeof(struct udphdr) + sizeof(dns_header_t));

        }
        
    }

    else{
        pcap_close(handle);

        fprintf(stderr, "Error: Unsupported packet found\n");

        exit(1);
    }

    // full printout of packet
    if (arguments->verbose){
        // extract individual flags
        uint16_t qr = (dns_header->flags >> 15) & 1;
        uint16_t opcode = (dns_header->flags >> 11) & 15;
        uint16_t aa = (dns_header->flags >> 10) & 1;
        uint16_t tc = (dns_header->flags >> 9) & 1;
        uint16_t rd = (dns_header->flags >> 8) & 1;
        uint16_t ra = (dns_header->flags >> 7) & 1;
        uint16_t ad = (dns_header->flags >> 5) & 1;
        uint16_t cd = (dns_header->flags >> 4) & 1;
        uint16_t rcode = dns_header->flags & 15;

        // print data already extracted
        fprintf(stdout, "Timestamp: %s\n", time_buffer);
        fprintf(stdout, "SrcIP: %s\n", ip_src);
        fprintf(stdout, "DstIP: %s\n", ip_dst);
        fprintf(stdout, "SrcPort: UDP/%d\n", port_src);
        fprintf(stdout, "DestPort: UDP/%d\n", port_dst);
        fprintf(stdout, "Identifier: 0x%X\n", dns_header->id);
        fprintf(stdout, "Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n\n", qr, opcode, aa, tc, rd, ra, ad, cd, rcode);

        // variable to store the offset from dns_data pointer
        uint16_t data_len = 0;

        // print all question records
        if (dns_header->qdcount > 0){
            fprintf(stdout, "[Question Section]\n\n");

            for (int i = 0; i < dns_header->qdcount; i++){

                // variable for domain name
                char domain_name[NAME_LENGTH];
                uint16_t domain_len = 0;

                // while there is segment for printou, print it
                while (dns_data[data_len] != 0){
                    uint16_t segment_len = dns_data[data_len];
                    data_len++;

                    for (int j = 0; j < segment_len; j++){
                        fprintf(stdout, "%c", dns_data[data_len]);
                        domain_name[domain_len] = dns_data[data_len];
                        data_len++;
                        domain_len++;
                    }

                    // if there is still segment, print .
                    if (dns_data[data_len] != 0){
                        fprintf(stdout, ".");
                        domain_name[domain_len] = '.';
                        domain_len++;
                    }

                }

                // if name needs to be written in file, find if it is already there and if not, append the file with it
                if (arguments->set_domains){
                    domain_name[domain_len] = '\0';

                    if (!find_in_file(arguments->domains_file, domain_name)){
                        append_file(arguments->domains_file, domain_name);
                    }

                }

                data_len++;

                // extract question type
                uint16_t qtype = ntohs(*(uint16_t *)(dns_data + data_len));
                data_len += 2;

                // extract question class
                uint16_t qclass = ntohs(*(uint16_t *)(dns_data + data_len));
                data_len += 2;

                // printout for different qclass types
                if (qclass == 1){
                    fprintf(stdout, " IN ");
                }
                else{
                    fprintf(stdout, " UNKNOWN ");
                }

                // printout for different qtype types
                switch (qtype) {
                    case 1: 
                        fprintf(stdout, "A\n");
                        break;
                    case 2:
                        fprintf(stdout, "NS\n");
                        break;
                    case 5:
                        fprintf(stdout, "CNAME\n");
                        break;
                    case 6:
                        fprintf(stdout, "SOA\n");
                        break;
                    case 15:
                        fprintf(stdout, "MX\n");
                        break;
                    case 28:
                        fprintf(stdout, "AAAA\n");
                        break;
                    case 33:
                        fprintf(stdout, "SRV\n");
                        break;
                    default:
                        fprintf(stdout, "UNKNOWN\n");
                }


                
            fprintf(stdout, "\n");
            }
        }

        // print all answer records
        if (dns_header->ancount > 0){

            fprintf(stdout, "[Answer Section]\n\n");

            for (int i = 0; i < dns_header->ancount; i++){
                data_len = dns_printout(dns_data, data_len, arguments, true);
            }

            fprintf(stdout, "\n");
        }

        // print all authority records
        if (dns_header->nscount > 0){

            fprintf(stdout, "[Authority Section]\n\n");

            for (int i = 0; i < dns_header->nscount; i++){
                data_len = dns_printout(dns_data, data_len, arguments, false);
            }

            fprintf(stdout, "\n");

        }

        // print all additional records
        if (dns_header->arcount > 1){

            fprintf(stdout, "[Additional Section]\n\n");

            for (int i = 0; i < dns_header->arcount - 1; i++){
                data_len = dns_printout(dns_data, data_len, arguments, false);
            }

            fprintf(stdout, "\n");
        }
    }

    // standard printout
    else{
        fprintf(stdout, "%s %s->%s (%c %d/%d/%d/%d)\n\n", time_buffer, ip_src, ip_dst, dns_type, dns_header->qdcount, dns_header->ancount, dns_header->nscount, dns_header->arcount);


    }
}

int main(int argc, char **argv){

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    // variable for getopt function
    int opt;

    // initialization of arguments variable
    arguments_t arguments;
    memset(arguments.domains_file, 0, INPUT_LEN);
    memset(arguments.interface, 0, INPUT_LEN);
    memset(arguments.pcap_file, 0, INPUT_LEN);
    memset(arguments.translation_file, 0, INPUT_LEN);
    arguments.verbose = false;
    arguments.set_interface = false;
    arguments.set_pcap = false;
    arguments.set_domains = false;
    arguments.set_translations = false;

    // findig all user given switches
    while((opt = getopt(argc, argv, "hi:p:vd:t:")) != -1){
        switch (opt){
            case 'h':
                fprintf(stdout, "how to use:\n./dns-monitor (-i interface | -r pcap file) [-v verbose output] [-d domains file] [-t translation file]\n");
                exit(0);
            case 'i':
                strncpy(arguments.interface, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.interface);
                arguments.set_interface = true;
                break;
            case 'p':
                strncpy(arguments.pcap_file, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.pcap_file);
                arguments.set_pcap = true;
                break;
            case 'v':
                arguments.verbose = true;
                fprintf(stdout, "Verbose set to true\n");
                break;
            case 'd':
                strncpy(arguments.domains_file, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.domains_file);
                arguments.set_domains = true;
                break;
            case 't':
                strncpy(arguments.translation_file, optarg, INPUT_LEN);
                fprintf(stdout, "%s\n", arguments.translation_file);
                arguments.set_translations = true;
                break;
            default:
                fprintf(stderr, "Error: wrong use of parameters\n");
                exit(1);
        }
    }
    

    // variables for pcap functions
    char errbuff[PCAP_ERRBUF_SIZE];

    bpf_u_int32 netp = 0;
    bpf_u_int32 maskp = 0;
    
    
    // ono interface given
    if (!arguments.set_interface && !arguments.set_pcap){
        fprintf(stdout, "how to use:\n./dns-monitor (-i interface | -r pcap file) [-v verbose output] [-d domains file] [-t translation file]\n");
        exit(0);
    }

    // interface is pcap file
    else if (!arguments.set_interface && arguments.set_pcap){
        handle = pcap_open_offline(arguments.pcap_file, errbuff);
        if (handle == NULL){
            fprintf(stderr, "Pcap file couldnt be opeded. Error: %s \n", errbuff);
            exit(1);
        }
    }

    // interface is network interface
    else if (arguments.set_interface && !arguments.set_pcap){
        if (pcap_lookupnet(arguments.interface, &netp, &maskp, errbuff) == -1){
            fprintf(stderr, "Error: %s \n", errbuff);
            exit(1);
        }

        handle = pcap_open_live(arguments.interface, BUFSIZ, 1, 1000, errbuff);
        if (handle == NULL){
            fprintf(stderr, "Interface couldnt be opened. Error: %s \n", errbuff);
            exit(1);
        }

    }

    // only one interface can be given
    else{
        fprintf(stderr, "Error: Cannot sniff on interface and read pcap file at the same time\n");
        exit(1);
    }


    

    // create an use filter for filtering only dns packets
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "udp port 53", 1, netp) == -1){
        fprintf(stderr, "DNS port filter couldnt be compiled.\n");
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "DNS port filter coulndt be applyed.\n");
        exit(1);
    }

    // pcap function for capturing packets
    pcap_loop(handle, 0, packet_handler, (unsigned char *)&arguments);

    // close interface
    pcap_close(handle);

    return 0;
}
