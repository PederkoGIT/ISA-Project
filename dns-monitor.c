#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include "dns-monitor.h"

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
    fprintf(stdout, "dns packet found\n");
}

int main(int argc, char **argv){
    int opt;

    Arguments arguments;
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
    }

    pcap_t *handle;
    handle = pcap_open_live(arguments.interface, BUFSIZ, 1, 1000, errbuff);
    if (handle == NULL){
        fprintf(stderr, "Interface couldnt be opened. Error: %s \n", errbuff);
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "port 53", 1, netp) == -1){
        fprintf(stderr, "DNS port filter couldnt be compiled.\n");
    }

    if (pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "DNS port filter coulndt be applyed.\n");
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}