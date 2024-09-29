#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "dns-monitor.h"

int main(int argc, char**argv){
    int opt;

    Arguments arguments;
    memset(arguments.domains_file, 0, INPUT_LEN);
    memset(arguments.interface, 0, INPUT_LEN);
    memset(arguments.pcap_file, 0, INPUT_LEN);
    memset(arguments.translation_file, 0, INPUT_LEN);
    arguments.verbose = false;

    while((opt = getopt(argc, argv, "i:r:vd:t:")) != -1){
        switch (opt){
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

    

    return 0;
}