#define INPUT_LEN 64

typedef struct arguments{
    char interface[INPUT_LEN];
    char pcap_file[INPUT_LEN];
    bool verbose;
    char domains_file[INPUT_LEN];
    char translation_file[INPUT_LEN];
}Arguments;
