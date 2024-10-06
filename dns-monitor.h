#define INPUT_LEN 64
#define DNS_TYPE_MASK 0x8000
#define ETHERNET_LEN 14
#define DNS_NAME_JUMP 0xC0

typedef struct arguments{
    char interface[INPUT_LEN];
    bool set_interface;
    char pcap_file[INPUT_LEN];
    bool set_pcap;
    bool verbose;
    char domains_file[INPUT_LEN];
    char translation_file[INPUT_LEN];
}arguments_t;

typedef struct dns_header{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}dns_header_t;
