#include "string.h"
#include "stdio.h"
#include "malloc.h"
#include "regex.h"

#define HAVE_REMOTE
#include "pcap.h"

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct ethernet_header {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);



#define BUFFER_SIZE 128

char *getMac(void);
char **extractMacs(char *result);
int isMacInAddresses(char *mac);
int isMacBroadcast(char *mac);
int isMacPrinted(char *mac);