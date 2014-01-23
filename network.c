#include "network.h"
#include "brand.h"


static char** selfMacAddresses;
static char* printedMacAddresses[100];
static int printedMacAddressesCounter = 0;


int main(int argc, char *argv[]) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];


    initializeMacToBrand();
    
    /* Retrieve the device list on the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    selfMacAddresses = extractMacs(getMac());
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    /* Open the device */
    if ( (adhandle= pcap_open(d->name,          // name of the device
                              65536,            // portion of the packet to capture
                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                              PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                              1000,             // read timeout
                              NULL,             // authentication on the remote machine
                              errbuf            // error buffer
                              ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nlistening on %s...\n", d->description);
    printf("Printing candidates:\n");

    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    i = 0;
    while (selfMacAddresses[i] != NULL) {
        free(selfMacAddresses[i]);
        i++;
    }
    free(selfMacAddresses);

    for (i = 0; i < printedMacAddressesCounter; i++) {
        free(printedMacAddresses[i]);
    }
    return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct ethernet_header *eh;

    char macDest[18]; // 2 * 6 + 5 separators
    char macSrc[18];

    eh = (struct ethernet_header*) pkt_data;

    sprintf(macDest, "%02X-%02X-%02X-%02X-%02X-%02X", 
        eh->ether_dhost[0],
        eh->ether_dhost[1],
        eh->ether_dhost[2], 
        eh->ether_dhost[3],
        eh->ether_dhost[4],
        eh->ether_dhost[5]);

    sprintf(macSrc, "%02X-%02X-%02X-%02X-%02X-%02X", 
        eh->ether_shost[0],
        eh->ether_shost[1],
        eh->ether_shost[2], 
        eh->ether_shost[3],
        eh->ether_shost[4],
        eh->ether_shost[5]);

    char* macBuffer;

    if (!isMacBroadcast(macDest) && !isMacInAddresses(macDest) && !isMacMulticast(macDest)
        && !isMacPrinted(macDest)) {
        macBuffer = (char *) malloc(strlen(macDest) + 1);
        strcpy(macBuffer, macDest);
        printedMacAddresses[printedMacAddressesCounter] = macBuffer;
        printedMacAddressesCounter++;
        printf("%s: %s\n", macDest, identifyBrand(macDest));
    }

    if (!isMacBroadcast(macSrc) && !isMacInAddresses(macSrc) && !isMacPrinted(macSrc)) {
        macBuffer = (char *) malloc(strlen(macSrc) + 1);
        strcpy(macBuffer, macSrc);
        printedMacAddresses[printedMacAddressesCounter] = macBuffer;
        printedMacAddressesCounter++;
        printf("%s: %s\n", macSrc, identifyBrand(macSrc));
    }
    
}

char *getMac(void) {
    FILE* pipe = popen("getmac", "r");
    if (!pipe) {
        return NULL;
    }
    char buffer[BUFFER_SIZE];

    char* result;
    char* temp;
    size_t string_size = 1;
    result = (char *) malloc(string_size);
    memset(result, 0, string_size);


    while (!feof(pipe)) {
        if (fgets(buffer, BUFFER_SIZE, pipe) != NULL) {
            temp = (char *)malloc(string_size + BUFFER_SIZE);
            memset(temp, 0, string_size + BUFFER_SIZE);
            memcpy(temp, result, string_size);
            strcat(temp, buffer);
            string_size = strlen(temp);
            result = temp;
        }
    }
    return result;
}

char** extractMacs (char *result) {

    char resultCopy[strlen(result) + 1];
    strcpy(resultCopy, result);

    char copyBuffer[strlen(result) + 1];
    memset(copyBuffer, 0, strlen(result) + 1);

    regex_t regex;
    int regex_result;
    char msgbuf[100];
    char match_string[] = "..-..-..-..-..-..";
    regmatch_t pmatch[1];
    size_t nmatch = 1;

    char* mac;
    char* macAddressBuffer[100];
    char** macAddresses;

    char printBuf[strlen(match_string) + 1];
    int i = 0;

    regex_result = regcomp(&regex, match_string, 0);

    memset(macAddressBuffer, 0, sizeof(macAddressBuffer));

    if( regex_result ){ fprintf(stderr, "Could not compile regex\n"); exit(1); }

    /* Execute regular expression */

    regex_result = regexec(&regex, resultCopy, nmatch, pmatch, 0);
    while ( !regex_result ){
            memcpy(printBuf, resultCopy + pmatch[0].rm_so, strlen(match_string));
            printBuf[strlen(match_string)] = 0;

            mac = (char *)malloc(strlen(match_string) + 1);
            memset(mac, 0, strlen(match_string) + 1);

            strcpy(mac, printBuf);
            macAddressBuffer[i] = mac;

            strcpy(copyBuffer, resultCopy + pmatch[0].rm_eo);
            strcpy(resultCopy, copyBuffer);
            regfree(&regex);
            regcomp(&regex, match_string, 0);

            regex_result = regexec(&regex, resultCopy, nmatch, pmatch, 0);
            ++i;
    }

    macAddresses = (char **)malloc(i + 2);
    memset(macAddresses, 0, i + 2);
    macAddresses[i + 1] = NULL;
    for (i; i >= 0; i--) {
        macAddresses[i] = macAddressBuffer[i];
    }

    if( regex_result == REG_NOMATCH ){
    }
    else{
            regerror(regex_result, &regex, msgbuf, sizeof(msgbuf));
            fprintf(stderr, "Regex match failed: %s\n", msgbuf);
            exit(1);
    }
    /* Free compiled regular expression if you want to use the regex_t again */

    regfree(&regex);

    return macAddresses;
}


int isMacInAddresses(char *mac) {

    int i = 0;
    char *currentMac = selfMacAddresses[i];

    while (currentMac != NULL) {
        if (strcmp(mac, currentMac) == 0) {
            return 1;
        }
        i++;
        currentMac = selfMacAddresses[i];
    }
    
    return 0;
}


int isMacBroadcast(char *mac) {

    char broadcastMac[] = "FF-FF-FF-FF-FF-FF";

    if (strcmp(mac, broadcastMac) == 0) {
        return 1;
    }    
    return 0;
}

int isMacMulticast(char *mac) {

    /*

    Multicast addresses taken from http://en.wikipedia.org/wiki/Multicast_address

    */
    char multicastCDP[] = "01-00-0C-CC-CC-CC";

    char multicastCiscoSharedSpanningTree[] = "01-00-0C-CC-CC-CD";
    char multicastSpanningTreeProtocol[] = "01-80-C2-00-00-00";

    // Link Layer Discovery Protocol
    char multicastLLDP1[] = "01-80-C2-00-00-03";
    char multicastLLDP2[] = "01-80-C2-00-00-0E";
    char multicastLLDP3[] = "01-80-C2-00-00-08";

    // Ethernet OAM Protocol
    char multicastEthernetOAMProtocol[] = "01-80-C2-00-00-02";

    // IPv4 Multicast
    char multicastIP4[] = "01-00-5E-xx-xx-xx";


    // IPv6 Multicast
    char multicastIP6[] = "33-33-xx-xx-xx-xx";

    if (strcmp(mac, multicastCDP) == 0) {
        return 1;
    } else if (strcmp(mac, multicastCiscoSharedSpanningTree) == 0) {
        return 1;
    } else if (strcmp(mac, multicastSpanningTreeProtocol) == 0) {
        return 1;
    } else if (strcmp(mac, multicastLLDP1) == 0) {
        return 1;
    } else if (strcmp(mac, multicastLLDP2) == 0) {
        return 1;
    } else if (strcmp(mac, multicastLLDP3) == 0) {
        return 1;
    } else if (strcmp(mac, multicastEthernetOAMProtocol) == 0) {
        return 1;
    } else if (strncmp(mac, multicastIP4, 9) == 0) {
        return 1;
    } else if (strncmp(mac, multicastIP6, 6) == 0) {
        return 1;
    } else {
        return 0;
    }
}

int isMacPrinted(char *mac) {
    int i = 0;
    for (i = 0; i < printedMacAddressesCounter; i++) {
        if (strcmp(mac, printedMacAddresses[i]) == 0) {
            return 1;
        }
    }
    return 0;
}
