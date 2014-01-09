#include <stdlib.h>
#include <pcap.h>

#include "devices.h"

device * determine_default_device()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char *s;
    char errbuf[PCAP_ERRBUF_SIZE+1];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
    }

    if ( (s = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr,"Error in pcap_lookupdev: %s\n",errbuf);
        return new device("eth0");
    }

    return new device(s);
}
 
