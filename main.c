#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arphdr {

    u_int16_t htype;
    u_int16_t ptype;
    u_char hlen;
    u_char plen;
    u_int16_t oper;
    u_char sha [6];
    u_char spa [4];
    u_char tha [6];
    u_char tpa [4];
}arphdr_t;

#define MAXBYTE2CAPTURE 2048

int main(void){

    pcap_t *handle;			/* Session handle */
    char *dev= "wlan0";			/* The device to sniff on */
    char errbuf[256];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *pkt_data;		/* The actual packet */
    int res;
    arphdr_t *arpheader = NULL;
    int i;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    while(1){
       res = pcap_next(handle, &header);
       if(res == NULL)
            continue;
       else {
            printf("Jacked a packet with length of [%d]\n", header.len);
            arpheader = (struct arphr *)(res+14);


            printf("sender MAC: ");
            for(i=0; i<6;i++)printf("%02x:", arpheader->sha[i]);
            printf("\nSender IP: ");
            for(i=0; i<4;i++)printf("%d.", arpheader->spa[i]);
            printf("\nTarget MAC: ");
            for(i=0; i<6;i++)printf("%02x:", arpheader->tha[i]);}


    }


}
