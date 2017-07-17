#include <pcap.h>
#include <stdlib.h>
#include <string.h>

typedef struct arphdr{

    u_char dmac [6];
    u_char smac [6];

}arphdr_t;

typedef struct iphdr{

    u_char sip [4];
    u_char dip [4];

}iphdr_t;

typedef struct tcphdr{

    u_char sport [2];
    u_char dport [2];

}tcphdr_t;

int main(void){

    pcap_t *handle;			/* Session handle */
    char *dev= "wlan0";			/* The device to sniff on */
    char errbuf[256];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 80";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *pkt_data;		/* The actual packet */
    int res;
    int i;
    arphdr_t *arpheader = NULL;
    iphdr_t *ipheader = NULL;
    tcphdr_t *tcpheader = NULL;
    const char *payload;

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
       res = pcap_next_ex(handle, &header, &pkt_data);

       if(res == 0 || pkt_data == NULL)
            continue;
       else {
            printf("Jacked a packet with length of [%d]\n", (*header).len);
            arpheader = (struct arphr *)(pkt_data);
            ipheader = (struct iphdr *)(pkt_data+26);
            tcpheader = (struct tcphdr *)(pkt_data+34);


            printf("Destination MAC: ");
            for(i=0; i<6;i++)printf("%02x:", arpheader->dmac[i]);
            printf("\nSource MAC: ");
            for(i=0; i<6;i++)printf("%02x:", arpheader->smac[i]);

            printf("\nSource IP: ");
            for(i=0; i<4;i++)printf("%d.", ipheader->sip[i]);
            printf("\nDestination IP: ");
            for(i=0; i<4; i++)printf("%d.", ipheader->dip[i]);

            printf("\nSender TCP Port: ");
            for(i=0; i<2; i++)printf("%d", tcpheader->sport[i]);
            printf("\nTarget TCP Port: ");
            for(i=0; i<2; i++)printf("%d", tcpheader->dport[i]);


            printf("\n\nData: ");
            payload = (u_char *)(pkt_data+54);
            printf(payload);
            printf("\n====================================================\n");


       }


    }
return 0;

}
