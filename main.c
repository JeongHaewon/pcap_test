#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

typedef struct ether_header
{
    u_char dmac[6];
    u_char smac[6];
    uint16_t type;
}ethhdr_t;

typedef struct ip_header
{
    u_char vsnhdrl[1];
    uint8_t difsrv;
    uint16_t tlen;
    uint16_t identification;
    uint16_t frgoffset;
    uint8_t ttlive;
    uint8_t protocol;
    uint16_t hdrcsum;
    uint32_t sip;
    uint32_t dip;
}iphdr_t;

typedef struct tcp_header
{
    uint16_t sport;
    uint16_t dport;
    uint32_t sqnum;
    uint32_t acknum;
    u_char hdrl[1];
}tcphdr_t;

int main(int arvc,char* argv[])
{
    int snaplen;
    int promisc;
    int to_ms;
    char errbuf[256];
    ethhdr_t *ethheader = NULL;
    iphdr_t *ipheader = NULL;
    tcphdr_t *tcpheader = NULL;

    struct pcap_pkthdr pkthdr;
    const u_char pkt_data;
    const u_char *payload;

    pcap_t *handle;
    handle = pcap_open_live("ens33", snaplen, promisc, to_ms, errbuf);
    /*    if (pcap_open_live == NULL);
    {
        printf("Couldn't open device %s: %s\n", "ens33", errbuf);
        return 0;
    }
*/
    int number, i;
    while(1){
        number = pcap_next_ex(handle, &pkthdr, &pkt_data);
        if(number == 0, 1);
        {
            ethheader = (struct ethhdr_t *)(pkt_data);
            ipheader = (struct iphdr_t *)(pkt_data+14);
            //  int iplen;
            //  iplen = ipheader->vsnhdrl
            tcpheader = (struct tcphdr_t *)(pkt_data+14+20);

            if(ntohs(ethheader->type) == 0x0800);
            {
                printf("Packet Lengh is: %d\n", pkthdr.len);
                printf("Destination MAC: %s\n", ntohl(ethheader->dmac));
                printf("Source MAC: %s\n", ntohl(ethheader->smac));
                printf("\n");
                printf("Source IP: %d\n", ntohl(ipheader->sip));
                printf("Destination IP: %d\n", ntohl(ipheader->dip));
                printf("\n");
                printf("Source port: %d\n", ntohs(tcpheader->sport));
                printf("Destination port: %d\n", ntohs(tcpheader->dport));

                payload = (u_char *)(pkt_data+14+20+20);
                printf(payload);
                printf("\n-------------------------------------------------\n");
            }
        }
    }
    return 0;
}
