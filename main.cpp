#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdlib.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test eth0\n");
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }


        struct libnet_ethernet_hdr *eh; //ether_header
        eh = (struct libnet_ethernet_hdr *)packet;
        struct libnet_ipv4_hdr *ipv4; //ipv4
        ipv4 = (struct libnet_ipv4_hdr *)(packet + sizeof(libnet_ethernet_hdr));
        struct libnet_tcp_hdr *tcp; //tcp
        tcp= (struct libnet_tcp_hdr *)(packet + sizeof(libnet_ethernet_hdr)+ (ipv4->ip_hl)*4);

        if((ntohs(eh->ether_type) != ETHERTYPE_IP))continue;
        if(ipv4->ip_p != IPPROTO_TCP)continue;
        printf("\n========Ethernet Header========\n");
        printf("Dst = %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_dhost[0],eh->ether_dhost[1],eh->ether_dhost[2],eh->ether_dhost[3],eh->ether_dhost[4],eh->ether_dhost[5]);
        printf("Src = %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_shost[0],eh->ether_shost[1],eh->ether_shost[2],eh->ether_shost[3],eh->ether_shost[4],eh->ether_shost[5]);

        printf("\n======IPv4 Header=======\n");
        printf("Src : %d.%d.%d.%d\n", ipv4->ip_src[0],ipv4->ip_src[1],ipv4->ip_src[2],ipv4->ip_src[3]);
        printf("Dst : %d.%d.%d.%d\n", ipv4->ip_dst[0],ipv4->ip_dst[1],ipv4->ip_dst[2],ipv4->ip_dst[3]);


        printf("\n======TCP Header========\n");
        printf("Src : %d\n", ntohs(tcp->srcadd));
        printf("Dst : %d\n", ntohs(tcp->dstadd));

        int payload = ntohs(ipv4->ip_len)- ipv4->ip_hl*4- tcp->th_off*4;
        const unsigned char *data;
        data = packet + sizeof(libnet_ethernet_hdr)+ipv4->ip_hl*4 + tcp->th_off*4;

        if(payload>0){
            for(int i=0;i<=16;i++){
                printf("%02x\n", data[i]);
            }

        }

    }
        pcap_close(handle);

}
