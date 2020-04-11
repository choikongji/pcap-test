#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
using namespace std;
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

        if((ntohs(eh->ether_type) != ETHERTYPE_IP))continue;
        if(ipv4->ip_p != IPPROTO_TCP)continue;
        struct libnet_tcp_hdr *tcp; //tcp
        tcp= (struct libnet_tcp_hdr *)(packet + sizeof(libnet_ethernet_hdr)+ (ipv4->ip_hl)*4);
        printf("\n========Ethernet Header========\n");
        printf("Dst = %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_dhost[0],eh->ether_dhost[1],eh->ether_dhost[2],eh->ether_dhost[3],eh->ether_dhost[4],eh->ether_dhost[5]);
        printf("Src = %02x:%02x:%02x:%02x:%02x:%02x\n",
               eh->ether_shost[0],eh->ether_shost[1],eh->ether_shost[2],eh->ether_shost[3],eh->ether_shost[4],eh->ether_shost[5]);

        printf("\n======IPv4 Header=======\n");
        for(int i=0;i<=3;i++){
            printf("%d", ipv4->ip_src[i]);
            printf(".");
        }
        printf("\n");
        for(int i=0;i<=3;i++){
            printf("%d", ipv4->ip_dst[i]);
            printf(".");
        }

        printf("\n======TCP Header========\n");
        printf("Src : %d\n", ntohs(tcp->srcadd));
        printf("Dst : %d\n", ntohs(tcp->dstadd));

        //packet = packet + sizeof(libnet_ethernet_hdr) + ipv4->ip_hl*4 + tcp->th_off*4;
        int payload_len = ntohs(ipv4->ip_len) - ipv4->ip_hl*4 - tcp->th_off*4;
        int data= min(payload_len,16);
        for(int i=0;i<=data;i++){
            printf("%02x",payload_len);
        }
        pcap_close(handle);
    }

}
