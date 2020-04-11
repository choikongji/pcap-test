#include <netinet/in.h>
#include <netinet/ether.h>

struct libnet_ethernet_hdr
{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
	u_int16_t ether_type;
};
#define ETHERTYPE_IP 0x0800

struct libnet_ipv4_hdr
{
u_int8_t ip_hl:4, ip_v:4; /* header length, version* LIBNET_LIL_ENDIAN*/
u_int8_t ip_tos;       /* type of service */
u_int16_t ip_len;         /* total lengtwh 2byte */
u_int16_t ip_id;          /* identification */
u_int16_t ip_off;
u_int8_t ip_ttl;          /* time to live */
u_int8_t ip_p;            /* protocol */
u_int16_t ip_sum;         /* checksum */
u_int8_t ip_src[4], ip_dst[4]; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t srcadd;       /* source port */
    u_int16_t dstadd;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,th_off:4; /*data offest* LIBNET_LIL_ENDIAN*/
    u_int8_t  th_flags; /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};
