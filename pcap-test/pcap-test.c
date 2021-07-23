// https://gitlab.com/gilgil/sns/-/wikis/osi-and-tcp/osi-and-tcp
// https://gitlab.com/gilgil/sns/-/wikis/basic-header-analysis/basic-header-analysis
// https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/pcap-programming
// https://gitlab.com/gilgil/sns/-/wikis/pcap-programming/report-pcap-test

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>     // apt install libnet-deb
#include <netinet/in.h>
#include <unistd.h>     // sleep

#define ETHERNET_HEADER_LEN 14
#define PAYLOAD_PRINTING_BYTE 8
#define MAC_BYTE 6
#define IPv4_BYTE 4
#define PORT_BYTE 2
#define ETHERNET_FOOTER_BYTE 16

void usage() {
	printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

struct payload
{
    uint8_t data[PAYLOAD_PRINTING_BYTE];
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool Is_footer(const u_char* packet, struct pcap_pkthdr* header, u_int ip_size, u_int tcp_size){
    for (unsigned int i = 0; i < header->caplen - tcp_size - ip_size - ETHERNET_HEADER_LEN; i++){
        if (i == ETHERNET_FOOTER_BYTE)
            return true;
        if(packet[i])
            return false;
    }
    return true;
}

void print_the_result(struct libnet_ethernet_hdr *L2_hdr, struct libnet_tcp_hdr *L4_hdr, struct payload *L5_to_L7, struct pcap_pkthdr *header,
                      u_int ip_size, u_int tcp_size, u_int8_t *ip_src_into_8bit_array, u_int8_t* ip_dst_into_8bit_array, bool print_payload){
    printf("============printing starts============\n");
    printf("src_mac: ");
    for (int i = 0; i < MAC_BYTE; i++){
        if (i == MAC_BYTE - 1){
            printf("%02x\n", L2_hdr->ether_shost[i]);
            break;
        }
        printf("%02x:", L2_hdr->ether_shost[i]);
    }
    printf("dst_mac: ");
    for (int i = 0; i < MAC_BYTE; i++){
        if (i == MAC_BYTE - 1){
            printf("%02x\n", L2_hdr->ether_dhost[i]);
            break;
        }
        printf("%02x:", L2_hdr->ether_dhost[i]);
    }
    printf("\n");

    printf("src_ip: ");
    for (int i = 0; i < IPv4_BYTE; i++){
        if (i == IPv4_BYTE - 1){
            printf("%u\n", ip_src_into_8bit_array[i]);
            break;
        }
        printf("%u.", ip_src_into_8bit_array[i]);
    }
    printf("dst_ip: ");
    for (int i = 0; i < IPv4_BYTE; i++){
        if (i == IPv4_BYTE - 1){
            printf("%u\n", ip_dst_into_8bit_array[i]);
            break;
        }
        printf("%u.", ip_dst_into_8bit_array[i]);
    }
    printf("\n");

    printf("src_port: %u\n", htons(L4_hdr->th_sport));
    printf("dst_port: %u\n\n", htons(L4_hdr->th_dport));

    if (print_payload){
        printf("Payload_data: ");
        for (unsigned int i = 0; i < header->caplen - tcp_size - ip_size - ETHERNET_HEADER_LEN; i++){
            if(i == 8)
                break;

            printf("%02x ", L5_to_L7->data[i]);
        }
        printf("\n\n");
    }
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    // create sniffing session
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // device, capturing size, if promisc, read time out in ms, error msg
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    // check if the device provides Ethernet header
    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", param.dev_);
        return -1;
    }

    while (true) {
        // declare
        struct pcap_pkthdr* header; // has general information about the packet
		const u_char* packet;
        struct libnet_ethernet_hdr *L2_hdr;
        struct libnet_ipv4_hdr *L3_v4_hdr;
        struct libnet_tcp_hdr *L4_hdr;
        struct payload *L5_to_L7;
        u_int ip_size, tcp_size;            // In case that IP or TCP uses options, not fixed 20 bytes
        u_int8_t ip_src_into_8bit_array[4], ip_dst_into_8bit_array[4];
        bool print_payload;

        // capture packets
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        // type cast to distinguish header,
        L2_hdr = (struct libnet_ethernet_hdr*)(packet);

        // check if the upper type is IPv4 or not then type cast
        if (htons(L2_hdr->ether_type) == 0x0800){
            packet += ETHERNET_HEADER_LEN;
            L3_v4_hdr = (struct libnet_ipv4_hdr*)(packet);
            ip_size = (L3_v4_hdr->ip_hl) * 4;
            L3_v4_hdr->ip_src.s_addr = htonl(L3_v4_hdr->ip_src.s_addr);
            L3_v4_hdr->ip_dst.s_addr = htonl(L3_v4_hdr->ip_dst.s_addr);
            for (int i=0; i < 4 ; i++){
                ip_src_into_8bit_array[i] = ((uint8_t*)&(L3_v4_hdr->ip_src.s_addr))[3-i];
                ip_dst_into_8bit_array[i] = ((uint8_t*)&(L3_v4_hdr->ip_dst.s_addr))[3-i];
            }
        }
        else
            continue;

        // check if the length of the IP is valid or not and if the upper protocol is TCP or not.
        if (ip_size >= 20 && L3_v4_hdr->ip_p == 0x06){
            packet += ip_size;
            L4_hdr = (struct libnet_tcp_hdr*)(packet);
            tcp_size = (L4_hdr->th_off) * 4;
        }
        else
            continue;

        // check if the lengh of the TCP is valid of not and if the remainder is the part of the Ethernet or not
        if (tcp_size >= 20){
            packet += tcp_size;
            print_payload = !Is_footer(packet, header, ip_size, tcp_size); // if not footer, print payload
            L5_to_L7 = (struct payload*)(packet);

            // print MAC, IP, port, payload
            print_the_result(L2_hdr, L4_hdr, L5_to_L7, header, ip_size, tcp_size, ip_src_into_8bit_array, ip_dst_into_8bit_array, print_payload);
        }
        else
            continue;
	}

    pcap_close(pcap);

    return 0;
}
