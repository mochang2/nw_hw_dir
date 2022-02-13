#include <stdio.h>
#include <unistd.h>
#include <string>
#include <list>
#include <pcap.h>
#include <mac.h>
#include <beacon.h>

// fail

std::list<std::string> ssidList {
  "1.aaa",
  "2.bbb",
  "3.ccc",
  "4.ddd",
  "5.eee",
  "6.fff"
};

void usage() {
    printf("syntax: beacon-flood <interface> <ssid-list-file>\n");
    printf("sample: beacon-flood mon0 ssid-list.txt\n");
}

typedef struct {
    char* interface;
    char* file;
} Param;

Param param  = {
    .interface = NULL,
    .file = NULL,
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return false;
    }
    param->interface = argv[1];
    param->file = argv[2];

    return true;
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }


    std::list<std::string>::iterator iter = ssidList.begin();

    Radiotap_hdr r_hdr;

    Dot11 dot11;
    dot11.type = 0x80;
    dot11.flag = 0x00;
    dot11.dst = Mac("ff:ff:ff:ff:ff:ff");
    dot11.src = Mac("aa:bb:cc:dd:ee:ff");  // example
    dot11.bssid = dot11.src;

    Tagged_param t_param;
    //t_param.ssid = *iter;
    //t_param.supported_rates.push_back(1.0f);
    //t_param.supported_rates.push_back(2.0f);
    //t_param.supported_rates.push_back(5.5f);
    //t_param.supported_rates.push_back(11.0f);

    Dot11_mng dot11_mng;
    dot11_mng.t_param = t_param;

    Beacon_frame bf;
    bf.r_hdr = r_hdr;
    bf.dot11 = dot11;
    bf.dot11_mng = dot11_mng;

    while (true) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&bf), sizeof(bf));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        if (++iter == ssidList.end())
          iter = ssidList.begin();

        usleep(10000);
    }

    return 0;
}
