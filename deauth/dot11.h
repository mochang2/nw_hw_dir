#pragma once
#include <stdint.h>
#include <mac.h>

struct antenna_related {  // 2byte
    uint8_t antenna_signal = 0x00;
    uint8_t antenna = 0x00;
};

struct au_radiotap_header { // 32byte
    uint8_t h_rev = 0x00;
    uint8_t h_pad = 0x00;
    uint16_t h_len = 0x0020;
    uint32_t present_flags[3] = {
        0xa00040ae,
        0xa0000820,
        0x00000820
    };
    uint8_t flag = 0x10;
    uint8_t data_rate = 0x02;
    uint16_t ch_freq = 0x096c;
    uint16_t ch_flag = 0x00a0;
    antenna_related a1;
    uint16_t signal_qual = 0x0064;
    uint16_t RX_flag = 0x0000;
    antenna_related a2;
    antenna_related a3;
};

struct au_wireless_mng {
    uint16_t auth_al = 0x0000;  // fixed params
    uint16_t auth_seq = 0x0001;
    uint16_t status = 0x0000;
    uint8_t vendor = 0xdd;  // tagged params
    uint8_t tag_len = 0x09;
    uint8_t OUI[3] = {
        0x00,
        0x10,
        0x18
    };
    uint8_t vendor_specific[6] = {
        0x02, 0x00,
        0x00, 0x10,
        0x00, 0x00
    };
};

struct au_dot11 {
    au_radiotap_header rt_h;
    uint8_t type = 0xb0;;
    uint8_t flag = 0x00;
    uint16_t duration = 0x013a;
    Mac dst_mac;
    Mac src_mac;
    Mac BSSID;
    uint16_t seq_num;
    au_wireless_mng mng;

    uint32_t FCS = 0x2cf225ad;
};

struct deau_radiotap_header { // 12byte
    uint8_t h_rev = 0x00;
    uint8_t h_pad = 0x00;
    uint16_t h_len = 0x000c;
    uint32_t present_flags = 0x00008004;
    uint8_t data_rate = 0x02;
    uint8_t undefined = 0x00;
    uint16_t TX_flag = 0x0018;
};


struct deau_wireless_mng {
    uint16_t fixed_params = 0x0007;
};

struct deau_dot11 {
    deau_radiotap_header rt_h;
    uint8_t type = 0xc0;;
    uint8_t flag = 0x00;
    uint16_t duration = 0x013a;
    Mac dst_mac;
    Mac src_mac;
    Mac BSSID;
    uint16_t seq_num;
    deau_wireless_mng mng;
};
