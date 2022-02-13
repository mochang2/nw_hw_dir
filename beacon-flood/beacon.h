#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <mac.h>

struct Radiotap_hdr {
    uint8_t h_rev = 0;
    uint8_t h_pad = 0;
    uint16_t h_len = 0x000c;
    uint32_t flag = 0x00008004;
    uint16_t rate = 0x0002;
    uint16_t tx_flag = 0x0018;
};

struct Dot11 {
    uint8_t type;
    uint8_t flag;
    uint16_t duration = 0;
    Mac dst;
    Mac src;
    Mac bssid;
    uint16_t seq_num = 0;
};

struct Fixed_param {
    uint32_t timestamp[2] = {
        0, 0
    };
    uint16_t interval = 0x0064;
    uint16_t capabilities = 0x0001;
};

struct Tagged_param {
    std::string ssid = "abcd";
    //std::vector<float> supported_rates;
    uint8_t supported_rates[6] {
        0x01, 0x04, 0x82,
        0x84, 0x8b, 0x96
    };
    uint8_t ds_param_set[3] {
        0x03, 0x01, 0x0c
    };
    uint8_t cf_param_set[8] {
        0x04, 0x06, 0x01, 0x02,
        0x00, 0x00, 0x00, 0x00
    };
    uint8_t tim[6] {
        0x05, 0x04, 0x00,
        0x01, 0x00, 0x00
    };
};

struct Dot11_mng {
    Fixed_param f_param;
    Tagged_param t_param;
};


struct Beacon_frame {
    Radiotap_hdr r_hdr;
    Dot11 dot11;
    Dot11_mng dot11_mng;
};
