#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <stdbool.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void usage(){
    printf("usage example: nfqnl_test 0");
}

bool check_len(int len){
    if (len < 20 || len > 60)
        return false;
    return true;
}

void parse(unsigned char* parsed_data, int len, unsigned char* buf, int i){
    parsed_data = (unsigned char*)malloc(len + 1);
    memcpy(parsed_data, buf + i, len);
    for (int j = 0; j < len; j++)
        printf("%02X ", parsed_data[j]);
    printf("\nlen is %u in decimal\n", len);

    free(parsed_data);
}

void dump(unsigned char* buf, int size, int *verdict) {
    for (int i = 0; i < size; i++) {
        //if (i != 0 && i % 16 == 0)
          //  printf("\n");

        if (i == 0 && (buf[i] & 0x40) == 0x40){ // if L3 is ipv4
            // initialize
            unsigned char* ip_h, *tcp_h, *payload;
            uint16_t ip_len, tcp_len, payload_len;

            // ip parse
            ip_len = (buf[i] & 0x0f) * 4;
            if(!check_len(ip_len))
                return;

            parse(ip_h, ip_len, buf, i);

            if (buf[i + 9] == IPPROTO_TCP){ // if L4 is tcp
                i += ip_len;

                // tcp parse
                tcp_len = ((buf[i + 12] >> 4) & 0xf) * 4;
                if(!check_len(tcp_len))
                    return;

                parse(tcp_h, tcp_len, buf, i);

                i += tcp_len;

                if(i != size){
                    payload_len = size - i;
                    payload = buf + i;
                    for (int j = 0; j < payload_len; j++)
                        printf("%02X ", payload[j]);
                    printf("\nlen is %u in decimal\n", payload_len);

                    if(strstr(payload, "Host: test.gilgil.net"))
                        *verdict = NF_DROP;
                }
                //printf("verdict in dump : %d\n", *verdict);
            }
        }
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb, int *verdict) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u\n", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u\n", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u\n", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u\n", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u\n", ifi);

    // the start point of the packet: dA0ata
    // packet len: ret
    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        dump(data, ret, verdict);
        printf("payload_len=%d\n", ret);
    }

    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    int verdict = NF_ACCEPT;
    u_int32_t id = print_pkt(nfa, &verdict);
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2)
        usage();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
