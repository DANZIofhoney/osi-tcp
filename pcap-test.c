#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

void usage() {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
}

typedef struct {
        char* dev_;
} Param;

static Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
        if (argc != 2) {
                usage();
                return false;
        }
        param->dev_ = argv[1];
        return true;
}

#define ETH_SRC 0x06
#define ETH_DST 0x06
#define ETH_SIZE 14

#define IP_SRC 0x04
#define IP_DST 0x04
#define IP_LEN 0x01

#define TCP_SRC 0x02
#define TCP_DST 0x02
#define TCP_LEN 0x01

#define PAYLOAD_OFFSET_inTCP 0x12
#define PAYLOAD_MAX 0x14

typedef struct {
        unsigned char EthernetSrc[ETH_SRC];
        unsigned char EthernetDst[ETH_DST];
        unsigned char IpSrc[IP_SRC];
        unsigned char IpDst[IP_DST];
        unsigned char IpLen[IP_LEN];
        unsigned char TcpSrc[TCP_SRC];
        unsigned char TcpDst[TCP_DST];
        unsigned char TcpLen[TCP_LEN];
        unsigned char payload[];
}packet_header_info;

char filter_exp[] = "tcp";

void eth_info(unsigned char packet[], packet_header_info* header_info);
void ip_info(unsigned char packet[], packet_header_info* header_info);
void tcp_info(unsigned char packet[], packet_header_info* header_info);
void payload_info(unsigned char packet[], packet_header_info* header_info);
void assign_info(unsigned char packet[], unsigned char dst[], int startIndex, int size);
void print_info(unsigned char info[], int size);
void eth_print_info(unsigned char info[], int size);
void ip_print_info(unsigned char info[], int size);
void tcp_print_info(unsigned char info[], int size);


int main(int argc, char* argv[]) {
        if (!parse(&param, argc, argv)){
            printf("Error!");
            return -1;
        }

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
        if (pcap == NULL) {
                fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
                return -1;
        }

        while (true) {
                struct pcap_pkthdr* header;
                const unsigned char* packet;
                packet_header_info header_info;
                struct bpf_program fp;
                int res = pcap_next_ex(pcap, &header, &packet);
                if (res == 0) continue;
                if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                        break;
                }
                if (pcap_compile(pcap, &fp, filter_exp, -1, 1) == -1) { //tcp 패킷에 대해서만 분석함
                        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
                        return(1);
                }
                if (pcap_setfilter(pcap, &fp) == -2) {
                        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
                        return(1);
                }
                printf("%u bytes captured\n", header->caplen);
                eth_info(packet, &header_info);
                

                ip_info(packet, &header_info);
                

                tcp_info(packet, &header_info);
                

                payload_info(packet, &header_info);

                printf("\n");
        }

        pcap_close(pcap);
}

void eth_info(unsigned char packet[], packet_header_info* header_info) {
        assign_info(packet, &(header_info->EthernetSrc), 0, ETH_SRC);
        assign_info(packet, &(header_info->EthernetDst), ETH_SRC, ETH_DST+1);
        printf("eth src : ");
        eth_print_info(&(header_info->EthernetSrc), ETH_SRC);
        printf("eth dst : ");
        eth_print_info(&(header_info->EthernetDst), ETH_DST);
}

void ip_info(unsigned char packet[], packet_header_info* header_info){
        assign_info(packet, &(header_info->IpLen), ETH_SIZE , IP_LEN);
	assign_info(packet, &(header_info->IpSrc), ETH_SIZE + 12 , IP_SRC);

	assign_info(packet, &(header_info->IpDst), ETH_SIZE + 12 + IP_SRC , IP_DST);

        //ip length manufactoring
        *(header_info->IpLen) &= 0x0f;
        *(header_info->IpLen) *= 4;

        printf("ip src : ");
        ip_print_info(&(header_info->IpSrc), IP_SRC);
        printf("ip dst : ");
        ip_print_info(&(header_info->IpDst), IP_DST);
}
void tcp_info(unsigned char packet[], packet_header_info* header_info){
        assign_info(packet, &(header_info->TcpSrc), ETH_SIZE + *(header_info->IpLen) , TCP_SRC);
	assign_info(packet, &(header_info->TcpDst), ETH_SIZE + *(header_info->IpLen) + TCP_SRC , TCP_DST);

	assign_info(packet, &(header_info->TcpLen), ETH_SIZE + *(header_info->IpLen) + TCP_SRC + 8 , TCP_LEN);

        //tcp length manufactoring
        *(header_info->TcpLen) &= 0xf0;
        *(header_info->TcpLen) *= 4;

        printf("tcp src : ");
        tcp_print_info(&(header_info->TcpSrc), TCP_SRC);
        printf("tcp dst : ");
        tcp_print_info(&(header_info->TcpDst), TCP_DST);
}
void payload_info(unsigned char packet[], packet_header_info* header_info){
        assign_info(packet, &(header_info->payload), ETH_SIZE + *(header_info->IpLen) + PAYLOAD_OFFSET_inTCP, 20);
        printf("payload : ");
	print_info(&(header_info->payload), 20);
}

void assign_info(unsigned char packet[], unsigned char dst[], int startindex, int size) {
        for (int i = 0; i < size; i++) { 
                dst[i] = packet[startindex + i];
        }
        //eth_src succeed
}
void print_info(unsigned char info[], int size) {
        for (int i = 0; i < size; i++) {
                printf("%02x ", (unsigned int)info[i]);
        }
        printf("\n");
}
void eth_print_info(unsigned char info[], int size) {
        for (int i = 0; i < size; i++) {
                printf("%02x", (unsigned int)info[i]);
                if(i!=size-1)printf(":");
        }
        printf("\n");
}
void ip_print_info(unsigned char info[], int size) {
        for (int i = 0; i < size; i++) {
                printf("%d", (unsigned int)info[i]);
                if(i!=size-1)printf(".");
        }
        printf("\n");
}
void tcp_print_info(unsigned char info[], int size) {
        unsigned int temp = 0;
        temp |= (info[0]<<8);
        temp |= info[1];
        printf("%d", temp);
        printf("\n");
}