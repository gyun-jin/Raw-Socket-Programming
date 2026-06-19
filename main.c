#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h> // 리눅스 Raw Socket 필수 헤더
#include <time.h>

#define BUFFER_SIZE 65536

// 구조체 정렬 문제 방지를 위해 packed 속성 추가
// 작성하신 구조체 그대로 사용하되 리눅스 호환성 보완

/* 이더넷 header 구조체 */
typedef struct __attribute__((packed)) Ethernet_Header {
    unsigned char des[6]; // 수신자 MAC
    unsigned char src[6]; // 송신자 MAC
    unsigned short ptype; // 프로토콜 타입
} Ethernet_Header;

/* IP header 구조체 (비트 필드 순서 리눅스 호환 고려) */
typedef struct __attribute__((packed)) IPHeader {
    unsigned char HeaderLength : 4;
    unsigned char Version : 4;
    unsigned char TypeOfService;
    unsigned short TotalLength;
    unsigned short ID;
    unsigned short FlagOffset;
    unsigned char TimeToLive;
    unsigned char Protocol;
    unsigned short checksum;
    struct in_addr SenderAddress;      // 표준 구조체 사용 권장
    struct in_addr DestinationAddress; // 표준 구조체 사용 권장
} IPHeader;

/* TCP header 구조체 */
typedef struct __attribute__((packed)) TCPHeader {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char reserved_part1 : 4;
    unsigned char data_offset : 4;
    unsigned char flags; // 플래그 통합
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCPHeader;

/* UDP header 구조체 */
typedef struct __attribute__((packed)) UDP_HDR {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
} UDP_HDR;

/* DNS 구조체 */
typedef struct __attribute__((packed)) DNS {
    unsigned short transaction_ID;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short authority;
    unsigned short additional;
    // 가변 길이 데이터는 포인터로 접근해야 함
} DNS_HDR;

// 함수 프로토타입
void packet_handler(unsigned char* buffer, int size);
void print_eth_header(unsigned char* buffer);
void print_ip_header(unsigned char* buffer);
void print_tcp_packet(unsigned char* buffer, int size);
void print_udp_packet(unsigned char* buffer, int size);
void print_data(unsigned char* data, int size);

// 전역 변수 (필터링 선택)
int sel = 0;

int main() {
    int sock_raw;
    int data_size;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);

    // 1. 리눅스 Raw Socket 생성 
    // AF_PACKET: 링크 계층(이더넷) 헤더부터 모두 가져옴
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sock_raw < 0) {
        perror("Socket Error (sudo로 실행했나요?)");
        return 1;
    }
    
    printf("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
    printf("┃    Computer Network Design (Raw Socket)      ┃\n");
    printf("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");
    
    while (1) {
        printf("\n<필터링>\n");
        printf(" 1. TCP (HTTP 포함)\n 2. UDP (DNS 포함)\n 3. ALL\n");
        printf(" >> ");
        // scanf_s 대신 scanf 사용 (리눅스)
        if (scanf("%d", &sel) == 1) { 
            if (sel >= 1 && sel <= 3) break;
        }
        // 입력 버퍼 비우기
        while(getchar() != '\n');
    }

    printf("패킷 캡처를 시작합니다... (중지: Ctrl+C)\n");

    while(1) {
        // 패킷 수신
        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (data_size < 0) {
            printf("Recvfrom error\n");
            return 1;
        }
        
        // 패킷 처리 함수 호출
        packet_handler(buffer, data_size);
    }

    close(sock_raw);
    free(buffer);
    return 0;
}

s
void packet_handler(unsigned char* buffer, int size) {
    // 이더넷 헤더 처리
    struct ethhdr *eth = (struct ethhdr *)buffer;
    unsigned short iphdrlen;
    
    // IP 패킷만 처리 (0x0800)
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        iphdrlen = iph->ihl * 4;

        // --- [핵심 수정] 노이즈 필터링 시작 ---
        // TCP나 UDP가 아니면 무시
        if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) return;

        int is_target_packet = 0; // 우리가 원하는 패킷인지 확인하는 깃발

        // 1. TCP인 경우 포트 80(HTTP)만 확인
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
            if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80) {
                is_target_packet = 1;
            }
        }
        // 2. UDP인 경우 포트 53(DNS)만 확인
        else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
            if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
                is_target_packet = 1;
            }
        }

        // 원하는 패킷(HTTP, DNS)이 아니면 함수 즉시 종료 (화면에 출력 안 함)
        if (is_target_packet == 0) return;
        // --- [핵심 수정] 노이즈 필터링 끝 ---

        // 여기서부터는 필터링된 "진짜" 패킷만 출력됨
        print_eth_header(buffer);
        print_ip_header(buffer);

        if (iph->protocol == IPPROTO_TCP) {
            print_tcp_packet(buffer, size);
        }
        else if (iph->protocol == IPPROTO_UDP) {
            print_udp_packet(buffer, size);
        }
    }
}

void print_eth_header(unsigned char* buffer) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    printf("\n\n==================================================\n");
    printf("Ethernet Header\n");
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
        eth->h_source[0], eth->h_source[1], eth->h_source[2], 
        eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", 
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}

void print_ip_header(unsigned char* buffer) {
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    printf("\nIP Header \n");
    printf("   |-IP Version        : %d\n", (unsigned int)iph->version);
    printf("   |-Header Length     : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl))*4);
    printf("   |-Total Length      : %d Bytes\n", ntohs(iph->tot_len));
    printf("   |-TTL               : %d\n", (unsigned int)iph->ttl);
    printf("   |-Protocol          : %d\n", (unsigned int)iph->protocol);
    printf("   |-Checksum          : %u\n", ntohs(iph->check)); // <--- 추가됨
    printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}


void print_tcp_packet(unsigned char* buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    
    printf("\nTCP Header \n");
    printf("   |-Source Port      : %u\n", ntohs(tcph->source));
    printf("   |-Destination Port : %u\n", ntohs(tcph->dest));
    printf("   |-Sequence Number  : %u\n", ntohl(tcph->seq));
    printf("   |-Acknowledge No   : %u\n", ntohl(tcph->ack_seq));
    printf("   |-Header Length    : %d DWORDS\n" ,(unsigned int)tcph->doff);
    printf("   |-Window Size      : %d\n", ntohs(tcph->window));
    printf("   |-Checksum         : %u\n", ntohs(tcph->check)); // <--- 추가됨
    printf("   |-Urgent Pointer   : %d\n", tcph->urg_ptr);

    // HTTP 확인 및 데이터 출력
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    if (ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 80) {
        printf("   [HTTP Protocol Detected]\n");
        unsigned char *data = buffer + header_size;
        int data_len = size - header_size;
        if(data_len > 0) print_data(data, data_len);
    }
}


void print_udp_packet(unsigned char* buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof(struct udphdr);

    printf("\nUDP Header \n");
    printf("   |-Source Port      : %u\n", ntohs(udph->source));
    printf("   |-Destination Port : %u\n", ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n", ntohs(udph->len));
    printf("   |-Checksum         : %u\n", ntohs(udph->check)); // <--- 추가됨
    
    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
        printf("   [DNS Protocol Detected]\n");
        unsigned char *data = buffer + header_size;
        int data_len = size - header_size;
        if(data_len > 0) print_data(data, (data_len > 100 ? 100 : data_len)); 
    }
}

void print_data(unsigned char* data, int size) {
    printf("Data Payload:\n");
    for(int i=0; i < size; i++) {
        if(i!=0 && i%16==0) printf("\n");
        if(data[i] >= 32 && data[i] <= 128) 
            printf("%c", (unsigned char)data[i]);
        else 
            printf("."); // 출력 불가능 문자는 점으로 표시
    }
    printf("\n");
}