#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <unordered_set>

// 블랙리스트 도메인 저장용 해시셋
std::unordered_set<std::string> blacklist;

void load_domains(const char* filename) {
    std::ifstream fin(filename);
    if (!fin) {
        std::cerr << "도메인 파일 열기 실패: " << filename << std::endl;
        exit(1);
    }
    std::string line;
    size_t count = 0;
    while (std::getline(fin, line)) {
        size_t pos = line.find(',');
        if (pos != std::string::npos)
            line = line.substr(pos + 1);
        // 공백/개행 제거
        line.erase(line.find_last_not_of(" \n\r\t") + 1);
        if (!line.empty()) {
            blacklist.insert(line);
            ++count;
        }
    }
    fin.close();
    std::cout << "총 " << count << "개의 도메인 로드 완료" << std::endl;
    
    // 테스트 출력
    std::cout << "테스트 검색 - google.com: " 
              << (blacklist.find("google.com") != blacklist.end() ? "차단 대상" : "허용됨") << std::endl;
    std::cout << "테스트 검색 - facebook.com: " 
              << (blacklist.find("facebook.com") != blacklist.end() ? "차단 대상" : "허용됨") << std::endl;
}

/* 패킷 검사 함수 - 반환 값: ID(허용) 또는 0(차단) */
static int check_packet(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet_data;
    int packet_len;
    
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("패킷 ID=%u ", id);
    }
    
    // 패킷 데이터 획득
    packet_len = nfq_get_payload(tb, &packet_data);
    if (packet_len < 0) {
        printf("페이로드 없음\n");
        return id; // 패킷 허용
    }
    
    printf("패킷 길이=%d 바이트\n", packet_len);
    
    // IP 헤더 처리
    struct iphdr* ip_header = (struct iphdr*)packet_data;
    if (ip_header->protocol != IPPROTO_TCP) {
        printf("TCP 패킷이 아님\n");
        return id; // TCP가 아니면 허용
    }
    
    int ip_header_len = ip_header->ihl * 4;
    if (ip_header_len > packet_len) {
        printf("IP 헤더 크기 오류\n");
        return id; // 패킷 허용
    }
    
    // TCP 헤더 처리
    struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;
    
    if (ip_header_len + tcp_header_len > packet_len) {
        printf("TCP 헤더 크기 오류\n");
        return id; // 패킷 허용
    }
    
    // HTTP 데이터 처리
    unsigned char* http_data = packet_data + ip_header_len + tcp_header_len;
    int http_data_len = packet_len - (ip_header_len + tcp_header_len);
    
    if (http_data_len <= 0) {
        printf("HTTP 데이터 없음\n");
        return id; // 패킷 허용
    }
    
    // HTTP 데이터를 문자열로 처리하기 위해 임시 버퍼 생성
    char http_str[8192] = {0};
    if (http_data_len > 8191) http_data_len = 8191;
    memcpy(http_str, http_data, http_data_len);
    http_str[http_data_len] = '\0';
    
    // Host 헤더 찾기
    char *host = strstr(http_str, "Host: ");
    if (host == NULL) {
        printf("Host 헤더 없음\n");
        return id; // 패킷 허용
    }
    
    // Host 값 추출
    host = host + 6; // "Host: " 건너뛰기
    
    // Host 값의 끝 찾기 (CRLF)
    char *host_end = strstr(host, "\r\n");
    if (host_end) {
        *host_end = '\0'; // 문자열 종료
    }
    
    printf("검사 대상 호스트: %s\n", host);
    
    // 블랙리스트 검사
    if (blacklist.find(std::string(host)) != blacklist.end()) {
        printf("차단 대상 발견: %s\n", host);
        return 0; // 차단
    }
    
    return id; // 허용
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph;
    int result;
    
    printf("콜백 함수 실행\n");
    
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);
    
    result = check_packet(nfa);
    
    if (result) {
        printf("패킷 허용: ID=%u\n", id);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    } else {
        printf("패킷 차단: ID=%u\n", id);
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

void print_usage() {
    printf("사용법: 1m-block <domain_list.csv>\n");
    printf("예시: sudo ./1m-block top-1m.csv\n");
}

int main(int argc, char** argv) {
    if (argc != 2) {
        print_usage();
        return 1;
    }
    
    load_domains(argv[1]);
    
    struct nfq_handle* h;
    struct nfq_q_handle* qh;
    int fd, rv;
    char buf[4096] __attribute__((aligned));
    
    printf("라이브러리 핸들 열기\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "nfq_open() 오류\n");
        exit(1);
    }
    
    printf("기존 큐 핸들러 제거\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_unbind_pf() 오류\n");
        exit(1);
    }
    
    printf("큐 핸들러 바인딩\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_bind_pf() 오류\n");
        exit(1);
    }
    
    printf("큐 생성\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "nfq_create_queue() 오류\n");
        exit(1);
    }
    
    printf("패킷 복사 모드 설정\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "패킷 복사 모드 설정 오류\n");
        exit(1);
    }
    
    fd = nfq_fd(h);
    
    printf("패킷 검사 시작...\n");
    printf("차단 준비 완료! - (iptables 설정 필요: sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0 --queue-bypass)\n");
    
    while (1) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("패킷 수신!\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("패킷 손실 발생!\n");
            continue;
        }
        perror("recv 실패");
        break;
    }
    
    printf("큐 제거\n");
    nfq_destroy_queue(qh);
    
    printf("라이브러리 핸들 닫기\n");
    nfq_close(h);
    
    return 0;
}
