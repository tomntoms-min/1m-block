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

// ===== Trie 구현 =====
const int CHARSET_SIZE = 128; // ASCII 전체 커버

struct TrieNode {
    TrieNode* children[CHARSET_SIZE];
    bool isEndOfWord;
    TrieNode() : isEndOfWord(false) {
        memset(children, 0, sizeof(children));
    }
    ~TrieNode() {
        for (int i = 0; i < CHARSET_SIZE; ++i)
            if (children[i]) delete children[i];
    }
};

class Trie {
public:
    Trie() { root = new TrieNode(); }
    ~Trie() { delete root; }

    void insert(const std::string& word) {
        TrieNode* node = root;
        for (char c : word) {
            unsigned char idx = (unsigned char)c;
            if (!node->children[idx])
                node->children[idx] = new TrieNode();
            node = node->children[idx];
        }
        node->isEndOfWord = true;
    }

    bool search(const std::string& word) const {
        TrieNode* node = root;
        for (char c : word) {
            unsigned char idx = (unsigned char)c;
            if (!node->children[idx])
                return false;
            node = node->children[idx];
        }
        return node->isEndOfWord;
    }

private:
    TrieNode* root;
};

// ===== 도메인 리스트 로딩 =====
Trie trie;

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
            trie.insert(line);
            ++count;
        }
    }
    fin.close();
    std::cout << "총 " << count << "개의 도메인 로드 완료" << std::endl;
}

// ===== Host 헤더 검사 =====
bool is_harmful_site(unsigned char* data, int data_len) {
    struct iphdr* ip_header = (struct iphdr*)data;
    if (ip_header->protocol != IPPROTO_TCP) return false;
    int ip_header_len = ip_header->ihl * 4;
    struct tcphdr* tcp_header = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;
    unsigned char* http_data = data + ip_header_len + tcp_header_len;
    int http_data_len = data_len - (ip_header_len + tcp_header_len);

    // HTTP 트래픽인지 확인 (포트 80)
    if (ntohs(tcp_header->dest) != 80) return false;

    // Host 헤더 추출
    for (int i = 0; i < http_data_len - 7; ++i) {
        if (memcmp(http_data + i, "Host: ", 6) == 0) {
            char host[512] = {0};
            char* host_pos = (char*)(http_data + i + 6);
            char* host_end = strpbrk(host_pos, "\r\n ");
            int host_len = host_end ? (host_end - host_pos) : strlen(host_pos);
            if (host_len > 0 && host_len < 512) {
                strncpy(host, host_pos, host_len);
                host[host_len] = '\0';
                if (trie.search(host)) {
                    printf("유해 사이트 발견: %s\n", host);
                    return true;
                }
            }
            break;
        }
    }
    return false;
}

// ===== Netfilter Queue 콜백 =====
static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* data) {
    unsigned char* packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    if (packet_len >= 0 && is_harmful_site(packet_data, packet_len)) {
        printf("유해 사이트 차단!\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// ===== 메인 함수 =====
void print_usage() {
    printf("사용법: netfilter-test <domain_list.csv>\n");
    printf("예시: sudo ./netfilter-test top-1m.csv\n");
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

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    printf("패킷 검사 시작...\n");
    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
