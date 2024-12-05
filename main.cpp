#include <pcap.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ctime>
#include <iomanip>
#include <sys/stat.h>
#include <climits>
#include <cctype>

using namespace std;

struct CaptureInfo {
    int max_packets;
    int captured_packets;
};

struct PacketData {
    int number;
    string timestamp;
    string src_mac;
    string dst_mac;
    int ip_version;
    int ip_header_length;
    int ip_tos;
    int ip_total_length;
    int ip_id;
    int ip_ttl;
    string protocol;
    int src_port;
    int dst_port;
    string tcp_flags;
    string payload;
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void save_to_csv(const string& filename, bool append);
string escape_csv(const string& str);
PacketData analyze_packet(const u_char *packet, int packet_len);

const long long MAX_FILE_SIZE = LLONG_MAX;
long long current_file_size = 0;
int file_count = 1;
int packet_count = 0;
vector<PacketData> packet_data;

std::string format_mac_address(const std::string& mac) {
    std::stringstream ss(mac);
    std::string item;
    std::string formatted_mac;

    while (std::getline(ss, item, ':')) {
        if (!formatted_mac.empty()) {
            formatted_mac += ":";
        }
        formatted_mac += std::string(2 - item.length(), '0') + item;
    }

    std::transform(formatted_mac.begin(), formatted_mac.end(), formatted_mac.begin(), ::toupper);

    return formatted_mac;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev;
    int num_packets;

    if (argc != 3) {
        cerr << "사용법: " << argv[0] << " <네트워크_장치> <캡처할_패킷_수>\n";
        cerr << "사용 가능한 네트워크 장치 목록:\n";
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            cerr << "네트워크 장치를 찾을 수 없습니다: " << errbuf << endl;
            return 1;
        }
        for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
            cout << d->name << " - " << (d->description ? d->description : "설명 없음") << endl;
        }
        pcap_freealldevs(alldevs);
        return 1;
    }

    dev = argv[1];
    num_packets = atoi(argv[2]);

    if (num_packets <= 0) {
        cerr << "캡처할 패킷 수는 1 이상이어야 합니다." << endl;
        return 1;
    }

    cout << "캡처에 사용할 장치: " << dev << endl;
    cout << "캡처할 패킷 수: " << num_packets << endl;

    mkdir("./packet", 0777);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "장치를 열 수 없습니다: " << errbuf << endl;
        return 1;
    }

    if (pcap_set_rfmon(handle, 1) != 0) {
        cerr << "모니터 모드를 설정할 수 없습니다. 일반 모드로 계속합니다." << endl;
    }

    cout << "패킷 캡처를 시작합니다." << endl;

    CaptureInfo capture_info = {num_packets, 0};
    pcap_loop(handle, num_packets, packet_handler, (u_char*)&capture_info);

    pcap_close(handle);
    save_to_csv("./packet/captured_packets_final.csv", false);

    cout << "패킷 캡처가 완료되었습니다." << endl;

    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    CaptureInfo *info = (CaptureInfo*)user_data;
    info->captured_packets++;

    PacketData pkt_data = analyze_packet(packet, pkthdr->len);
    pkt_data.number = ++packet_count;

    ostringstream time_ss;
    time_ss << pkthdr->ts.tv_sec << "." << setfill('0') << setw(6) << pkthdr->ts.tv_usec;
    pkt_data.timestamp = time_ss.str();

    // MAC 주소 형식 변환
    pkt_data.src_mac = format_mac_address(pkt_data.src_mac);
    pkt_data.dst_mac = format_mac_address(pkt_data.dst_mac);

    packet_data.push_back(pkt_data);

    if (current_file_size >= MAX_FILE_SIZE) {
        cout << "\n저장 중...\n";
        save_to_csv("./packet/captured_packets_" + to_string(file_count) + ".csv", file_count > 1);
        file_count++;
        current_file_size = 0;
        packet_data.clear();
    }

    cout << "캡처된 패킷: " << info->captured_packets << "/" << info->max_packets << endl;
}

PacketData analyze_packet(const u_char *packet, int packet_len) {
    PacketData pkt_data;
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_length = ip_header->ip_hl * 4;

    // Ethernet 헤더
    pkt_data.src_mac = ether_ntoa((struct ether_addr*)eth_header->ether_shost);
    pkt_data.dst_mac = ether_ntoa((struct ether_addr*)eth_header->ether_dhost);

    // IP 헤더
    pkt_data.ip_version = (int)ip_header->ip_v;
    pkt_data.ip_header_length = ip_header_length;
    pkt_data.ip_tos = (int)ip_header->ip_tos;
    pkt_data.ip_total_length = ntohs(ip_header->ip_len);
    pkt_data.ip_id = ntohs(ip_header->ip_id);
    pkt_data.ip_ttl = (int)ip_header->ip_ttl;

    // 프로토콜 분석
    switch(ip_header->ip_p) {
        case IPPROTO_TCP: {
            pkt_data.protocol = "TCP";
            struct tcphdr *tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_length);
            pkt_data.src_port = ntohs(tcp_header->th_sport);
            pkt_data.dst_port = ntohs(tcp_header->th_dport);

            ostringstream flags;
            if (tcp_header->th_flags & TH_FIN) flags << "FIN ";
            if (tcp_header->th_flags & TH_SYN) flags << "SYN ";
            if (tcp_header->th_flags & TH_RST) flags << "RST ";
            if (tcp_header->th_flags & TH_PUSH) flags << "PSH ";
            if (tcp_header->th_flags & TH_ACK) flags << "ACK ";
            if (tcp_header->th_flags & TH_URG) flags << "URG ";
            pkt_data.tcp_flags = flags.str();
            break;
        }
        case IPPROTO_UDP: {
            pkt_data.protocol = "UDP";
            struct udphdr *udp_header = (struct udphdr*)((u_char*)ip_header + ip_header_length);
            pkt_data.src_port = ntohs(udp_header->uh_sport);
            pkt_data.dst_port = ntohs(udp_header->uh_dport);
            break;
        }
        default:
            pkt_data.protocol = "Other";
    }

    // 페이로드
    int header_length = sizeof(struct ether_header) + ip_header_length;
    if (ip_header->ip_p == IPPROTO_TCP) {
        header_length += ((struct tcphdr*)((u_char*)ip_header + ip_header_length))->th_off * 4;
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        header_length += sizeof(struct udphdr);
    }

    ostringstream payload;
    for (int i = header_length; i < packet_len; i++) {
        payload << setfill('0') << setw(2) << hex << (int)packet[i];
    }
    pkt_data.payload = payload.str();

    return pkt_data;
}

void save_to_csv(const string& filename, bool append) {
    ofstream csv_file(filename, append ? ios::app : ios::out);
    if (!append) {
        csv_file << "번호,시간,출발지MAC,목적지MAC,IP버전,IP헤더길이,서비스유형,전체길이,식별자,TTL,프로토콜,출발지포트,목적지포트,TCP플래그,페이로드\n";
    }
    for (const auto& pkt : packet_data) {
        csv_file << pkt.number << ","
                 << pkt.timestamp << ","
                 << escape_csv(pkt.src_mac) << ","
                 << escape_csv(pkt.dst_mac) << ","
                 << pkt.ip_version << ","
                 << pkt.ip_header_length << ","
                 << "0x" << hex << pkt.ip_tos << dec << ","
                 << pkt.ip_total_length << ","
                 << "0x" << hex << pkt.ip_id << dec << ","
                 << pkt.ip_ttl << ","
                 << escape_csv(pkt.protocol) << ","
                 << pkt.src_port << ","
                 << pkt.dst_port << ","
                 << escape_csv(pkt.tcp_flags) << ","
                 << escape_csv(pkt.payload) << "\n";
    }
    csv_file.close();
    cout << filename << "에 데이터가 저장되었습니다." << endl;
}

string escape_csv(const string& str) {
    if (str.find_first_of(",\"\n") == string::npos) {
        return str;
    }
    ostringstream result;
    result << '"';
    for (char c : str) {
        if (c == '"') {
            result << "\"\"";
        } else {
            result << c;
        }
    }
    result << '"';
    return result.str();
}