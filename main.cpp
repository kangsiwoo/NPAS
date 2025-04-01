#include <iostream>
#include <string>
#include <pcap.h>
#include <cstring>
#include <fstream>
#include <memory>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <array>

enum class ProtocolType {
    Ethernet, LLC, SNAP, IPv4, IPv6, ARP, ICMP, TCP, UDP, NetBIOS, SSL, TLS, HTTP, FTP, SMTP, DNS
};

class Layer {
public:
    virtual ~Layer() = default;
    virtual void parse(const uint8_t* data, size_t len) = 0;
    virtual std::string toString() const = 0;
    virtual ProtocolType getProtocolType() const = 0;
    virtual size_t getHeaderLength() const = 0;
};

class ProtocolDissector {
public:
    virtual ~ProtocolDissector() = default;
    virtual ProtocolType getProtocolType() const = 0;
    virtual std::unique_ptr<Layer> dissect(const uint8_t* data, size_t len) = 0;
};

class EthernetLayer : public Layer {
private:
    std::array<uint8_t, 6> destMac;
    std::array<uint8_t, 6> srcMac;
    uint16_t etherType;

public:
    void parse(const uint8_t* data, size_t len) override {
        if (len < 14) throw std::runtime_error("유효하지 않은 이더넷 프레임");
        std::copy_n(data, 6, destMac.begin());
        std::copy_n(data + 6, 6, srcMac.begin());
        etherType = (data[12] << 8) | data[13];
    }

    std::string toString() const override {
        std::ostringstream oss;
        oss << "이더넷 계층 - 출발지: " << macToString(srcMac)
            << ", 목적지: " << macToString(destMac)
            << ", 타입: 0x" << std::hex << etherType;
        return oss.str();
    }

    ProtocolType getProtocolType() const override {
        return ProtocolType::Ethernet;
    }

    size_t getHeaderLength() const override {
        return 14;
    }

private:
    static std::string macToString(const std::array<uint8_t, 6>& mac) {
        std::ostringstream oss;
        for (size_t i = 0; i < 6; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
            if (i < 5) oss << ":";
        }
        return oss.str();
    }
};

class IPv4Layer : public Layer {
private:
    uint8_t version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndFragmentOffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint32_t srcIP;
    uint32_t destIP;

public:
    void parse(const uint8_t* data, size_t len) override {
        if (len < 20) throw std::runtime_error("유효하지 않은 IPv4 패킷");
        version = (data[0] >> 4) & 0xF;
        ihl = data[0] & 0xF;
        tos = data[1];
        totalLength = (data[2] << 8) | data[3];
        identification = (data[4] << 8) | data[5];
        flagsAndFragmentOffset = (data[6] << 8) | data[7];
        ttl = data[8];
        protocol = data[9];
        headerChecksum = (data[10] << 8) | data[11];
        srcIP = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
        destIP = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
    }

    std::string toString() const override {
        std::ostringstream oss;
        oss << "IPv4 계층 - 출발지: " << ipToString(srcIP)
            << ", 목적지: " << ipToString(destIP)
            << ", 프로토콜: " << static_cast<int>(protocol);
        return oss.str();
    }

    ProtocolType getProtocolType() const override {
        return ProtocolType::IPv4;
    }

    size_t getHeaderLength() const override {
        return ihl * 4;
    }

private:
    static std::string ipToString(uint32_t ip) {
        return std::to_string((ip >> 24) & 0xFF) + "." +
               std::to_string((ip >> 16) & 0xFF) + "." +
               std::to_string((ip >> 8) & 0xFF) + "." +
               std::to_string(ip & 0xFF);
    }
};

class TCPLayer : public Layer {
private:
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t seqNumber;
    uint32_t ackNumber;
    uint8_t dataOffset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;

public:
    void parse(const uint8_t* data, size_t len) override {
        if (len < 20) throw std::runtime_error("유효하지 않은 TCP 세그먼트");
        srcPort = (data[0] << 8) | data[1];
        destPort = (data[2] << 8) | data[3];
        seqNumber = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
        ackNumber = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
        dataOffset = (data[12] >> 4) & 0xF;
        flags = data[13];
        window = (data[14] << 8) | data[15];
        checksum = (data[16] << 8) | data[17];
        urgentPointer = (data[18] << 8) | data[19];
    }

    std::string toString() const override {
        std::ostringstream oss;
        oss << "TCP 계층 - 출발 포트: " << srcPort
            << ", 목적지 포트: " << destPort
            << ", 시퀀스: " << seqNumber
            << ", ACK: " << ackNumber;
        return oss.str();
    }

    ProtocolType getProtocolType() const override {
        return ProtocolType::TCP;
    }

    size_t getHeaderLength() const override {
        return dataOffset * 4;
    }
};

class EthernetDissector : public ProtocolDissector {
public:
    ProtocolType getProtocolType() const override {
        return ProtocolType::Ethernet;
    }

    std::unique_ptr<Layer> dissect(const uint8_t* data, size_t len) override {
        auto layer = std::make_unique<EthernetLayer>();
        layer->parse(data, len);
        return layer;
    }
};

class IPv4Dissector : public ProtocolDissector {
public:
    ProtocolType getProtocolType() const override {
        return ProtocolType::IPv4;
    }

    std::unique_ptr<Layer> dissect(const uint8_t* data, size_t len) override {
        auto layer = std::make_unique<IPv4Layer>();
        layer->parse(data, len);
        return layer;
    }
};

class TCPDissector : public ProtocolDissector {
public:
    ProtocolType getProtocolType() const override {
        return ProtocolType::TCP;
    }

    std::unique_ptr<Layer> dissect(const uint8_t* data, size_t len) override {
        auto layer = std::make_unique<TCPLayer>();
        layer->parse(data, len);
        return layer;
    }
};

class ProtocolFactory {
public:
    static std::unique_ptr<ProtocolDissector> createDissector(ProtocolType type) {
        switch (type) {
            case ProtocolType::Ethernet:
                return std::make_unique<EthernetDissector>();
            case ProtocolType::IPv4:
                return std::make_unique<IPv4Dissector>();
            case ProtocolType::TCP:
                return std::make_unique<TCPDissector>();
            default:
                return nullptr;
        }
    }
};

void write_to_csv(const std::string& filename, const std::string& data) {
    std::ofstream csvFile(filename, std::ios::app);
    if (csvFile.is_open()) {
        csvFile << data << std::endl;
    } else {
        std::cerr << "CSV 파일 열기 오류: " << filename << std::endl;
    }
}

std::string packet_info_to_csv(const struct pcap_pkthdr* pkthdr, const Layer* layer) {
    std::ostringstream oss;
    std::time_t timestamp = pkthdr->ts.tv_sec;
    std::tm* tm_info = std::localtime(&timestamp);
    oss << std::put_time(tm_info, "%Y-%m-%d %H:%M:%S") << "," << pkthdr->len << "," << layer->toString();
    return oss.str();
}

class PacketAnalyzer {
public:
    static void analyze_packet(const uint8_t* packet, const struct pcap_pkthdr* pkthdr, const std::string& csvFilename) {
        ProtocolType currentType = ProtocolType::Ethernet;
        const uint8_t* currentData = packet;
        size_t remainingLen = pkthdr->caplen;

        while (remainingLen > 0) {
            auto dissector = ProtocolFactory::createDissector(currentType);
            if (!dissector) break;

            auto layer = dissector->dissect(currentData, remainingLen);
            if (!layer) break;

            print_layer_info(layer.get());
            write_to_csv(csvFilename, packet_info_to_csv(pkthdr, layer.get()));

            currentType = getNextProtocolType(layer.get());
            currentData += layer->getHeaderLength();
            remainingLen -= layer->getHeaderLength();
        }
    }

private:
    static void print_layer_info(const Layer* layer) {
        std::cout << layer->toString() << std::endl;
    }

    static ProtocolType getNextProtocolType(const Layer* layer) {
        if (dynamic_cast<const EthernetLayer*>(layer)) {
            return ProtocolType::IPv4;
        } else if (dynamic_cast<const IPv4Layer*>(layer)) {
            return ProtocolType::TCP;
        }
        return ProtocolType::Ethernet;
    }
};

void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::string* csvFilename = reinterpret_cast<std::string*>(user);
    PacketAnalyzer::analyze_packet(packet, pkthdr, *csvFilename);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* allDevs;
    pcap_if_t* device = nullptr;

    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "장치 찾기 오류: " << errbuf << std::endl;
        return 1;
    }

    for (pcap_if_t* d = allDevs; d != nullptr; d = d->next) {
        std::cout << "인터페이스: " << d->name << std::endl;
    }

    std::string interfaceName;
    std::cout << "캡처할 인터페이스 이름을 입력하세요: ";
    std::cin >> interfaceName;

    for (pcap_if_t* d = allDevs; d != nullptr; d = d->next) {
        if (d->name == interfaceName) {
            device = d;
            break;
        }
    }

    if (device == nullptr) {
        std::cerr << "장치 " << interfaceName << "를 찾을 수 없습니다." << std::endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    const std::string csvFilename = "captured_packets.csv";
    write_to_csv(csvFilename, "타임스탬프,길이,프로토콜");

    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "장치 열기 오류 " << device->name << ": " << errbuf << std::endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    std::cout << "인터페이스 " << device->name << "에서 캡처 중" << std::endl;

    pcap_loop(handle, 100, packet_handler, reinterpret_cast<u_char*>(const_cast<std::string*>(&csvFilename)));

    pcap_close(handle);
    pcap_freealldevs(allDevs);

    std::cout << "패킷이 캡처되어 " << csvFilename << "에 저장되었습니다." << std::endl;

    return 0;
}