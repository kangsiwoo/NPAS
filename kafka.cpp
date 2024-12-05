#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <pcap.h>
#include <librdkafka/rdkafkacpp.h>
#include <hiredis/hiredis.h>
#include <stdexcept>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// Kafka 프로듀서 설정
std::string brokers = "localhost:9092";
std::string topic = "my-topic";
RdKafka::Producer* producer = nullptr;

// Redis 연결 설정
redisContext* redis = nullptr;

// 패킷 처리 함수
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // 이더넷 헤더 건너뛰기
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        std::string packetInfo = std::string(src_ip) + ":" + std::to_string(ntohs(tcp_header->th_sport)) +
                                 " -> " + std::string(dst_ip) + ":" + std::to_string(ntohs(tcp_header->th_dport));

        RdKafka::ErrorCode err = producer->produce(
            topic,
            RdKafka::Topic::PARTITION_UA,
            RdKafka::Producer::RK_MSG_COPY,
            const_cast<char*>(packetInfo.c_str()),
            packetInfo.size(),
            nullptr,
            nullptr
        );

        if (err != RdKafka::ERR_NO_ERROR) {
            std::cerr << "Kafka 메시지 전송 실패: " << RdKafka::err2str(err) << std::endl;
        }
    }
}

// Kafka 컨슈머 및 Redis 저장 함수
void consumeAndStore()
{
    // 이전 코드와 동일
}

int main()
{
    try {
        // Kafka 프로듀서 초기화
        std::string errstr;
        RdKafka::Conf* conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
        if (conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK) {
            throw std::runtime_error("Kafka 설정 실패: " + errstr);
        }
        producer = RdKafka::Producer::create(conf, errstr);
        if (!producer) {
            throw std::runtime_error("Kafka 프로듀서 생성 실패: " + errstr);
        }
        delete conf;

        // Redis 연결
        redis = redisConnect("127.0.0.1", 6379);
        if (redis == nullptr || redis->err) {
            throw std::runtime_error("Redis 연결 실패: " + (redis ? std::string(redis->errstr) : "알 수 없는 오류"));
        }

        // 패킷 캡처 시작
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            throw std::runtime_error("장치를 열 수 없습니다: " + std::string(errbuf));
        }

        // Kafka 컨슈머 및 Redis 저장 스레드 시작
        std::thread consumerThread(consumeAndStore);

        // 패킷 캡처 시작
        std::cout << "패킷 캡처 중... 중지하려면 Ctrl+C를 누르세요" << std::endl;
        pcap_loop(handle, -1, packet_handler, nullptr);

        // 리소스 정리
        pcap_close(handle);
        delete producer;
        redisFree(redis);

        consumerThread.join();

    } catch (const std::exception& e) {
        std::cerr << "오류 발생: " << e.what() << std::endl;
        if (producer) delete producer;
        if (redis) redisFree(redis);
        return 1;
    }

    return 0;
}