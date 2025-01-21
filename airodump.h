#ifndef AIRODUMP_H
#define AIRODUMP_H

#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <pcap.h>
#include <cstdint>
#include "ieee80211.h"

// AP 정보 구조체
struct ap_info {
    std::string bssid;
    int8_t  pwr;
    uint64_t beacon_count;
    uint64_t data_count;
    int     channel;
    std::string essid;
    std::string enc;
};

// Station(클라이언트) 정보 구조체
struct station_info {
    std::string mac;
    std::string bssid;
    int8_t  pwr;
    std::string probes;
};

// 전역 변수 선언 (정의는 단 하나의 소스파일에서 합니다)
extern std::unordered_map<std::string, ap_info>     g_ap_map;
extern std::unordered_map<std::string, station_info> g_station_map;
extern std::mutex g_data_mutex;
extern std::atomic<int> g_current_channel;

// 종료 플래그 (스레드 종료 조건)
extern std::atomic<bool> g_running;

// 함수 프로토타입
std::string mac_to_string(const uint8_t mac[6]);                  // MAC 주소를 문자열로 변환
void channel_hop_thread(const char *ifname);                      // 채널 호핑 스레드 함수
void init_ncurses();                                              // ncurses 초기화
void end_ncurses();                                               // ncurses 종료
void print_result_ncurses();                                      // ncurses 화면 출력
void parse_packet(const struct pcap_pkthdr *header, const u_char *packet); // 패킷 분석

void process_beacon_frame(const struct pcap_pkthdr *header, const ieee80211_frame *wifi, const u_char *packet);
void process_probe_request(const ieee80211_frame *wifi);
void process_station_frame(const ieee80211_frame *wifi);
void parse_tagged_params(const uint8_t *tagged_params, const uint8_t *packet_end,
                         std::string &essid, std::string &enc_str,
                         std::string &cipher_str, std::string &auth_str);

#endif // AIRODUMP_H
