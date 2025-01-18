#include "airodump.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <cstdlib>
#include <ncurses.h>
#include "radiotap.h"
#include "ieee80211.h"

#ifndef WLAN_CAPABILITY_PRIVACY
#define WLAN_CAPABILITY_PRIVACY 0x0010
#endif

static const uint8_t RSN_OUI[3] = { 0x00, 0x0F, 0xAC };
static const uint8_t WPA_OUI[3] = { 0x00, 0x50, 0xF2 };

// 전역 변수 정의
std::unordered_map<std::string, ap_info> g_ap_map;
std::unordered_map<std::string, station_info> g_station_map;
std::mutex g_data_mutex;
std::atomic<int> g_current_channel(0);
std::atomic<bool> g_running(true);

// MAC 배열 -> 문자열 변환 함수
std::string mac_to_string(const uint8_t mac[6]) {
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[0];
    for (int i = 1; i < 6; i++) {
        oss << ":" << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    return oss.str();
}

// 채널 호핑 스레드 함수: g_running가 false가 될 때까지 루프
void channel_hop_thread(const char *ifname) {
    static int ch_list[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    int idx = 0;
    const int hop_interval = 1; // 초

    while (g_running.load()) {
        int ch = ch_list[idx];

        {
            std::lock_guard<std::mutex> lock(g_data_mutex);
            struct iwreq wrq;
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) {
                perror("socket");
            } else {
                std::memset(&wrq, 0, sizeof(wrq));
                std::strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
                wrq.u.freq.m = ch; // 채널 번호
                wrq.u.freq.e = 0;
                if (ioctl(sock, SIOCSIWFREQ, &wrq) < 0) {
                    perror("ioctl(SIOCSIWFREQ)");
                }
                close(sock);
            }
            g_current_channel.store(ch);
        }

        idx = (idx + 3) % (sizeof(ch_list) / sizeof(ch_list[0]));
        std::this_thread::sleep_for(std::chrono::seconds(hop_interval));
    }
}


// ncurses 초기화
void init_ncurses() {
    initscr();            // ncurses 초기화
    cbreak();             // 라인 버퍼 비활성화
    noecho();             // 입력된 문자를 화면에 출력하지 않음
    curs_set(0);          // 커서 숨김
    nodelay(stdscr, TRUE); // 입력이 없을 경우 블록되지 않음
    keypad(stdscr, TRUE); // 특수 키 지원
}

// ncurses 종료
void end_ncurses() {
    endwin();
}

// ncurses 출력 함수
void print_result_ncurses() {
    std::lock_guard<std::mutex> lock(g_data_mutex);
    int current_ch = g_current_channel.load();

    time_t now = time(nullptr);
    tm *tm_struct = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_struct);

    clear(); // 화면 초기화

    // 상단 정보 출력
    mvprintw(0, 0, "[ CH %d ] [ %s ]", current_ch, time_str);

    // AP 정보 출력
    mvprintw(2, 0, " BSSID              PWR   Beacons  #Data  CH  ENC       ESSID");
    int row = 3;
    for (const auto &kv : g_ap_map) {
        const ap_info &ap = kv.second;
        mvprintw(row++, 0, " %-17s %4d %8lu %5lu %2d %-8s %s",
                 ap.bssid.c_str(), (int)ap.pwr, (unsigned long)ap.beacon_count,
                 (unsigned long)ap.data_count, ap.channel, ap.enc.c_str(),
                 ap.essid.c_str());
    }

    // Station 정보 출력
    row += 1; // 빈 줄 추가
    mvprintw(row++, 0, " BSSID              STATION            PWR   Rate    Lost    Frames  Notes           Probes");
    for (const auto &station_kv : g_station_map) {
        const station_info &station = station_kv.second;

        // BSSID를 기준으로 AP를 찾음
        auto ap_it = g_ap_map.find(station.bssid);
        const ap_info *ap = (ap_it != g_ap_map.end()) ? &ap_it->second : nullptr;

        // 데이터 계산
        int rate = ap ? ap->data_count * 10 : 0; // 단순 예제: data_count 기반 계산
        int lost = ap ? (ap->beacon_count - ap->data_count) : 0; // 손실 계산
        int frames = ap ? ap->data_count : 0; // 전송된 프레임 수
        std::string notes = (ap && ap->enc == "OPN") ? "Open Network" : "Secured";
        std::string probes = station.probes.empty() ? "<no probes>" : station.probes;

        mvprintw(row++, 0, " %-17s %-17s %4d %6d %6d %7d %-14s %s",
                 (ap ? ap->bssid.c_str() : "Unknown"), station.mac.c_str(),
                 (int)station.pwr, rate, lost, frames, notes.c_str(), probes.c_str());
    }

    // 변경된 부분만 출력
    wnoutrefresh(stdscr); 
    doupdate(); // 실제 화면 업데이트
}

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) return;

    const ieee80211_radiotap_header *rtap =
        reinterpret_cast<const ieee80211_radiotap_header *>(packet);
    uint16_t radiotap_len = rtap->it_len;

    const ieee80211_frame *wifi =
        reinterpret_cast<const ieee80211_frame *>(packet + radiotap_len);

    uint8_t fc0 = wifi->i_fc[0];
    uint8_t type    = fc0 & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = fc0 & IEEE80211_FC0_SUBTYPE_MASK;

    std::string bssid_str;
    int8_t rssi = -100;

    // Beacon Frame 처리 (Management frame, subtype Beacon)
    if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
        uint8_t bssid_mac[6];
        std::memcpy(bssid_mac, wifi->i_addr3, 6);
        bssid_str = mac_to_string(bssid_mac);

        rssi = -60;  // 예시 RSSI

        const uint8_t *mgmt_body = reinterpret_cast<const uint8_t *>(wifi) + 24;
        uint16_t capab = mgmt_body[10] | (mgmt_body[11] << 8);

        const uint8_t *tagged_params = mgmt_body + 12;
        const uint8_t *packet_end = packet + header->caplen;

        bool isWEP  = false;
        bool isWPA  = false;
        bool isWPA2 = false;
        std::string cipher_str;
        std::string auth_str;
        std::string essid;

        if (capab & WLAN_CAPABILITY_PRIVACY) {
            isWEP = true;
        }

        while (tagged_params + 2 < packet_end) {
            uint8_t tag_number = tagged_params[0];
            uint8_t tag_length = tagged_params[1];
            const uint8_t *tag_value = tagged_params + 2;
            if (tag_value + tag_length > packet_end) break;

            switch (tag_number) {
                case 0: // SSID
                    if (tag_length > 0)
                        essid.assign(reinterpret_cast<const char*>(tag_value), tag_length);
                    else
                        essid = "<hidden SSID>";
                    break;
                case 48: // RSN = WPA2
                    isWPA2 = true;
                    isWEP  = false;
                    if (tag_length >= 6) {
                        const uint8_t *group_oui = tag_value + 2;
                        uint8_t group_cipher_type = *(tag_value + 5);
                        if (!std::memcmp(group_oui, RSN_OUI, 3)) {
                            switch (group_cipher_type) {
                                case 2: cipher_str = "TKIP"; break;
                                case 4: cipher_str = "CCMP"; break;
                                default: cipher_str = "?"; break;
                            }
                        }
                    }
                    auth_str = "PSK";
                    break;
                case 221: // WPA
                    if (tag_length >= 4) {
                        if (!std::memcmp(tag_value, WPA_OUI, 3) && tag_value[3] == 0x01) {
                            isWPA  = true;
                            isWEP  = false;
                            cipher_str = "TKIP";
                            auth_str   = "PSK";
                        }
                    }
                    break;
                default:
                    break;
            }
            tagged_params += (2 + tag_length);
        }

        std::string enc_str;
        if (isWPA2) enc_str = "WPA2";
        else if (isWPA) enc_str = "WPA";
        else if (isWEP) enc_str = "WEP";
        else enc_str = "OPN";

        std::string final_enc = enc_str;
        if (!cipher_str.empty()) final_enc += " " + cipher_str;
        if (!auth_str.empty())   final_enc += " " + auth_str;

        {
            std::lock_guard<std::mutex> lock(g_data_mutex);
            auto it = g_ap_map.find(bssid_str);
            if (it == g_ap_map.end()) {
                ap_info ap;
                ap.bssid        = bssid_str;
                ap.pwr          = rssi;
                ap.beacon_count = 1;
                ap.data_count   = 0;
                ap.channel      = g_current_channel.load();
                ap.essid        = essid;
                ap.enc          = final_enc;
                g_ap_map[bssid_str] = ap;
            } else {
                it->second.pwr = rssi;
                it->second.beacon_count++;
                if (it->second.essid.empty())
                    it->second.essid = essid;
                it->second.enc = final_enc;
            }
        }
    }
    // Station 처리 (Data/Probe Frame 등)
    {
        uint8_t sta_mac[6];
        std::memcpy(sta_mac, wifi->i_addr2, 6); // 송신 MAC 주소 (Station 주소)
        std::string sta_str = mac_to_string(sta_mac);

        std::lock_guard<std::mutex> lock(g_data_mutex);

        // Station 정보가 없으면 새로 추가
        auto st_it = g_station_map.find(sta_str);
        if (st_it == g_station_map.end()) {
            station_info st;
            st.mac = sta_str;
            st.bssid = bssid_str; // Beacon에서 추출된 BSSID를 사용
            st.pwr = rssi;        // 수신 신호 강도 (RSSI)
            st.probes = "";       // 초기 프로브 리스트
            g_station_map[sta_str] = st;
        } else {
            // 이미 존재하는 Station이면 정보 업데이트
            st_it->second.pwr = rssi;

            // Probe Request 프레임 처리
            if (type == IEEE80211_FC0_TYPE_MGT && subtype == 0x40) { // 0x40: Probe Request
                const uint8_t *probe_ssid_tag = reinterpret_cast<const uint8_t *>(wifi) + 24;
                uint8_t tag_number = probe_ssid_tag[0];
                uint8_t tag_length = probe_ssid_tag[1];
                if (tag_number == 0 && tag_length > 0) { // SSID Tag
                    std::string probe_ssid(reinterpret_cast<const char *>(probe_ssid_tag + 2), tag_length);
                    if (!probe_ssid.empty()) {
                        if (st_it->second.probes.find(probe_ssid) == std::string::npos) {
                            if (!st_it->second.probes.empty()) {
                                st_it->second.probes += ", ";
                            }
                            st_it->second.probes += probe_ssid;
                        }
                    }
                }
            }
        }
    }

}
