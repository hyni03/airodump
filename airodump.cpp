// airodump.cpp
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

static const uint8_t RSN_OUI[3] = {0x00, 0x0F, 0xAC};
static const uint8_t WPA_OUI[3] = {0x00, 0x50, 0xF2};

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

// 채널 변경 함수
void set_channel(const char *ifname, int channel) {
    struct iwreq wrq;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    std::memset(&wrq, 0, sizeof(wrq));
    std::strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
    wrq.u.freq.m = channel;
    wrq.u.freq.e = 0;
    if (ioctl(sock, SIOCSIWFREQ, &wrq) < 0) {
        perror("ioctl(SIOCSIWFREQ)");
    }
    close(sock);
}

// 채널 호핑 스레드 함수
void channel_hop_thread(const char *ifname) {
    static int ch_list[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    int idx = 0;
    const int hop_interval = 1; // 초

    while (g_running.load()) {
        int ch = ch_list[idx];
        set_channel(ifname, ch);
        g_current_channel.store(ch);

        idx = (idx + 3) % (sizeof(ch_list) / sizeof(ch_list[0]));
        std::this_thread::sleep_for(std::chrono::seconds(hop_interval));
    }
}

// ncurses 초기화
void init_ncurses() {
    initscr();            
    cbreak();             
    noecho();             
    curs_set(0);          
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE); 
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

    clear(); 

    mvprintw(0, 0, "[ CH %d ] [ %s ]", current_ch, time_str);

    mvprintw(2, 0, " BSSID              PWR   Beacons  #Data  CH  ENC       ESSID");
    int row = 3;
    for (const auto &kv : g_ap_map) {
        const ap_info &ap = kv.second;
        mvprintw(row++, 0, " %-17s %4d %8lu %5lu %2d %-8s %s",
                 ap.bssid.c_str(), (int)ap.pwr, (unsigned long)ap.beacon_count,
                 (unsigned long)ap.data_count, ap.channel, ap.enc.c_str(),
                 ap.essid.c_str());
    }

    row += 1; 
    mvprintw(row++, 0, " BSSID              STATION            PWR   Rate    Lost    Frames  Notes           Probes");
    for (const auto &station_kv : g_station_map) {
        const station_info &station = station_kv.second;

        auto ap_it = g_ap_map.find(station.bssid);
        const ap_info *ap = (ap_it != g_ap_map.end()) ? &ap_it->second : nullptr;

        int rate = ap ? ap->data_count * 10 : 0;
        int lost = ap ? (ap->beacon_count - ap->data_count) : 0;
        int frames = ap ? ap->data_count : 0;
        std::string notes = (ap && ap->enc == "OPN") ? "Open Network" : "Secured";
        std::string probes = station.probes.empty() ? "<no probes>" : station.probes;

        mvprintw(row++, 0, " %-17s %-17s %4d %6d %6d %7d %-14s %s",
                 (ap ? ap->bssid.c_str() : "Unknown"), station.mac.c_str(),
                 (int)station.pwr, rate, lost, frames, notes.c_str(), probes.c_str());
    }

    wnoutrefresh(stdscr); 
    doupdate(); 
}

// 공통 Station 업데이트 로직
void update_station_info(const std::string &mac, const std::string &bssid, int8_t rssi) {
    std::lock_guard<std::mutex> lock(g_data_mutex);

    auto st_it = g_station_map.find(mac);
    if (st_it == g_station_map.end()) {
        station_info st = {mac, bssid, rssi, ""};
        g_station_map[mac] = st;
    } else {
        st_it->second.pwr = rssi;
    }
}

// 패킷 파싱 함수
void parse_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    if (!header || !packet) return;

    const ieee80211_radiotap_header *rtap = reinterpret_cast<const ieee80211_radiotap_header *>(packet);
    uint16_t radiotap_len = rtap->it_len;
    const ieee80211_frame *wifi = reinterpret_cast<const ieee80211_frame *>(packet + radiotap_len);

    uint8_t fc0 = wifi->i_fc[0];
    uint8_t type = fc0 & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = fc0 & IEEE80211_FC0_SUBTYPE_MASK;

    if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
        process_beacon_frame(header, wifi, packet);
    } else if (type == IEEE80211_FC0_TYPE_MGT && subtype == 0x40) {
        update_station_info(mac_to_string(wifi->i_addr2), mac_to_string(wifi->i_addr3), -60);
    } else {
        update_station_info(mac_to_string(wifi->i_addr2), "", -60);
    }
}

// Beacon 프레임 처리
void process_beacon_frame(const struct pcap_pkthdr *header, const ieee80211_frame *wifi, const u_char *packet) {
    uint8_t bssid_mac[6];
    std::memcpy(bssid_mac, wifi->i_addr3, 6);
    std::string bssid_str = mac_to_string(bssid_mac);

    int8_t rssi = -60;
    const uint8_t *mgmt_body = reinterpret_cast<const uint8_t *>(wifi) + 24;

    const uint8_t *tagged_params = mgmt_body + 12;
    const uint8_t *packet_end = packet + header->caplen;

    std::string essid, enc_str, cipher_str, auth_str;
    parse_tagged_params(tagged_params, packet_end, essid, enc_str, cipher_str, auth_str);

    if (!cipher_str.empty()) enc_str += " " + cipher_str;
    if (!auth_str.empty()) enc_str += " " + auth_str;

    {
        std::lock_guard<std::mutex> lock(g_data_mutex);
        auto it = g_ap_map.find(bssid_str);
        if (it == g_ap_map.end()) {
            ap_info ap = {bssid_str, rssi, 1, 0, g_current_channel.load(), essid, enc_str};
            g_ap_map[bssid_str] = ap;
        } else {
            it->second.pwr = rssi;
            it->second.beacon_count++;
            if (it->second.essid.empty()) it->second.essid = essid;
            it->second.enc = enc_str;
        }
    }
}

// Tagged Parameters 파싱
void parse_tagged_params(const uint8_t *tagged_params, const uint8_t *packet_end,
                         std::string &essid, std::string &enc_str,
                         std::string &cipher_str, std::string &auth_str) {
    bool isWEP = false, isWPA = false, isWPA2 = false;

    while (tagged_params + 2 < packet_end) {
        uint8_t tag_number = tagged_params[0];
        uint8_t tag_length = tagged_params[1];
        const uint8_t *tag_value = tagged_params + 2;

        if (tag_value + tag_length > packet_end) break;

        switch (tag_number) {
            case 0:
                essid = (tag_length > 0) ? std::string(reinterpret_cast<const char *>(tag_value), tag_length)
                                         : "<hidden SSID>";
                break;
            case 48:
                isWPA2 = true;
                if (tag_length >= 6 && !std::memcmp(tag_value + 2, RSN_OUI, 3)) {
                    cipher_str = (*(tag_value + 5) == 4) ? "CCMP" : "TKIP";
                }
                auth_str = "PSK";
                break;
            case 221:
                if (tag_length >= 4 && !std::memcmp(tag_value, WPA_OUI, 3) && tag_value[3] == 0x01) {
                    isWPA = true;
                    cipher_str = "TKIP";
                    auth_str = "PSK";
                }
                break;
        }
        tagged_params += 2 + tag_length;
    }

    enc_str = isWPA2 ? "WPA2" : isWPA ? "WPA" : isWEP ? "WEP" : "OPN";
}
