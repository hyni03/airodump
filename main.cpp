#include "airodump.h"
#include <iostream>
#include <csignal>
#include <thread>
#include <pcap.h>
#include <cstdlib>
#include <ctime>

using namespace std;

// 시그널 핸들러: g_running을 false로 설정하여 모든 스레드가 종료되도록 함.
void signal_handler(int signo) {
    (void)signo;
    g_running.store(false);
}

void usage(void) {
    cout << "syntax : airodump <interface>\n";
    cout << "sample : airodump mon0\n";
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return EXIT_FAILURE;
    }

    // ncurses 초기화
    init_ncurses();

    std::signal(SIGINT, [](int) {
        g_running.store(false);
    });

    std::thread hopper(channel_hop_thread, argv[1]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        g_running.store(false);
        hopper.join();
        end_ncurses();
        return EXIT_FAILURE;
    }

    time_t last_print = time(nullptr);
    while (g_running.load()) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) continue;           // timeout
        if (res == -1 || res == -2) break;  // error or EOF

        parse_packet(header, pkt_data);

        time_t now = time(nullptr);
        if (now - last_print >= 0.01) { // 매초 화면 갱신
            print_result_ncurses();
            last_print = now;
        }
    }

    pcap_close(handle);
    g_running.store(false);
    hopper.join();

    // ncurses 종료
    end_ncurses();

    return EXIT_SUCCESS;
}
