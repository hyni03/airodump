#ifndef RADIOTAP_H
#define RADIOTAP_H

#include <stdint.h>

/*
 * 간단 버전 radiotap 헤더
 */
#pragma pack(push, 1)
typedef struct ieee80211_radiotap_header {
    uint8_t  it_version;     /* set to 0 */
    uint8_t  it_pad;
    uint16_t it_len;         /* 전체 radiotap header 길이 */
    uint32_t it_present;     /* 어떤 정보가 들어있는지 비트마스크 */
    // 이후 it_present 비트에 따라 다양한 필드가 따라옴 (RSSI, Channel 등)
} ieee80211_radiotap_header;
#pragma pack(pop)

#endif // RADIOTAP_H
