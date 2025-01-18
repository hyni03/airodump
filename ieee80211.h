#ifndef IEEE80211_H
#define IEEE80211_H

#include <stdint.h>

#define IEEE80211_FC0_TYPE_MASK        0x0c
#define IEEE80211_FC0_TYPE_MGT         0x00
#define IEEE80211_FC0_TYPE_CTL         0x04
#define IEEE80211_FC0_TYPE_DATA        0x08

#define IEEE80211_FC0_SUBTYPE_MASK     0xf0
#define IEEE80211_FC0_SUBTYPE_BEACON   0x80

#pragma pack(push, 1)

/*
 * 802.11 MAC 헤더(간단 버전)
 */
typedef struct ieee80211_frame {
    uint8_t i_fc[2];     // Frame Control (type/subtype 등)
    uint8_t i_dur[2];    // Duration
    uint8_t i_addr1[6];  // 수신 대상
    uint8_t i_addr2[6];  // 송신 주소
    uint8_t i_addr3[6];  // BSSID
    uint8_t i_seq[2];    // Sequence control
    // (Data frame에서는 이어서 addr4가 있을 수 있음)
} ieee80211_frame;

#pragma pack(pop)

#endif // IEEE80211_H
