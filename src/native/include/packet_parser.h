#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #ifdef BUILDING_PACKET_PARSER
    #define NS_EXPORT __declspec(dllexport)
  #else
    #define NS_EXPORT __declspec(dllimport)
  #endif
#else
  #define NS_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Ethernet & ARP protocol constants */
#define ETH_HEADER_LEN      14
#define VLAN_HEADER_LEN     4
#define ARP_IPV4_HEADER_LEN 28
#define MIN_ARP_FRAME_LEN   (ETH_HEADER_LEN + ARP_IPV4_HEADER_LEN)

#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_VLAN      0x8100
#define ETHERTYPE_QINQ      0x88A8

#define ARP_HTYPE_ETHERNET  1
#define ARP_PTYPE_IPV4      0x0800
#define ARP_HLEN_ETHERNET   6
#define ARP_PLEN_IPV4       4

#define ARP_OP_REQUEST      1
#define ARP_OP_REPLY        2

/* Parsed ARP packet structure shared across C and Python ctypes */
typedef struct {
    char src_mac[18];       /* ARP Sender MAC ("AA:BB:CC:DD:EE:FF") */
    char dst_mac[18];       /* ARP Target MAC ("AA:BB:CC:DD:EE:FF") */
    char eth_src_mac[18];   /* Ethernet Frame Source MAC */
    char eth_dst_mac[18];   /* Ethernet Frame Destination MAC */
    char src_ip[16];        /* ARP Sender IPv4 ("192.168.1.1") */
    char dst_ip[16];        /* ARP Target IPv4 ("192.168.1.254") */
    int opcode;             /* 1 = ARP Request, 2 = ARP Reply */
    int is_gratuitous;      /* 1 if Gratuitous ARP (src_ip == dst_ip) */
    int mac_mismatch;       /* 1 if Ethernet src_mac != ARP src_mac (Spoofing anomaly) */
    int vlan_id;            /* 802.1Q VLAN ID or -1 if untagged */
    int is_valid;           /* 1 if successfully parsed as IPv4-over-Ethernet ARP */
} ParsedArpPacket;

/* Parsed IPv4 header summary for general traffic inspection */
typedef struct {
    char src_mac[18];
    char dst_mac[18];
    char src_ip[16];
    char dst_ip[16];
    int protocol;           /* 1 = ICMP, 6 = TCP, 17 = UDP */
    int src_port;           /* TCP/UDP source port or 0 */
    int dst_port;           /* TCP/UDP destination port or 0 */
    int ttl;                /* IPv4 Time-To-Live */
    int total_length;       /* IPv4 total packet length */
    int is_valid;
} ParsedIpPacket;

/**
 * Parse a raw Ethernet frame containing an ARP packet (supports optional 802.1Q VLAN tag).
 * Returns 0 on success (and sets out_pkt->is_valid = 1), or a negative error code on failure:
 *  -1: NULL pointer argument
 *  -2: Frame too short (< 42 bytes, or < 46 bytes for VLAN-tagged frame)
 *  -3: Not an ARP frame (EtherType != 0x0806)
 *  -4: Unsupported ARP hardware/protocol type or length (not Ethernet/IPv4)
 */
NS_EXPORT int parse_arp_packet(
    const uint8_t *raw_bytes,
    size_t length,
    ParsedArpPacket *out_pkt
);

/**
 * Parse a raw Ethernet frame containing an IPv4 packet.
 * Returns 0 on success, negative error code on failure.
 */
NS_EXPORT int parse_ipv4_packet(
    const uint8_t *raw_bytes,
    size_t length,
    ParsedIpPacket *out_pkt
);

/**
 * Construct a raw 42-byte Ethernet + IPv4 ARP frame in `out_buffer`.
 * Returns 42 on success, or negative error code on invalid parameters.
 */
NS_EXPORT int build_arp_frame(
    const uint8_t eth_dst[6],
    const uint8_t eth_src[6],
    uint16_t opcode,
    const uint8_t sender_mac[6],
    const uint8_t sender_ip[4],
    const uint8_t target_mac[6],
    const uint8_t target_ip[4],
    uint8_t *out_buffer,
    size_t buffer_capacity
);

/**
 * Check whether Npcap / WinPcap (wpcap.dll) or libpcap (libpcap.so) is dynamically
 * available on the current host OS. Returns 1 if available, 0 otherwise.
 */
NS_EXPORT int is_pcap_available(void);

/**
 * Return the version string of the Native C Packet Engine.
 */
NS_EXPORT const char* packet_engine_version(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_PARSER_H */
