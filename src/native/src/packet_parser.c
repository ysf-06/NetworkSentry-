#ifndef BUILDING_PACKET_PARSER
#define BUILDING_PACKET_PARSER
#endif
#include "../include/packet_parser.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <dlfcn.h>
#endif

static const char HEX_DIGITS[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static void format_mac_fast(const uint8_t mac[6], char out_str[18]) {
    int i;
    for (i = 0; i < 6; ++i) {
        uint8_t b = mac[i];
        out_str[i * 3]     = HEX_DIGITS[(b >> 4) & 0x0F];
        out_str[i * 3 + 1] = HEX_DIGITS[b & 0x0F];
        if (i < 5) {
            out_str[i * 3 + 2] = ':';
        }
    }
    out_str[17] = '\0';
}

static void format_ipv4_fast(const uint8_t ip[4], char out_str[16]) {
    snprintf(
        out_str,
        16,
        "%u.%u.%u.%u",
        (unsigned int)ip[0],
        (unsigned int)ip[1],
        (unsigned int)ip[2],
        (unsigned int)ip[3]
    );
    out_str[15] = '\0';
}

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

NS_EXPORT int parse_arp_packet(
    const uint8_t *raw_bytes,
    size_t length,
    ParsedArpPacket *out_pkt
) {
    if (out_pkt != NULL) {
        memset(out_pkt, 0, sizeof(ParsedArpPacket));
        out_pkt->vlan_id = -1;
    }

    if (raw_bytes == NULL || out_pkt == NULL) {
        return -1;
    }

    if (length < MIN_ARP_FRAME_LEN) {
        return -2;
    }

    const uint8_t *eth_dst = raw_bytes;
    const uint8_t *eth_src = raw_bytes + 6;
    uint16_t ethertype = read_be16(raw_bytes + 12);
    size_t arp_offset = ETH_HEADER_LEN;

    /* Handle up to 2 IEEE 802.1Q / 802.1ad (QinQ) VLAN tags */
    int vlan_tags = 0;
    while ((ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) && vlan_tags < 2) {
        if (length < arp_offset + VLAN_HEADER_LEN + ARP_IPV4_HEADER_LEN) {
            return -2;
        }
        uint16_t tci = read_be16(raw_bytes + arp_offset);
        out_pkt->vlan_id = (int)(tci & 0x0FFF);
        ethertype = read_be16(raw_bytes + arp_offset + 2);
        arp_offset += VLAN_HEADER_LEN;
        vlan_tags++;
    }

    if (ethertype != ETHERTYPE_ARP) {
        return -3;
    }

    const uint8_t *arp = raw_bytes + arp_offset;
    uint16_t htype  = read_be16(arp + 0);
    uint16_t ptype  = read_be16(arp + 2);
    uint8_t  hlen   = arp[4];
    uint8_t  plen   = arp[5];
    uint16_t opcode = read_be16(arp + 6);

    if (htype != ARP_HTYPE_ETHERNET ||
        ptype != ARP_PTYPE_IPV4 ||
        hlen != ARP_HLEN_ETHERNET ||
        plen != ARP_PLEN_IPV4 ||
        (opcode != ARP_OP_REQUEST && opcode != ARP_OP_REPLY)) {
        return -4;
    }

    const uint8_t *sha = arp + 8;   /* Sender Hardware Address (6 bytes) */
    const uint8_t *spa = arp + 14;  /* Sender Protocol Address (4 bytes) */
    const uint8_t *tha = arp + 18;  /* Target Hardware Address (6 bytes) */
    const uint8_t *tpa = arp + 24;  /* Target Protocol Address (4 bytes) */

    format_mac_fast(sha, out_pkt->src_mac);
    format_mac_fast(tha, out_pkt->dst_mac);
    format_mac_fast(eth_src, out_pkt->eth_src_mac);
    format_mac_fast(eth_dst, out_pkt->eth_dst_mac);

    format_ipv4_fast(spa, out_pkt->src_ip);
    format_ipv4_fast(tpa, out_pkt->dst_ip);

    out_pkt->opcode = (int)opcode;
    out_pkt->is_gratuitous = (memcmp(spa, tpa, 4) == 0) ? 1 : 0;
    out_pkt->mac_mismatch = (memcmp(eth_src, sha, 6) != 0) ? 1 : 0;
    out_pkt->is_valid = 1;

    return 0;
}

NS_EXPORT int parse_ipv4_packet(
    const uint8_t *raw_bytes,
    size_t length,
    ParsedIpPacket *out_pkt
) {
    if (out_pkt != NULL) {
        memset(out_pkt, 0, sizeof(ParsedIpPacket));
    }

    if (raw_bytes == NULL || out_pkt == NULL) {
        return -1;
    }

    if (length < ETH_HEADER_LEN + 20) {
        return -2;
    }

    const uint8_t *eth_dst = raw_bytes;
    const uint8_t *eth_src = raw_bytes + 6;
    uint16_t ethertype = read_be16(raw_bytes + 12);
    size_t ip_offset = ETH_HEADER_LEN;

    int vlan_tags = 0;
    while ((ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) && vlan_tags < 2) {
        if (length < ip_offset + VLAN_HEADER_LEN + 20) {
            return -2;
        }
        ethertype = read_be16(raw_bytes + ip_offset + 2);
        ip_offset += VLAN_HEADER_LEN;
        vlan_tags++;
    }

    if (ethertype != ETHERTYPE_IPV4) {
        return -3;
    }

    const uint8_t *ip = raw_bytes + ip_offset;
    uint8_t version = (ip[0] >> 4) & 0x0F;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    uint16_t total_len = read_be16(ip + 2);

    if (version != 4 || ihl < 20 || length < ip_offset + ihl || total_len < ihl) {
        return -4;
    }

    format_mac_fast(eth_src, out_pkt->src_mac);
    format_mac_fast(eth_dst, out_pkt->dst_mac);
    format_ipv4_fast(ip + 12, out_pkt->src_ip);
    format_ipv4_fast(ip + 16, out_pkt->dst_ip);

    out_pkt->total_length = (int)total_len;
    out_pkt->ttl = (int)ip[8];
    out_pkt->protocol = (int)ip[9];

    /* Extract TCP (6) or UDP (17) ports if transport header is present */
    if ((out_pkt->protocol == 6 || out_pkt->protocol == 17) &&
        length >= ip_offset + ihl + 4) {
        const uint8_t *l4 = ip + ihl;
        out_pkt->src_port = (int)read_be16(l4 + 0);
        out_pkt->dst_port = (int)read_be16(l4 + 2);
        if (out_pkt->protocol == 6 && length >= ip_offset + ihl + 14) {
            out_pkt->tcp_flags = (int)(l4[13] & 0x3F);
        }
    }

    out_pkt->is_valid = 1;
    return 0;
}

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
) {
    if (eth_dst == NULL || eth_src == NULL || sender_mac == NULL ||
        sender_ip == NULL || target_mac == NULL || target_ip == NULL ||
        out_buffer == NULL) {
        return -1;
    }

    if (buffer_capacity < MIN_ARP_FRAME_LEN) {
        return -2;
    }

    /* Ethernet Header (14 bytes) */
    memcpy(out_buffer + 0, eth_dst, 6);
    memcpy(out_buffer + 6, eth_src, 6);
    out_buffer[12] = 0x08;
    out_buffer[13] = 0x06; /* EtherType: ARP (0x0806) */

    /* ARP Header (28 bytes) */
    out_buffer[14] = 0x00;
    out_buffer[15] = 0x01; /* HTYPE: Ethernet (1) */
    out_buffer[16] = 0x08;
    out_buffer[17] = 0x00; /* PTYPE: IPv4 (0x0800) */
    out_buffer[18] = 6;    /* HLEN: 6 */
    out_buffer[19] = 4;    /* PLEN: 4 */
    out_buffer[20] = (uint8_t)((opcode >> 8) & 0xFF);
    out_buffer[21] = (uint8_t)(opcode & 0xFF);

    memcpy(out_buffer + 22, sender_mac, 6);
    memcpy(out_buffer + 28, sender_ip, 4);
    memcpy(out_buffer + 32, target_mac, 6);
    memcpy(out_buffer + 38, target_ip, 4);

    return MIN_ARP_FRAME_LEN;
}

NS_EXPORT int is_pcap_available(void) {
#ifdef _WIN32
    HMODULE hMod = LoadLibraryA("wpcap.dll");
    if (hMod == NULL) {
        hMod = LoadLibraryExA(
            "C:\\Windows\\System32\\Npcap\\wpcap.dll",
            NULL,
            LOAD_WITH_ALTERED_SEARCH_PATH
        );
    }
    if (hMod != NULL) {
        FreeLibrary(hMod);
        return 1;
    }
    return 0;
#else
    void *handle = dlopen("libpcap.so.0.8", RTLD_LAZY);
    if (!handle) {
        handle = dlopen("libpcap.so", RTLD_LAZY);
    }
    if (handle != NULL) {
        dlclose(handle);
        return 1;
    }
    return 0;
#endif
}

NS_EXPORT const char* packet_engine_version(void) {
    return "NetworkSentry-NativeEngine/1.3.0";
}

