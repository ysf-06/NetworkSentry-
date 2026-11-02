#include "../include/packet_parser.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void test_valid_arp_request_and_reply(void) {
    uint8_t frame[64];
    ParsedArpPacket pkt;

    const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t sender_mac[6]    = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
    const uint8_t zero_mac[6]      = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t sender_ip[4]     = {192, 168, 1, 10};
    const uint8_t target_ip[4]     = {192, 168, 1, 1};

    int built = build_arp_frame(
        broadcast_mac, sender_mac, ARP_OP_REQUEST,
        sender_mac, sender_ip, zero_mac, target_ip,
        frame, sizeof(frame)
    );
    assert(built == 42);

    int rc = parse_arp_packet(frame, (size_t)built, &pkt);
    assert(rc == 0);
    assert(pkt.is_valid == 1);
    assert(pkt.opcode == 1);
    assert(pkt.is_gratuitous == 0);
    assert(pkt.mac_mismatch == 0);
    assert(pkt.vlan_id == -1);
    assert(strcmp(pkt.src_mac, "AA:BB:CC:11:22:33") == 0);
    assert(strcmp(pkt.dst_mac, "00:00:00:00:00:00") == 0);
    assert(strcmp(pkt.eth_dst_mac, "FF:FF:FF:FF:FF:FF") == 0);
    assert(strcmp(pkt.src_ip, "192.168.1.10") == 0);
    assert(strcmp(pkt.dst_ip, "192.168.1.1") == 0);
}

static void test_gratuitous_and_mac_mismatch_spoofing(void) {
    uint8_t frame[64];
    ParsedArpPacket pkt;

    const uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t eth_src_mac[6]   = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const uint8_t arp_sha_mac[6]   = {0x50, 0xC7, 0xBF, 0x00, 0x00, 0x01};
    const uint8_t gw_ip[4]         = {192, 168, 1, 1};

    int built = build_arp_frame(
        broadcast_mac, eth_src_mac, ARP_OP_REPLY,
        arp_sha_mac, gw_ip, broadcast_mac, gw_ip,
        frame, sizeof(frame)
    );
    assert(built == 42);

    int rc = parse_arp_packet(frame, (size_t)built, &pkt);
    assert(rc == 0);
    assert(pkt.is_valid == 1);
    assert(pkt.opcode == 2);
    assert(pkt.is_gratuitous == 1);
    assert(pkt.mac_mismatch == 1);
    assert(strcmp(pkt.eth_src_mac, "DE:AD:BE:EF:00:01") == 0);
    assert(strcmp(pkt.src_mac, "50:C7:BF:00:00:01") == 0);
}

static void test_malformed_and_truncated_packets(void) {
    uint8_t short_buf[20] = {0};
    ParsedArpPacket pkt;

    assert(parse_arp_packet(NULL, 42, &pkt) == -1);
    assert(parse_arp_packet(short_buf, 42, NULL) == -1);
    assert(parse_arp_packet(short_buf, 20, &pkt) == -2);
    assert(pkt.is_valid == 0);

    /* Non-ARP EtherType (0x0800 IPv4) */
    uint8_t non_arp[42] = {0};
    non_arp[12] = 0x08;
    non_arp[13] = 0x00;
    assert(parse_arp_packet(non_arp, 42, &pkt) == -3);

    /* Invalid ARP opcode (0 and 99) */
    uint8_t bad_op[42];
    const uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
    const uint8_t ip[4]  = {192, 168, 1, 1};
    build_arp_frame(mac, mac, 0, mac, ip, mac, ip, bad_op, sizeof(bad_op));
    assert(parse_arp_packet(bad_op, 42, &pkt) == -4);

    /* QinQ double-tagged VLAN ARP frame (0x88A8 outer S-Tag 200 + 0x8100 inner C-Tag 42) */
    uint8_t base_arp[42];
    uint8_t qinq_arp[50];
    build_arp_frame(mac, mac, ARP_OP_REPLY, mac, ip, mac, ip, base_arp, sizeof(base_arp));
    memcpy(qinq_arp, base_arp, 12);
    qinq_arp[12] = 0x88; qinq_arp[13] = 0xA8; qinq_arp[14] = 0x00; qinq_arp[15] = 200;
    qinq_arp[16] = 0x81; qinq_arp[17] = 0x00; qinq_arp[18] = 0x00; qinq_arp[19] = 42;
    memcpy(qinq_arp + 20, base_arp + 12, 30);
    assert(parse_arp_packet(qinq_arp, 50, &pkt) == 0);
    assert(pkt.vlan_id == 42);
    assert(pkt.opcode == 2);

    /* IPv4 with IHL = 6 (24-byte header with options) and boundary TCP port extraction */
    uint8_t ipv4_opt[42] = {0};
    ParsedIpPacket ip_pkt;
    memcpy(ipv4_opt + 0, mac, 6);
    memcpy(ipv4_opt + 6, mac, 6);
    ipv4_opt[12] = 0x08; ipv4_opt[13] = 0x00; /* IPv4 */
    ipv4_opt[14] = 0x46; /* Version 4, IHL = 6 (24 bytes) */
    ipv4_opt[16] = 0x00; ipv4_opt[17] = 28; /* total_length = 28 */
    ipv4_opt[22] = 64;   /* TTL */
    ipv4_opt[23] = 6;    /* TCP */
    memcpy(ipv4_opt + 26, ip, 4);
    memcpy(ipv4_opt + 30, ip, 4);
    /* 4 bytes of IPv4 options at 34..37, then TCP ports at 38..41 */
    ipv4_opt[38] = 0x1F; ipv4_opt[39] = 0x90; /* src_port = 8080 */
    ipv4_opt[40] = 0x01; ipv4_opt[41] = 0xBB; /* dst_port = 443 */

    /* Truncated before IHL finishes (37 bytes < 14 + 24) -> -4 */
    assert(parse_ipv4_packet(ipv4_opt, 37, &ip_pkt) == -4);
    /* Full 42 bytes -> parses options + TCP ports */
    assert(parse_ipv4_packet(ipv4_opt, 42, &ip_pkt) == 0);
    assert(ip_pkt.src_port == 8080);
    assert(ip_pkt.dst_port == 443);

    /* Bogus total_length < ihl -> -4 */
    ipv4_opt[17] = 10;
    assert(parse_ipv4_packet(ipv4_opt, 42, &ip_pkt) == -4);
}

int main(void) {
    printf("[C-Test] Running NetworkSentry Native C Packet Parser Tests...\n");
    test_valid_arp_request_and_reply();
    printf("  [PASS] test_valid_arp_request_and_reply\n");

    test_gratuitous_and_mac_mismatch_spoofing();
    printf("  [PASS] test_gratuitous_and_mac_mismatch_spoofing\n");

    test_malformed_and_truncated_packets();
    printf("  [PASS] test_malformed_and_truncated_packets\n");

    /* Micro-benchmark: 100,000 ARP packet parses */
    uint8_t frame[42];
    ParsedArpPacket pkt;
    const uint8_t mac[6] = {0x00, 0x03, 0x93, 0xAA, 0xBB, 0xCC};
    const uint8_t ip[4]  = {10, 0, 0, 1};
    build_arp_frame(mac, mac, 2, mac, ip, mac, ip, frame, sizeof(frame));

    clock_t start = clock();
    int i;
    for (i = 0; i < 100000; ++i) {
        parse_arp_packet(frame, 42, &pkt);
    }
    clock_t end = clock();
    double elapsed_ms = ((double)(end - start) * 1000.0) / CLOCKS_PER_SEC;
    printf("  [BENCH] Parsed 100,000 ARP frames in %.2f ms (Engine: %s)\n",
           elapsed_ms, packet_engine_version());
    printf("[C-Test] All C unit tests PASSED.\n");
    return 0;
}
