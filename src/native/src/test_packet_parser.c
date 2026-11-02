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
