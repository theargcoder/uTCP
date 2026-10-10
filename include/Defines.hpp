#pragma once

#include <asm/byteorder.h>

#include <cstdint>

struct __attribute__((packed)) ethhdr
{
  uint8_t daddr[6];
  uint8_t saddr[6];
  uint16_t ethtype;
};

struct __attribute__((packed)) ipv4hdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint8_t ihl : 4, version : 4;
  uint8_t dscp : 6, ecn : 2;
#elif defined(__BIG_ENDIAN_BITFIELD)
  uint8_t version : 4, ihl : 4;
  uint8_t ecn : 2, dscp : 6;
#endif
  uint16_t tot_len;
  uint16_t id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint16_t flags : 3, frag_off : 13;
#elif defined(__BIG_ENDIAN_BITFIELD)
  uint16_t frag_off : 13, flags : 3;
#endif
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

struct __attribute__((packed)) tcphdr
{
  uint16_t sport;
  uint16_t dport;
  uint32_t seqnum;
  uint32_t acknum;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint8_t res_x1 : 4, doff : 4;
  uint8_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, cwr_ece : 2;
#elif defined(__BIG_ENDIAN_BITFIELD)
  uint8_t doff : 4, res_x1 : 4;
  uint8_t cwr_ece : 2, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#endif
  uint16_t window;
  uint16_t checksum;
  uint16_t urgptr;
};

static_assert(sizeof(ipv4hdr) == 20);
static_assert(sizeof(tcphdr) == 20);
