#define BOOST_TEST_MODULE SocketTest

#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_suite.hpp>

#include <linux/if_xdp.h>

#include "include/Socket.hpp"

namespace
{
  using namespace HttpServer;

  [[nodiscard]]
  const std::byte *get_tcp_udp_payload_ptr(std::span<std::byte> packet) noexcept
  {
    const std::byte *data = packet.data();
    const std::byte *end = data + packet.size();

    // Skip destination + source MAC.
    data += 12;

    uint16_t header = load_be16(data);

    if(header == Ethernet::VLAN || header == Ethernet::VLAN_8021AD)
    {
      for(std::size_t i = 0; i < 8; ++i)
      {
        header = load_be16(data);

        if(header != Ethernet::VLAN && header != Ethernet::VLAN_8021AD)
        {
          break;
        }

        // Skip TCI.
        data += 4;
      }
      // data now points at the next EtherType.
    }

    if(header < 1501)
    {
      data += 8; // Skip Length.(2) DSAP + SSAP (2) + Control byte (1) + OUI (3)

      // SNAP encapsulated EtherType.
      header = load_be16(data);
    }

    if(header == Ethernet::MPLS_UC || header == Ethernet::MPLS_MC)
    {
      // Skip the EtherType.
      data += 2;

      for(std::size_t i = 0; i < 8; ++i)
      {
        const std::uint32_t mpls_header = load_be32(data);

        // Skip MPLS label.
        data += 4;

        if(mpls_header & 0x00000100U)
          break;
      }

      const std::uint8_t ip_version = std::to_integer<std::uint8_t>(*data) >> 4U;

      header = ip_version == 4 ? Ethernet::IP : Ethernet::IPV6;
    }

    bool is_tcp = false;
    if(header == Ethernet::IP)
    {
      data += 2; // skip Ether/Type

      data += 6; // skip Ver/IHL (1) and DSCP/ECN (1) + TotalLen (2) and Identification (2)

      data += 3; // // Flags-Fragment Offset (2) and Time-to-live (1)

      const unsigned char ipv4_octet_9 = *reinterpret_cast<const unsigned char *>(data);

      is_tcp = ipv4_octet_9 == 6;

      data += 11; // skip Protocol (1) and Checksum (2)  + Source Address (4) and Desination Address (4)

      // now data points to start of payload
    }
    else
    {
      data += 2; // skip Ether/Type (2)

      data += 6; // skip version (1) + traffic class (1) + flow label (2) + skip payload length (2)

      const unsigned char ipv6_octet_6 = *reinterpret_cast<const unsigned char *>(data);

      is_tcp = ipv6_octet_6 == 6;

      data += 34; // skip Next Header (1) + Hop Limit (1) + Source Address (16) + Destination Address (16)
    }

    if(is_tcp)
    {
      // Need at least the fixed TCP header.
      if(data + 20 > end)
      {
        return nullptr;
      }

      const std::uint8_t data_offset = std::to_integer<std::uint8_t>(data[12]) >> 4U;

      const std::size_t tcp_header_len = static_cast<std::size_t>(data_offset) * 4U;

      // TCP header must be at least 20 bytes.
      if(tcp_header_len < 20)
      {
        return nullptr;
      }

      if(data + tcp_header_len > end)
      {
        return nullptr;
      }

      // THIS IS THE APPLICATION DATA *
      return data + tcp_header_len;
    }
    else
    {
      // UDP header is always 8 bytes.
      if(data + 8 > end)
      {
        return nullptr;
      }

      return data + 8;
    }
  }
} // namespace

BOOST_AUTO_TEST_CASE(test_create_socket_and_wait_4_packet)
{
  HttpServer::Socket socket{};

  std::atomic<uint8_t> signal; // if one day we make it async ...
  xdp_desc *desc;

  auto *packet = socket.wait_for_a_packet(desc, signal);

  auto span = std::span<std::byte>(reinterpret_cast<std::byte *>(packet), desc->len);

  // XDP already filtered this packet before it ever reached us. so we return the Application data ptr
  const auto *beg_of_data = get_tcp_udp_payload_ptr(span);

  printf("\n=== AF_XDP RX PACKET ===\n"
         "\tlength: %u\n"
         "\taddr:   %llu\n",
         desc->len, static_cast<unsigned long long>(desc->addr));

  // --------------------------------------------------------------
  // Full packet hex dump
  // ---------------------------------------------------------------
  const __u32 dump_len = desc->len < 64 ? desc->len : 64;

  printf("\nPACKET HEX:");

  for(__u32 i = 0; i < dump_len; ++i)
  {
    if(i % 16 == 0)
    {
      printf("\n%04x: ", i);
    }

    printf("%02x ", static_cast<unsigned>(std::to_integer<unsigned char>(span[i])));
  }

  printf("\n");

  // --------------------------------------------------------------
  // Application DATA
  // ---------------------------------------------------------------
  if(beg_of_data == nullptr)
  {
    printf("\nDATA:\n \tParser returned nullptr\n");
  }
  else
  {
    const auto *packet_begin = span.data();

    const auto *packet_end = packet_begin + span.size();

    const auto data_offset = static_cast<std::size_t>(beg_of_data - packet_begin);

    const auto data_length = static_cast<std::size_t>(packet_end - beg_of_data);

    printf("\n=== APPLICATION DATA ===\n"
           "\tOffset: %zu\n"
           "\tLength: %zu\n"
           "\tPtr:    %p\n",
           data_offset, data_length, static_cast<const void *>(beg_of_data));

    // Raw application payload. With your current test this should print: HELLO_FROM_AF_XDP
    printf("\nDATA STRING:\n");

    for(const std::byte byte : std::span{ beg_of_data, data_length })
    {
      printf("%c", static_cast<char>(std::to_integer<unsigned char>(byte)));
    }

    printf("\n");

    // Application payload hex dump.
    printf("\nDATA HEX:");

    for(std::size_t i = 0; i < data_length; ++i)
    {
      if(i % 16 == 0)
      {
        printf("\n%04zx: ", i);
      }

      printf("%02x ", static_cast<unsigned>(std::to_integer<unsigned char>(beg_of_data[i])));
    }

    printf("\n");
  }

  socket.release_rx_packet(desc);
}
