#include <cstdint>
#include <linux/ip.h>
#include <netinet/in.h>
#include <stdexcept>

#include "include/Defines.hpp"
#include "include/Helpers/Simd.hpp"
#include "include/Tcp.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

void hex_dump(const uint8_t *ptr, const size_t len);

void hex_dump(const uint8_t *ptr, const size_t len)
{
  // Application payload hex dump.
  printf("\nHEX DUMP:\n");

  for(std::size_t i = 0; i < len; ++i)
  {
    /*
    if(i % 16 == 0)
    {
      printf("\n%04zx: ", i);
    }
    */

    printf("%02x ", static_cast<unsigned>(ptr[i]));
  }

  printf("\n");
}

namespace HttpServer
{
  Tcp::Tcp(Tcp &&) noexcept = default;
  Tcp &Tcp::operator=(Tcp &&) noexcept = default;

  Tcp::~Tcp() = default;
  Tcp::Tcp() = default;

  const uint8_t *get_ip_payload_ptr(const uint8_t *data, const size_t size) noexcept;
  [[nodiscard]]
  const uint8_t *get_ip_payload_ptr(const uint8_t *data, const size_t size) noexcept
  {
    if(size < 20)
    {
      return nullptr;
    }

    // Skip destination + source MAC.
    data += 12;

    uint16_t header = ntohs(*reinterpret_cast<const uint16_t *>(data));

    if(header == Ethernet::VLAN || header == Ethernet::VLAN_8021AD)
    {
      for(std::size_t i = 0; i < 8; ++i)
      {
        header = ntohs(*reinterpret_cast<const uint16_t *>(data));

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
      header = ntohs(*reinterpret_cast<const uint16_t *>(data));
    }

    if(header == Ethernet::MPLS_UC || header == Ethernet::MPLS_MC)
    {
      // Skip the EtherType.
      data += 2;

      for(size_t i = 0; i < 8; ++i)
      {
        const uint32_t mpls_header = ntohl(*reinterpret_cast<const uint32_t *>(data));

        // Skip MPLS label.
        data += 4;

        if(mpls_header & 0x00000100U)
          break;
      }

      const std::uint8_t ip_version = *data >> 4U;

      header = ip_version == 4 ? Ethernet::IP : Ethernet::IPV6;
    }

    data += 2; // skip Ether/Type

    return data;
  }

  void Tcp::wait_for_connection()
  {
    std::atomic<uint8_t> signal; // if one day we make it async ...
    xdp_desc *rx_desc;

    const auto *rx_packet = static_cast<uint8_t *>(this->wait_for_a_packet(rx_desc, signal));

    printf("\n=========== RECIVED PACKET HEX DUMP ==========\n");
    printf("desc_ptr= %p \n", static_cast<void *>(rx_desc));
    printf("desc_ptr->addr= %llu \n", rx_desc->addr);
    printf("desc_ptr->len = %u \n", rx_desc->len);
    printf("desc_ptr->option = %u \n", rx_desc->options);
    hex_dump(rx_packet, rx_desc->len);
    printf("\n==================== END =====================\n");

    const auto *rx_ip_ptr = get_ip_payload_ptr(rx_packet, rx_desc->len);

    const auto *rx_ip_hdr = reinterpret_cast<const ipv4hdr *>(rx_ip_ptr);

    if(!this->ipv4_validate_checksum(rx_ip_ptr, rx_packet + rx_desc->len))
    {
      throw std::runtime_error{ "TCP - ipv4 - checksum failed" };
    }

    const auto *rx_tcp_ptr = rx_ip_ptr + (rx_ip_hdr->ihl << 2);

    const auto *rx_tcp_hdr = reinterpret_cast<const tcphdr *>(rx_tcp_ptr);

    if(rx_tcp_hdr->syn) // reply SYN + ACK ....
    {
      uint32_t ipv4_source = rx_ip_hdr->saddr;
      if(this->address_to_tcb.contains(ipv4_source)) // already established/ing connection ?? suspicious
      {
        throw std::runtime_error{ "remote IPv4 is trying to SYN twice ???" };
      }

      auto &tc_block = this->address_to_tcb[ipv4_source];
      tc_block.state = SocketState::SYN_RECIVED;
      tc_block.remote_seq = ntohl(rx_tcp_hdr->seqnum);       // we store the remote sequence so whe can ACK it
      tc_block.local_seq = static_cast<uint32_t>(__rdtsc()); // we assign a pseudo-random sequence so whe can SYN it

      // where to write the packet
      xdp_desc *tx_desc = nullptr;

      for(; tx_desc == nullptr; tx_desc = this->get_tx_packet_ptr())
      {
      }

      tx_desc->len = 0;
      uint8_t *eth_frame_ptr = this->get_umem_ptr() + tx_desc->addr;

      // swap MAC's since the frame going the the same link it arrived from, from the same device LOL
      memcpy(&eth_frame_ptr[0], &rx_packet[6], 6);
      memcpy(&eth_frame_ptr[6], &rx_packet[0], 6);
      tx_desc->len += 12;

      eth_frame_ptr[12] = 0x08; // IPv4
      eth_frame_ptr[13] = 0;
      tx_desc->len += 2;

      auto *tx_ip_hdr = reinterpret_cast<ipv4hdr *>(&eth_frame_ptr[tx_desc->len]);

      tx_ip_hdr->version = 4;                                           // IPv4
      tx_ip_hdr->ihl = 5;                                               // 20 bytes no options
      tx_ip_hdr->dscp = 0;                                              // DSCP to 0 since traffic management not in the scope yet
      tx_ip_hdr->ecn = 0;                                               // ECN to 0 since traffic management not in the scope yet
      tx_ip_hdr->tot_len = static_cast<uint16_t>(tx_ip_hdr->ihl << 2U); //
      tx_ip_hdr->id = 0;                                                // for now its 0, should be assigned an ID TBH
      tx_ip_hdr->flags = 0;                                             // I belive its resered
      tx_ip_hdr->frag_off = 0;                                          // for now its 0, since this is fragment 0
      tx_ip_hdr->ttl = 1;                                               //  if I can ping to china in 200 ms idk why any more than 1 sec is not enough lol
      tx_ip_hdr->protocol = 6;                                          //
      tx_ip_hdr->check = 0;                                             // zero'd so checksum can be computed and replaced
      tx_ip_hdr->saddr = rx_ip_hdr->daddr;                              // the destination source is the outgoing source  (aka this computer)
      tx_ip_hdr->daddr = rx_ip_hdr->saddr;                              // the incoming source is the outgoing destination

      tx_desc->len += static_cast<uint32_t>(tx_ip_hdr->ihl << 2U);

      auto *tx_tcp_hdr = reinterpret_cast<tcphdr *>(&eth_frame_ptr[tx_desc->len]);

      printf("RX sport=%u dport=%u\n", ntohs(rx_tcp_hdr->sport), ntohs(rx_tcp_hdr->dport));

      tx_tcp_hdr->sport = rx_tcp_hdr->dport;
      tx_tcp_hdr->dport = rx_tcp_hdr->sport;

      printf("TX sport=%u dport=%u\n", ntohs(tx_tcp_hdr->sport), ntohs(tx_tcp_hdr->dport));

      tc_block.remote_seq += 1;
      tx_tcp_hdr->seqnum = tc_block.local_seq;
      tx_tcp_hdr->acknum = htonl(tc_block.remote_seq);

      tx_tcp_hdr->doff = 5;
      tx_tcp_hdr->res_x1 = 0;
      tx_tcp_hdr->cwr_ece = 0;
      tx_tcp_hdr->urg = 0;
      tx_tcp_hdr->ack = 1;
      tx_tcp_hdr->psh = 0;
      tx_tcp_hdr->rst = 0;
      tx_tcp_hdr->syn = 1;
      tx_tcp_hdr->fin = 0;

      tx_tcp_hdr->window = htons(65535); // we accept full tcp length for now
      tx_tcp_hdr->checksum = 0;
      tx_tcp_hdr->urgptr = 0;

      tx_desc->len += static_cast<uint16_t>(sizeof(tcphdr));

      tx_ip_hdr->tot_len = htons(static_cast<uint16_t>(tx_desc->len - 14)); // minus ETHDRLEN

      auto sum = Simd::HorizontalReduction2byte(&eth_frame_ptr[14], &eth_frame_ptr[14 + (tx_ip_hdr->ihl << 2)]);
      sum = (sum & 0xFFFF) + (sum >> 16U);
      sum = (sum & 0xFFFF) + (sum >> 16U);

      const auto ip_hdr_checksum = static_cast<uint16_t>(~sum);

      tx_ip_hdr->check = ip_hdr_checksum;

      const auto tcp_header_checksum = ipv4_compute_checksum(&eth_frame_ptr[14], &eth_frame_ptr[tx_desc->len]);

      tx_tcp_hdr->checksum = tcp_header_checksum;

      printf("\n============ SENT PACKET HEX DUMP ============\n");
      printf("desc_ptr = %p \n", static_cast<void *>(tx_desc));
      printf("desc_ptr->addr= %llu \n", tx_desc->addr);
      printf("desc_ptr->len = %u \n", tx_desc->len);
      printf("desc_ptr->option = %u \n", tx_desc->options);
      hex_dump(eth_frame_ptr, tx_desc->len);
      printf("\n==================== END =====================\n");

      release_tx_packet();
    }
    else if(rx_tcp_hdr->ack) // reply ....
    {
    }

    this->release_rx_packet(rx_desc);
  }

  bool Tcp::ipv4_validate_checksum(const uint8_t *ip_packet_ptr, const uint8_t *ip_packet_end) // assumes network order
  {
    const auto checksum = ipv4_compute_checksum(ip_packet_ptr, ip_packet_end);

    return checksum == 0;
  }

  // this only exists if TCP/UDP NIC checksum offloading isn't available
  uint16_t Tcp::ipv4_compute_checksum(const uint8_t *ip_packet_ptr, const uint8_t *ip_packet_end)
  {
    if(ip_packet_end - ip_packet_ptr < 40) // not even a IP header and TCP header provided ???
    {
      throw std::runtime_error{ "tcp for ipv4 - compute checksum length is less than minimum 40 byte for tcp and ip header" };
    }

    const auto *ipv4_hdr = reinterpret_cast<const ipv4hdr *>(ip_packet_ptr);
    const auto ip_len = ntohs(ipv4_hdr->tot_len);
    const auto ip_header_len = static_cast<uint16_t>(ipv4_hdr->ihl << 2U);
    const auto tcp_len = static_cast<uint16_t>(ip_len - ip_header_len);

    const uint8_t *tcp_ptr = ip_packet_ptr + ip_header_len;
    const uint8_t *tcp_end = tcp_ptr + tcp_len;

    ip_packet_ptr += ip_header_len; // done with IPv4 header

    uint32_t sum = Simd::HorizontalReduction2byte(tcp_ptr, tcp_end);

    sum += static_cast<uint16_t>(ipv4_hdr->saddr);
    sum += static_cast<uint16_t>(ipv4_hdr->saddr >> 16);
    sum += static_cast<uint16_t>(ipv4_hdr->daddr);
    sum += static_cast<uint16_t>(ipv4_hdr->daddr >> 16);
    sum += htons(static_cast<uint16_t>(ipv4_hdr->protocol));
    sum += htons(tcp_len);

    sum = (sum & 0xFFFF) + (sum >> 16U);
    sum = (sum & 0xFFFF) + (sum >> 16U);

    return static_cast<uint16_t>(~sum);
  }

} // namespace HttpServer

#pragma GCC diagnostic pop
//
//
