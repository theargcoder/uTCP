#pragma once
#include <cstdint>

namespace HttpServer
{
  namespace Ethernet
  {
    constexpr uint16_t IP = 0x0800;
    constexpr uint16_t IPV6 = 0x86DD;
    constexpr uint16_t VLAN = 0x8100;
    constexpr uint16_t VLAN_8021AD = 0x88A8;
    constexpr uint16_t MPLS_UC = 0x8847;
    constexpr uint16_t MPLS_MC = 0x8848;
  } // namespace Ethernet

  namespace IP
  {
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
  } // namespace IP

  constexpr uint16_t HTTP = 80;
  constexpr uint16_t HTTPS = 443;
} // namespace HttpServer
