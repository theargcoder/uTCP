#pragma once

#include <cstdint>
#include <unordered_map>

#include "include/Socket.hpp"

namespace HttpServer
{
  // RFC 9293 is the spec

  enum class SocketState : uint8_t
  {
    LISTEN,      // Waiting for connection request
    SYN_SENT,    // Client only so ignore
    SYN_RECIVED, // Waiting for confirming connection request ack after both (client && server) recived and sent a connection request
    ESTABLISHED, // An open connection - data recived can be delivered to the user - this is the normal state for the data transfer state phase of the connection
    FIN_WAIT_1,  // Waiting for connection termination request from the remote TCP, or an ack of the connection termination request previously sent
    FIN_WAIT_2,  // Waiting for a connection termination request from the remote TCP.
    CLOSE_WAIT,  // Waiting for a connection termination request from the local user.
    CLOSING,     // Waiting for a connection termination ack from the remote TCP.
    LAST_ACK,    // Waiting for an ack of the connection termination request previously sent to the remote TCP.
    TIME_WAIT,   // Waiting for enough time to pass to be sure that all remaining packets on the connection have expired.
    CLOSED,      // No connection state at all.
  };

  class Tcp : Socket
  {
  public:
    Tcp();
    ~Tcp();

    Tcp(const Tcp &other) = delete;
    Tcp &operator=(const Tcp &other) = delete;

    Tcp(Tcp &&other) noexcept;
    Tcp &operator=(Tcp &&other) noexcept;

    struct tcb
    {
      SocketState state;
      uint32_t remote_seq;
      uint32_t local_seq;
    };

  private:
    std::unordered_map<uint32_t, tcb> address_to_tcb;

  public:
    void wait_for_connection();
    void close_connection();

  private:
    uint16_t ipv4_compute_checksum(const uint8_t *ip_packet_ptr, const uint8_t *ip_packet_end);
    bool ipv4_validate_checksum(const uint8_t *ip_packet_ptr, const uint8_t *ip_packet_end);
  };
} // namespace HttpServer
