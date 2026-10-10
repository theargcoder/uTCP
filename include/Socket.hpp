#pragma once

#include <atomic>
#include <cerrno>
#include <net/if.h>

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <poll.h>

#include <cstddef>
#include <cstdint>

#include "include/Defines.hpp"
#include "include/HttpServer.hpp"

namespace HttpServer
{
  inline constexpr unsigned CHUNK_SIZE = 4096;
  inline constexpr unsigned CHUNK_COUNT = 4096;
  inline constexpr unsigned UMEM_LEN = CHUNK_SIZE * CHUNK_COUNT;
  inline constexpr unsigned HUGE_PAGE_SIZE = 2 * 1024 * 1024; // 2 MB

  inline constexpr unsigned RING_BUFFER_SIZE = 2048;

  inline constexpr unsigned RX_FRAME_BEGIN = 0;
  inline constexpr unsigned RX_FRAME_COUNT = CHUNK_COUNT / 2;

  inline constexpr unsigned TX_FRAME_BEGIN = RX_FRAME_COUNT;
  inline constexpr unsigned TX_FRAME_COUNT = CHUNK_COUNT - TX_FRAME_BEGIN;

  inline constexpr uint64_t TX_UMEM_BASE = static_cast<uint64_t>(TX_FRAME_BEGIN) * CHUNK_SIZE;

  static_assert(RX_FRAME_COUNT == RING_BUFFER_SIZE);
  static_assert(TX_FRAME_COUNT == RING_BUFFER_SIZE);

  inline constexpr const char *NETWORK_INTERFACE = "wlp3s0";

  struct ring_ptrs
  {
    __u32 *rx, *tx, *fill, *completion;
  };

  class Socket
  {
  private:
    xdp_umem_reg umem_reg;
    xdp_mmap_offsets mmap_offsets{};

    ring_ptrs consumer, producer;
    xdp_desc *rx_ring, *tx_ring;
    __u64 *fill_ring, *completion_ring;

    sockaddr_xdp sock_addr;

    unsigned char *umem;
    int fd;

    unsigned ifindex;
    bool xdp_attached;

  public:
    Socket();
    ~Socket() noexcept;

    // can't copy sockets bro, singleton only
    Socket(const Socket &other) = delete;
    Socket &operator=(const Socket &other) = delete;

    // It can be moved tho!!
    Socket(Socket &&other) noexcept;
    Socket &operator=(Socket &&other) noexcept;

  public:
    void *wait_for_a_packet(xdp_desc *&ptr, std::atomic<uint8_t> &signal);

  public: // getters
    __attribute((always_inline)) uint8_t *get_umem_ptr()
    {
      return this->umem;
    }

    __attribute((always_inline)) xdp_desc *get_tx_packet_ptr()
    {
      // get a UMEM frame from kernel for tx
      const uint32_t tail_idx = __atomic_load_n(this->consumer.completion, __ATOMIC_ACQUIRE);
      const uint32_t head_idx = __atomic_load_n(this->producer.completion, __ATOMIC_ACQUIRE);

      if(head_idx == tail_idx) // TX ring is full and the kernel hasn't sent anything
      {
        return nullptr;
      }

      __atomic_store_n(this->consumer.completion, tail_idx + 1, __ATOMIC_RELEASE);
      const uint32_t index = tail_idx & (RING_BUFFER_SIZE - 1);

      return &this->tx_ring[index];
    }

    // releases the PREVIOUSLY get_tx_packet_ptr() tx_ring desc
    __attribute((always_inline)) void release_tx_packet()
    {
      const __u32 tx_head = __atomic_load_n(this->producer.tx, __ATOMIC_ACQUIRE);
      __atomic_store_n(this->producer.tx, tx_head + 1, __ATOMIC_RELEASE); // we let the kernel know it can send it

      // Kick TX processing for this diagnostic implementation.
      if(sendto(this->fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0) < 0)
      {
        if(errno != EAGAIN && errno != EBUSY)
        {
          perror("AF_XDP TX sendto");
        }
      }
    }

    __attribute((always_inline)) xdp_desc *get_rx_packet_ptr()
    {
      const __u32 tail_idx = __atomic_load_n(this->consumer.rx, __ATOMIC_RELAXED);
      const __u32 head_idx = __atomic_load_n(this->producer.rx, __ATOMIC_ACQUIRE);

      if(tail_idx == head_idx) // nothing new recived
      {
        return nullptr;
      }

      // we don't increment consumer since we are reading those bytes;
      // once processed then release_rx_packet() does the releasing

      const __u32 index = tail_idx & (RING_BUFFER_SIZE - 1);

      return &this->rx_ring[index];
    }

    __attribute((always_inline)) void release_rx_packet(const xdp_desc *desc)
    {
      const __u32 rx_tail = __atomic_load_n(this->consumer.rx, __ATOMIC_ACQUIRE);
      const __u32 fill_head = __atomic_load_n(this->producer.fill, __ATOMIC_ACQUIRE);
      const uint32_t index = rx_tail & (RING_BUFFER_SIZE - 1);

      this->fill_ring[index] = desc->addr;

      __atomic_store_n(this->producer.fill, fill_head + 1, __ATOMIC_RELEASE); // we give the kernel the frame
      __atomic_store_n(this->consumer.rx, rx_tail + 1, __ATOMIC_RELEASE);     // we already read and used it
    }
  };

  [[nodiscard]] constexpr uint16_t load_be16(const std::byte *ptr) noexcept
  {
    return static_cast<uint16_t>((std::to_integer<uint16_t>(ptr[0]) << 8U) | std::to_integer<uint16_t>(ptr[1]));
  }

  [[nodiscard]] constexpr uint32_t load_be32(const std::byte *ptr) noexcept
  {
    return (static_cast<uint32_t>(std::to_integer<uint8_t>(ptr[0])) << 24U) | (static_cast<uint32_t>(std::to_integer<uint8_t>(ptr[1])) << 16U)
           | (static_cast<uint32_t>(std::to_integer<uint8_t>(ptr[2])) << 8U) | (static_cast<uint32_t>(std::to_integer<uint8_t>(ptr[3])));
  }

} // namespace HttpServer
