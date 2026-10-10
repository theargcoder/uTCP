#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

#include "include/Socket.hpp"

extern "C"
{
  extern const unsigned char _binary_xdp_redirect_bpf_o_start[];
  extern const unsigned char _binary_xdp_redirect_bpf_o_end[];
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"

namespace
{
  int perror_and_throw(const char *STR)
  {
    perror(STR);
    throw std::runtime_error{ STR };
  }

  void load_xdp_program(const unsigned ifindex, const int xsk_fd)
  {
    // bpf_object *obj = bpf_object__open_file(TCP_SOCKET_BPF_OBJECT, nullptr);
    const auto *bpf_data = _binary_xdp_redirect_bpf_o_start;

    const auto bpf_size = static_cast<size_t>(_binary_xdp_redirect_bpf_o_end - _binary_xdp_redirect_bpf_o_start);

    bpf_object *obj = bpf_object__open_mem(bpf_data, bpf_size, nullptr);

    if(obj == nullptr)
    {
      perror_and_throw("TcpSocket::Socket()::load_xdp_program() - failed to load BPF object form this executable");
    }

    const long open_err = libbpf_get_error(obj);

    if(open_err != 0)
    {
      errno = static_cast<int>(-open_err);
      perror_and_throw("TcpSocket::Socket()::load_xdp_program() - failed to open BPF object");
    }

    if(const int err = bpf_object__load(obj); err != 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - failed to load BPF object");
    }

    bpf_map *xsks_map = bpf_object__find_map_by_name(obj, "xsks_map");

    if(xsks_map == nullptr)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - xsks_map not found");
    }

    const int xsks_map_fd = bpf_map__fd(xsks_map);

    if(xsks_map_fd < 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - invalid xsks_map FD");
    }

    // Our XSK is bound to queue 0.
    const __u32 queue = 0;

    // XSKMAP stores the FD of the AF_XDP socket from userspace. The kernel resolves it to the actual XSK.
    const auto value = static_cast<__u32>(xsk_fd);

    if(bpf_map_update_elem(xsks_map_fd, &queue, &value, BPF_ANY) == -1)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - failed to insert XSK into XSKMAP");
    }

    bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_redirect_12345");

    if(prog == nullptr)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - XDP program not found");
    }

    const int prog_fd = bpf_program__fd(prog);

    if(prog_fd < 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - invalid XDP program FD");
    }

    // Force XDP_SKB/generic mode. This is what we want for lo.
    constexpr auto xdp_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

    if(const int err = bpf_xdp_attach(static_cast<int>(ifindex), prog_fd, xdp_flags, nullptr); err < 0)
    {
      bpf_object__close(obj);

      perror_and_throw("TcpSocket::Socket() - failed to attach XDP program");
    }

    // The XDP program and its map are now referenced by the kernel's attached program, so the userspace ELF object can be closed.
    bpf_object__close(obj);
  }

  void prime_fill_ring(__u64 *fill_ring, __u32 *producer)
  {
    // RING_BUFFER_SIZE is 512, so we can only initially put 512 addresses into the FILL ring.
    for(__u32 i = 0; i < HttpServer::RING_BUFFER_SIZE; ++i)
    {
      fill_ring[i] = static_cast<__u64>(i) * HttpServer::CHUNK_SIZE;
    }

    // Publish all descriptors after writing them.
    __atomic_store_n(producer, HttpServer::RING_BUFFER_SIZE, __ATOMIC_RELEASE);
  }

  // we simulate like the kernel sent all the tx rings so the completion -> tx -> send loop can work
  void prime_completion_ring(__u64 *completion_ring, xdp_desc *tx_ring, __u32 *producer)
  {
    for(__u32 i = 0; i < HttpServer::RING_BUFFER_SIZE; ++i)
    {
      const __u64 addr = static_cast<__u64>(HttpServer::TX_FRAME_BEGIN + i) * HttpServer::CHUNK_SIZE;

      completion_ring[i] = addr;

      tx_ring[i].addr = addr;
      tx_ring[i].len = 0;
      tx_ring[i].options = 0;
    }

    __atomic_store_n(producer, HttpServer::RING_BUFFER_SIZE, __ATOMIC_RELEASE);
  }

} // namespace

namespace HttpServer
{
  Socket::Socket(Socket && /*other*/) noexcept = default;
  Socket &Socket::operator=(Socket && /*other*/) noexcept = default;

  Socket::~Socket() noexcept
  {
    if(this->xdp_attached && this->ifindex != 0)
    {
      if(const int err = bpf_xdp_detach(static_cast<int>(this->ifindex), XDP_FLAGS_SKB_MODE, nullptr); err < 0)
      {
        // cant throw since desctructors in C++ have to be noexcept
        fprintf(stderr, "bpf_xdp_detach failed: %s\n", strerror(-err));
      }
    }

    if(this->umem)
    {
      munmap(umem, UMEM_LEN);
    }

    if(fd != -1)
    {
      close(fd);
    }
  }

  Socket::Socket() : umem(nullptr), fd(-1), ifindex(0), xdp_attached(false)
  {
    // huge pages to try to minimize page walks or TLB fails in hot XDP path
    void *addr = mmap(nullptr, UMEM_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB | MAP_POPULATE, -1, 0);

    if(addr == MAP_FAILED)
    {
      perror_and_throw("TcpSocket::Socket() - mmap MAP_HUGETLB failed");
    }

    this->umem = static_cast<unsigned char *>(addr);

    // Optional sanity check.
    if(reinterpret_cast<uintptr_t>(umem) % HUGE_PAGE_SIZE != 0)
    {
      munmap(umem, UMEM_LEN);
      perror_and_throw("TcpSocket::Socket() - HugeTLB mapping is not 2MB aligned");
    }

    this->fd = socket(AF_XDP, SOCK_RAW, 0);

    if(this->fd == -1)
    {
      perror_and_throw("TcpSocket::Socket() - socket creation failed");
    }

    this->umem_reg
        = { .addr = reinterpret_cast<std::uintptr_t>(static_cast<void *>(this->umem)), .len = UMEM_LEN, .chunk_size = CHUNK_SIZE, .headroom = 0, .flags = 0, .tx_metadata_len = 0 };

    if(setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &this->umem_reg, sizeof(this->umem_reg)) == -1)
    {
      perror_and_throw("TcpSocket::Socket() - syscall for socket XDP UMEM failed");
    }

    for(const auto &opt : { XDP_RX_RING, XDP_TX_RING, XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING })
    {
      if(setsockopt(fd, SOL_XDP, opt, &RING_BUFFER_SIZE, sizeof(RING_BUFFER_SIZE)) == -1)
      {
        perror_and_throw("TcpSocket::Socket() - syscall setsockopt for options for XDP socket failed");
      }
    }

    if(socklen_t mmap_offset_len = sizeof(this->mmap_offsets); getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &this->mmap_offsets, &mmap_offset_len) == -1)
    {
      perror_and_throw("TcpSocket::Socket() - syscall setsockopt for XDP MMAP offsets failed");
    }

    void *mmap_rx = mmap(nullptr, this->mmap_offsets.rx.desc + RING_BUFFER_SIZE * sizeof(xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_RX_RING);
    void *mmap_tx = mmap(nullptr, this->mmap_offsets.tx.desc + RING_BUFFER_SIZE * sizeof(xdp_desc), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_PGOFF_TX_RING);
    void *mmap_fill = mmap(nullptr, this->mmap_offsets.fr.desc + RING_BUFFER_SIZE * sizeof(__u64), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_FILL_RING);
    void *mmap_completion
        = mmap(nullptr, this->mmap_offsets.cr.desc + RING_BUFFER_SIZE * sizeof(__u64), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, XDP_UMEM_PGOFF_COMPLETION_RING);

    if(mmap_rx == MAP_FAILED || mmap_tx == MAP_FAILED || mmap_fill == MAP_FAILED || mmap_completion == MAP_FAILED)
    {
      perror_and_throw("TcpSocket::Socket() - ring buffer memory maps failed");
    }

    auto *rx_base = static_cast<uint8_t *>(mmap_rx);
    auto *tx_base = static_cast<uint8_t *>(mmap_tx);
    auto *fill_base = static_cast<uint8_t *>(mmap_fill);
    auto *completion_base = static_cast<uint8_t *>(mmap_completion);

    this->consumer.rx = reinterpret_cast<__u32 *>(rx_base + this->mmap_offsets.rx.consumer);
    this->producer.rx = reinterpret_cast<__u32 *>(rx_base + this->mmap_offsets.rx.producer);
    this->consumer.tx = reinterpret_cast<__u32 *>(tx_base + this->mmap_offsets.tx.consumer);
    this->producer.tx = reinterpret_cast<__u32 *>(tx_base + this->mmap_offsets.tx.producer);

    this->consumer.fill = reinterpret_cast<__u32 *>(fill_base + this->mmap_offsets.fr.consumer);
    this->producer.fill = reinterpret_cast<__u32 *>(fill_base + this->mmap_offsets.fr.producer);

    this->consumer.completion = reinterpret_cast<__u32 *>(completion_base + this->mmap_offsets.cr.consumer);
    this->producer.completion = reinterpret_cast<__u32 *>(completion_base + this->mmap_offsets.cr.producer);

    this->rx_ring = reinterpret_cast<xdp_desc *>(rx_base + this->mmap_offsets.rx.desc);
    this->tx_ring = reinterpret_cast<xdp_desc *>(tx_base + this->mmap_offsets.tx.desc);
    this->fill_ring = reinterpret_cast<__u64 *>(fill_base + this->mmap_offsets.fr.desc);
    this->completion_ring = reinterpret_cast<__u64 *>(completion_base + this->mmap_offsets.cr.desc);

    this->ifindex = if_nametoindex(NETWORK_INTERFACE);

    if(this->ifindex == 0)
    {
      perror_and_throw("TcpSocket::Socket() - if_nametoindex(lo) failed");
    }

    this->sock_addr = { .sxdp_family = AF_XDP, .sxdp_flags = 0, .sxdp_ifindex = this->ifindex, .sxdp_queue_id = 0, .sxdp_shared_umem_fd = static_cast<__u32>(this->fd) };

    // prime emm
    prime_fill_ring(this->fill_ring, this->producer.fill);
    prime_completion_ring(this->completion_ring, this->tx_ring, this->producer.completion);

    if(bind(this->fd, reinterpret_cast<const sockaddr *>(&this->sock_addr), sizeof(this->sock_addr)) == -1)
    {
      perror_and_throw("TcpSocket::Socket() - bind raw socket failed");
    }

    load_xdp_program(this->ifindex, this->fd);

    this->xdp_attached = true;
  };

  void *Socket::wait_for_a_packet(xdp_desc *&desc, std::atomic<uint8_t> &signal)
  {
    pollfd pfd{ .fd = this->fd, .events = POLLIN, .revents = 0 };

    for(;;)
    {
      const int ret = poll(&pfd, 1, -1);

      if(ret == -1)
      {
        if(errno == EINTR)
        {
          continue;
        }

        perror_and_throw("TcpSocket::wait_for_one_packet() - poll failed");
      }

      if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
      {
        throw std::runtime_error{ "TcpSocket::wait_for_one_packet() - poll reported socket error" };
      }

      xdp_desc *packet = nullptr;
      for(; packet == nullptr; packet = this->get_rx_packet_ptr())
      {
      }

      desc = packet;

      if(desc->addr >= UMEM_LEN || desc->len > UMEM_LEN - desc->addr)
      {
        throw std::runtime_error{ "TcpSocket::wait_for_one_packet() - invalid RX descriptor" };
      }

      signal.fetch_add(1);

      return this->umem + desc->addr;
    }
  }

} // namespace HttpServer

#pragma GCC diagnostic pop

//
//
//
