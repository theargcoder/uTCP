# uTCP
userspace TCP stack written in C++ and using AF_XDP Zero Copy (when available) socket types, setting them up manually as well as loading manually the eBPF code binding it to the specified network devices (virual or actual hardware NIC). should in practice maximize throughput and minimize latency when compared to linux kernel's implementation while residing purely in userspace code.

## References for eBPF and XDP

[Low-Latency, Deterministic Networking with Standard Linux... Magnus Karlsson & Björn Töpel, Intel](https://www.youtube.com/watch?v=p61PlC9y62k&t=71s)

[eBPF: AF_XDP Socket Setup, eBPF Program and Options-Variations-Exceptions](https://docs.ebpf.io/linux/concepts/af_xdp/)

## References for eBPF Layer 2 code packet filtering 

> Note : There is a billion (sarcasm) layer 2 configurations but I tried to handle how 99% of normal traffic would arrive to a HTTP server in layer 2

[EtherTypes Definitions](https://en.wikipedia.org/wiki/EtherType)

[Ethernet Frames](https://en.wikipedia.org/wiki/Ethernet_frame)

[IEEE_802.1Q](https://en.wikipedia.org/wiki/IEEE_802.1Q)

[IEEE_802.2+ (LLC)](https://en.wikipedia.org/wiki/IEEE_802.2)

[IEEE_802.2+ (SNAP)](https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol)

[MPLS](https://en.wikipedia.org/wiki/Multiprotocol_Label_Switching)

## References for eBPF Layer 3 code packet filtering 

> Note : We dont support IP fragmenting yet; thats a nightmare for later

[IPv4 - Header, fragmenting and more](https://en.wikipedia.org/wiki/IPv4)

[IPv6 - Packet](https://en.wikipedia.org/wiki/IPv6_packet)

## References for eBPF Layer 4 code packet filtering 

[TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)

[UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
