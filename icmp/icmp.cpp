#include "icmp.h"
#include "../logging.h"
#include <cstring>

using namespace ICMP;

void Protocol::handle_packet(const Ethernet::Address &src_mac, const IPv4::Address &src_ip,
                             const IPv4::Address &dst_ip, const uint8_t *buffer,
                             size_t buffer_len) {
// TODO: Implement this method!
}

void Protocol::send(const Frame *req_frame, size_t frame_len, const Ethernet::Address &dst_mac,
                    const IPv4::Address &dst_ip) {
// TODO: Implement this method!
}
