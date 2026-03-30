#include "ethernet.h"
#include "../layer_internet/arp.h"
#include "../layer_internet/ipv4.h"
#include "../logging.h"

#include <cstring>
#include <algorithm>

using namespace Ethernet;

void Protocol::handle_packet(const uint8_t *buffer, size_t buffer_len) {
  if (buffer_len < sizeof(Frame))
    return;

  auto frame = reinterpret_cast<const Frame *>(buffer);
  log_ethernet_frame(reinterpret_cast<const Address *>(frame->hdr.ether_shost),
                     reinterpret_cast<const Address *>(frame->hdr.ether_dhost));
// TODO: Implement this method!
  uint16_t ether_type = ntohs(frame->hdr.ether_type);

  const uint8_t *payload = frame->payload;
  size_t payload_len = buffer_len - sizeof(Header);

  switch (ether_type)
  {
    case  TYPE_ARP:
      if(arp_handler){
        arp_handler->handle_packet(payload, payload_len);
      }
      break;
    case TYPE_IP:
      if(ipv4_handler){
        Ethernet::Address src_mac;
        memccpy(&src_mac, frame->hdr.ether_shost, 1, ETH_ALEN);
        ipv4_handler->handle_packet( src_mac, payload, payload_len);
      }
      break;
    default:
      // Keine Aktion für unbekannte Ether-Typen
      break;  
  }
}

void Protocol::send(const Address &dst, uint16_t ether_type, uint8_t *payload, size_t payload_len) {
// TODO: Implement this method!
size_t frame_size = sizeof(Header) + payload_len;
uint8_t *frame_buffer = new uint8_t[frame_size];
Frame *frame = reinterpret_cast<Frame *>(frame_buffer);

memcpy(frame->hdr.ether_dhost, &dst, ETH_ALEN);
memcpy(frame->hdr.ether_shost, &mac, ETH_ALEN);
frame->hdr.ether_type = htons(ether_type);

if(payload_len>0)
{
    memcpy(frame->payload, payload, payload_len);
}

log_ethernet_frame(&mac, &dst);
send(frame_buffer, frame_size);
delete[] frame_buffer;
}
