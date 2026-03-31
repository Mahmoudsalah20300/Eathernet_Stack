/* 
Author: Mahmoud Ali
*/
#include "ipv4.h"
#include "../layer_link/ethernet.h"
#include "../icmp/icmp.h"
#include "../logging.h"

#include <algorithm>
#include <cstring>

using namespace IPv4;

Protocol::Protocol(const Address &address) : ipAddress(address) {
  icmp_handler = std::make_unique<ICMP::Protocol>(this);
}

void Protocol::handle_packet(const Ethernet::Address &src_mac, const uint8_t *buffer,
                             size_t buffer_len) {
// TODO: Implement this method!
if(buffer_len < sizeof(Header))
      return;
 
 auto ip_frame = reinterpret_cast<const Frame *>(buffer);
 const Header &hdr = ip_frame->hdr;
 
 if (hdr.ip_v != 4) {
     // Not IPv4
     return;
 }
  size_t header_len = hdr.ip_hl * 4;
  if(header_len < sizeof(Header) || buffer_len < header_len)
      return;
  
  log_ip_packet(&hdr.ip_src, &hdr.ip_dst);
  if (!isOwnIpAddress(hdr.ip_dst)) {
      // Not for us
      return;
  }
  
  if(hdr.ip_p == 1) { 
  const uint8_t *payload = buffer + header_len;
  size_t payload_len = buffer_len - header_len;
  if(icmp_handler){
      icmp_handler->handle_packet(src_mac, hdr.ip_src, hdr.ip_dst, 
                                  payload, payload_len);
  }    
  }
}

void Protocol::send(const Ethernet::Address &dst_mac, const IPv4::Address &dst_ip,
                    const uint16_t protocol, uint8_t *payload, size_t payload_len) {
// TODO: Implement this method!
size_t header_len = sizeof(Header);
  size_t total_len = header_len + payload_len;
  
  // Create buffer for IP packet
  uint8_t *packet_buffer = new uint8_t[total_len];
  Frame *ip_frame = reinterpret_cast<Frame *>(packet_buffer);
  
  // Fill IPv4 header
  Header &hdr = ip_frame->hdr;
  
  hdr.ip_v = 4;                     
  hdr.ip_hl = sizeof(Header) / 4;   
  hdr.ip_tos = 0;                   
  hdr.ip_len = htons(total_len);    
  hdr.ip_id = htons(0);             
  hdr.ip_off = 0;                   
  hdr.ip_ttl = 64;                  
  hdr.ip_p = protocol;              
  hdr.ip_sum = 0;                   
  hdr.ip_src = ipAddress;           
  hdr.ip_dst = dst_ip;              
  
  
  hdr.ip_sum = checksum(&hdr, header_len);
  
  
  if (payload_len > 0) {
    memcpy(ip_frame->payload, payload, payload_len);
  }
  
  
  log_ip_packet(&hdr.ip_src, &hdr.ip_dst);
  
  
  if (ethernet_handler) {
    ethernet_handler->send(dst_mac, Ethernet::TYPE_IP, packet_buffer, total_len);
  }
  
  delete[] packet_buffer;
}
