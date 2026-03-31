/*
Author: Mahmoud Ali
*/
#include "arp.h"
#include "../layer_link/ethernet.h"
#include "../layer_internet/ipv4.h"
#include "../logging.h"
#include <cstring>

#define ARPPRO_IP 2048

using namespace ARP;

void Protocol::handle_packet(const uint8_t *buffer, size_t buffer_len) {
  
  if (buffer_len < sizeof(Packet)) {
    return;
  }

  auto arp_packet = reinterpret_cast<const Packet *>(buffer);
  
  
  if (ntohs(arp_packet->hdr.ar_hrd) != ARPHRD_ETHER || 
      ntohs(arp_packet->hdr.ar_pro) != ARPPRO_IP) {
    return;  
  }

  
  uint16_t ar_op = ntohs(arp_packet->hdr.ar_op);
  
  if (ar_op == ARPOP_REQUEST) {
  
    Ethernet::Address src_mac = arp_packet->src_mac;
    IPv4::Address src_ip = arp_packet->src_ip;
    Ethernet::Address dst_mac = arp_packet->dst_mac;
    IPv4::Address dst_ip = arp_packet->dst_ip;
    
  
    log_arp_request(&src_mac, &src_ip, &dst_mac, &dst_ip);
    
  
    if (ipv4_handler && ipv4_handler->isOwnIpAddress(dst_ip)) {
  
      send(src_mac, src_ip, dst_mac, dst_ip);
    }
  }
}

void Protocol::send(const Ethernet::Address &src_mac, const IPv4::Address &src_ip,
                    const Ethernet::Address &dst_mac, const IPv4::Address &dst_ip) {
  
  Packet arp_reply;
  
  
  arp_reply.hdr.ar_hrd = htons(ARPHRD_ETHER);  
  arp_reply.hdr.ar_pro = htons(ARPPRO_IP);     
  arp_reply.hdr.ar_hln = ETH_ALEN;            
  arp_reply.hdr.ar_pln = sizeof(IPv4::Address); 
  arp_reply.hdr.ar_op = htons(ARPOP_REPLY);    
  

  Ethernet::Address our_mac;
  if (ethernet_handler) {
    our_mac = ethernet_handler->mac;
  } else {

    memset(&our_mac, 0xff, sizeof(our_mac));
  }
  
  memcpy(&arp_reply.src_mac, &our_mac, sizeof(Ethernet::Address));
  arp_reply.src_ip = dst_ip;  
  memcpy(&arp_reply.dst_mac, &src_mac, sizeof(Ethernet::Address));
  arp_reply.dst_ip = src_ip;  
  

  Ethernet::Address log_src_mac = arp_reply.src_mac;
  IPv4::Address log_src_ip = arp_reply.src_ip;
  Ethernet::Address log_dst_mac = arp_reply.dst_mac;
  IPv4::Address log_dst_ip = arp_reply.dst_ip;
  

  log_arp_reply(&log_src_mac, &log_src_ip, &log_dst_mac, &log_dst_ip);
  

  if (ethernet_handler) {
    ethernet_handler->send(src_mac, Ethernet::TYPE_ARP, 
                          reinterpret_cast<uint8_t *>(&arp_reply), sizeof(Packet));
  }
}