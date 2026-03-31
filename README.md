# Eathernet_Stack

## Overview
In this task, a simplified network stack was implemented in C++ to process and generate network packets across multiple layers of the TCP/IP model. The implementation is based on the provided framework and supports Ethernet, ARP, and IPv4 protocols.

## Implemented Features

### Ethernet Layer
- Parses incoming Ethernet frames and extracts source and destination MAC addresses.
- Dispatches payload based on EtherType:
  - IPv4 packets are forwarded to the IPv4 layer.
  - ARP packets are forwarded to the ARP layer.
- Unsupported frame types are ignored.
- Constructs and sends Ethernet frames for outgoing packets.

### ARP (Address Resolution Protocol)
- Processes ARP requests for IPv4 over Ethernet.
- Logs incoming ARP requests.
- Generates ARP replies when the request targets the local IP address.
- Constructs valid ARP response packets and forwards them to the Ethernet layer.

### IPv4 Layer
- Parses IPv4 packets and logs source and destination IP addresses.
- Processes only packets addressed to the local IP.
- Identifies encapsulated protocols using the protocol field.
- Forwards valid payloads to higher layers when applicable.
- Constructs IPv4 packets and sends them via the Ethernet layer.

## Notes
- The implementation follows a layered architecture where each protocol handles its own logic.
- Proper byte-order conversions are handled using standard networking functions (`ntohs`, `ntohl`, `htons`, `htonl`).
- The framework's logging functions are used for all required output.

## Incomplete Parts
- ICMP functionality is not implemented yet.
