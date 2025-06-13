# SoftEther VPN Laboratory Activity

![Politecnico di Torino](resources/General/logo_polito.png)

## Overview

This repository contains a comprehensive laboratory activity that demonstrates the implementation and comparative analysis of Virtual Private Network (VPN) technologies using SoftEther VPN's multi-protocol capabilities. The project simulates realistic network scenarios where geographically separated private networks communicate securely across the Internet through encrypted VPN tunnels.

## Project Description

This laboratory activity explores two major VPN implementations within a unified SoftEther VPN platform:

- **IPSec VPN**: Network-layer security using strongSwan client with ISAKMP/ESP protocols
- **TLS/SSL VPN**: Session-layer security using OpenVPN client with certificate-based authentication

The project demonstrates how different VPN protocols achieve the same security objectives through different technical approaches, providing hands-on experience with both kernel-space (IPSec) and user-space (TLS) VPN implementations.

## Key Accomplishments

### Network Infrastructure Design
- Implemented realistic Internet topology using GNS3 with Cisco routers
- Configured NAT traversal and port forwarding for VPN services
- Simulated ISP infrastructure with public IP addressing and routing

### Multi-Protocol VPN Implementation
- Deployed SoftEther VPN server supporting simultaneous IPSec and TLS connections
- Configured strongSwan IPSec client with pre-shared key authentication
- Set up OpenVPN TLS client with X.509 certificate validation
- Implemented SecureNAT for automatic client IP assignment and routing

### Security Analysis
- Performed detailed packet analysis using Wireshark
- Compared encryption mechanisms between IPSec ESP and TLS protocols
- Analyzed VPN tunnel establishment phases and traffic encapsulation
- Evaluated NAT traversal capabilities and firewall compatibility

### Educational Framework
- Created comprehensive documentation with step-by-step configurations
- Developed comparative analysis of VPN protocol characteristics
- Provided troubleshooting guidance and verification procedures

## Technologies Used

### Networking & Simulation
- **GNS3**: Network topology simulation and management
- **Cisco IOS**: Router configuration and enterprise networking
- **Docker**: Containerized VPN endpoints and service isolation

### VPN Technologies
- **SoftEther VPN**: Multi-protocol VPN server platform
- **strongSwan**: IPSec implementation for Linux systems
- **OpenVPN**: SSL/TLS VPN client software

### Security Protocols
- **IPSec**: Internet Protocol Security with ESP encapsulation
- **TLS/SSL**: Transport Layer Security for encrypted tunnels
- **X.509 PKI**: Public Key Infrastructure for certificate management

### Analysis Tools
- **Wireshark**: Network protocol analysis and packet inspection
- **Linux networking**: Advanced routing, NAT, and interface configuration

## Network Architecture

The laboratory implements a realistic three-tier network topology:

```
[Server Network] ↔ [Edge Router] ↔ [ISP Router] ↔ [Edge Router] ↔ [Client Network]
   10.0.1.0/24        203.0.113.1    Internet    198.51.100.1      10.0.2.0/24
```

This design demonstrates:
- Site-to-site VPN connectivity across public Internet infrastructure
- NAT traversal for VPN protocols behind network address translation
- Port forwarding configuration for VPN service accessibility
- Realistic routing and addressing schemes using RFC-compliant networks

## Documentation Structure

```
├── main/                    # LaTeX source files for comprehensive lab report
│   ├── SoftEther_VPN_Lab.tex
│   └── sections/            # Individual report sections
├── Utilities/               # Reference materials and examples
│   ├── Examples/            # Sample configurations and lab exercises
│   └── Project_Structure/   # Network topology documentation
├── Makefile                 # Automated PDF compilation
└── README.md               # This file
```

## Related Resources

### SoftEther VPN
- **Official Repository**: [SoftEtherVPN/SoftEtherVPN](https://github.com/SoftEtherVPN/SoftEtherVPN)
- **Official Documentation**: [SoftEther VPN Project](https://www.softether.org/)
- **Installation Guide**: [SoftEther VPN Manual](https://www.softether.org/4-docs)

### IPSec & strongSwan
- **strongSwan Project**: [strongSwan VPN](https://www.strongswan.org/)
- **IPSec Documentation**: [RFC 4301 - Security Architecture for IP](https://tools.ietf.org/html/rfc4301)
- **strongSwan Configuration**: [strongSwan Documentation](https://docs.strongswan.org/)

### OpenVPN & TLS
- **OpenVPN Project**: [OpenVPN Community](https://openvpn.net/community/)
- **TLS Protocol**: [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- **OpenVPN HOWTO**: [OpenVPN 2.4 Manual](https://openvpn.net/community-resources/how-to/)

### Network Simulation
- **GNS3 Project**: [GNS3 Network Simulator](https://www.gns3.com/)
- **GNS3 Documentation**: [GNS3 Docs](https://docs.gns3.com/)

## Academic Context

This laboratory activity was developed as part of the **Network and Cloud Security** course at **Politecnico di Torino**, Master's degree in **Cybersecurity Engineering**. The project provides practical experience with enterprise VPN technologies and demonstrates real-world applications of network security protocols.

## Key Learning Outcomes

- Understanding of VPN protocol differences and use cases
- Hands-on experience with enterprise network simulation
- Practical knowledge of IPSec and TLS security mechanisms
- Network security analysis and troubleshooting skills
- Comparative evaluation of different VPN implementation approaches

## License

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.

## Contact

**Renato Mignone**  
- [LinkedIn](https://www.linkedin.com/in/renato-mignone/)  
- MSc in Cybersecurity Engineering, Politecnico di Torino

---

[![Python](https://img.shields.io/badge/GNS3-Network_Simulation-blue)](https://www.gns3.com/)
[![Docker](https://img.shields.io/badge/Docker-Containerization-lightblue)](https://www.docker.com/)
[![SoftEther](https://img.shields.io/badge/SoftEther-VPN_Platform-green)](https://www.softether.org/)
[![IPSec](https://img.shields.io/badge/IPSec-Network_Security-red)](https://tools.ietf.org/html/rfc4301)
[![TLS](https://img.shields.io/badge/TLS-Transport_Security-orange)](https://tools.ietf.org/html/rfc8446)