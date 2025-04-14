#include <pcap.h>
#include <iostream>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <net/ethernet.h>     // For Ethernet header
#include <netinet/ip.h>       // For IPv4 header
#include <netinet/tcp.h>      // For TCP header
#include <netinet/udp.h>      // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header

#include "pcap-abbv.h"
//todo add function to make cerr print or not

//order of IP pairs should not be important

//Get L2 to find L3
std::string getUniqueStreamKey(const char *packet, int capLen) {
    // Verify that the packet is long enough for an Ethernet header.
    //otherwise, we can segfault when recast as ether_header
    if (capLen < sizeof(struct ether_header)) {
        std::cerr << "Error in size is less than ethernet header minimum" << std::endl;
        return "";
    }

    //do we have other types besides ethernet L2 header to consider?
    const struct ether_header *eth_hdr = reinterpret_cast<const struct ether_header *>(packet);
    //which L3 protocol we are dealing with, eg ipv4 or ipv6
    uint16_t l3ProtoType= ntohs(eth_hdr->ether_type);
    if ((l3ProtoType != ETHERTYPE_IP) || (l3ProtoType != ETHERTYPE_IPV6)) { //the only L3 protocols we handle
        std::cerr << "Error in L3, neither ipv4 or ipv6" << std::endl;
        return "";
    }
    return generateStreamIpKey(packet+sizeof(struct ether_header), capLen, l3ProtoType);
}

//Parse L3 portion of key due to Ipv4 or Ipv6
std::string generateStreamIpKey (const char  *ipPacket, int capLen, uint16_t l3Prototype) {
    //prep variables for ipv4/6 later on
    std::string streamKey;
    std::string protocolInfo;

    // Convert IP addresses to strings.
    char srcIp[INET6_ADDRSTRLEN], dstIp[INET6_ADDRSTRLEN];  //big enough for boht ipv4 and ipv6


    //we now point to ipv4 or ipv6 packet
    uint16_t ipHdrLength=0;
    if (l3Prototype==ETHERTYPE_IP) {
        if (capLen < sizeof(struct ether_header) + sizeof(struct ip)) {
            std::cerr << "Error in size is less than ipv4 header minimum" << std::endl;
            return "";
        }
        ipv4Hdr = reinterpret_cast<const struct ip *>(ipPacket);
        if (inet_ntop(AF_INET, &(ip_hdr->ip_src), srcIp, INET_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting source IPv4 address" << std::endl;
            return "";
        }
        if (inet_ntop(AF_INET, &(ip_hdr->ip_dst), dstIp, INET_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting destination IPv4 address" << std::endl;
            return "";  //need to return empty string
        }
        l4Layer = ipPacket+sizeof(struct ip_hdr);
        proto = ipv4Hdr->ip_p;
        ip_header_length = ipv4Hdr->ip_hl * 4; //options
    } else if (l3ProtoType==ETHERTYPE_IPV6) {
        if (capLen < sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
            std::cerr << "Error in size is less than ipv4 minimum" << std::endl;
            return "";
        }
        const struct *ip6Hdr = reinterpret_cast<const struct ip6_hdr*>(ipPacket);
        // Convert IPv6 binary to string
        if (inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), srcIp, INET6_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting source IPv6 address" << std::endl;
            return "";
        }
        if (inet_ntop(AF_INET6,&(ip6_hdr->ip6_dst), dstIp, INET6_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting destination IPv6 address" << std::endl;
            return "";
        }
        // IPv6 has fixed header length of 40 bytes; options are handled as extension headers

        l4Layer = ipPacket+sizeof(struct ip6_hdr); //point to tcp/udp
        proto=ip6Hdr->ip6_nxt;

    }
    return l4KeyParsing(l4Layer, proto, srcIp, dstIp, capLen-ipHdrLen);
}

//parse L4
std::string l4KeyParsing(const char *l4Hdr, uint16_t proto, const std::string &srcIp, const std::string &destIP, int capLen) {
// Based on the IP protocol, parse further.
//assume IPv4/6 as L3, so TCP, UDP, and ICMP are valid
    if (proto == IPPROTO_TCP) {
        // Ensure that there is sufficient data for the TCP header.
        if (capLen < sizeof(struct ether_header) +  sizeof(struct tcphdr)) {
            std::cerr << "Error in buffer size for TCP header " << std::endl;
            return "";
        }
        const struct tcpHdr *tcp_hdr = reinterpret_cast<const struct tcphdr *>(ipPacket + ip_header_length);
        uint16_t srcPort = ntohs(tcpHdr->th_sport);
        uint16_t dstPort = ntohs(tcpHdr->th_dport);
        streamKey = generateStreamTcpUdpKey(srcIp, srcPort, dstIp, dstPort);
        protocolInfo = "TCP" + getTcpFlags(tcp_hdr);
    } else if (proto == IPPROTO_UDP) {
        // Ensure that there is sufficient data for the UDP header.
        if ( < sizeof(struct ether_header) + sizeof(struct udphdr)) {
            std::cerr << "Error in buffer size for UDP header " << std::endl;
            return  "";
        }
        const struct udphdr *udp_hdr = reinterpret_cast<const struct udphdr *>(ipPacket + ip_header_length);
        uint16_t srcPort = ntohs(udp_hdr->uh_sport);
        uint16_t dstPort = ntohs(udp_hdr->uh_dport);
        streamKey = generateStreamTcpUdpKey(srcIp, srcPort, dstIp, dstPort);
        protocolInfo = "UDP" + getUdpInfo(udp_hdr);
    } else if (proto == IPPROTO_ICMP) {
        // Ensure that there is sufficient data for the ICMP header.

        if (capLen < sizeof(struct ether_header) +  sizeof(struct icmp)) {
            std::cerr << "Error in buffer size for ICMP  header " << std::endl;
            return "";
        }
        const struct icmp *icmp_hdr = reinterpret_cast<const struct icmp *>(ipPacket + ip_header_length);
        // For echo request/reply, include the identifier in the key.
        if (icmp_hdr->icmp_type == ICMP_ECHO || icmp_hdr->icmp_type == ICMP_ECHOREPLY)
            streamKey = generateIcmpStreamKey(srcIp, dstIp, icmp_hdr->icmp_type, icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_id), true);
        else
            streamKey = generateIcmpStreamKey(srcIp, dstIp, icmp_hdr->icmp_type, icmp_hdr->icmp_code);

        protocolInfo = "ICMP" + getIcmpInfo(icmp_hdr);
    } else {
        // Skip any protocols other than TCP/UDP/ICMP.
        return "";
    }   //decide based upon protocol
    return protocolInfo;
}

std::string generateStreamTcpUdpKey(const std::string &ip1, uint16_t port1,
                                    const std::string &ip2, uint16_t port2) {
    if ((ip1 < ip2) || (ip1 == ip2 && port1 <= port2))
        return ip1 + ":" + std::to_string(port1) + "-" + ip2 + ":" + std::to_string(port2);
    else
        return ip2 + ":" + std::to_string(port2) + "-" + ip1 + ":" + std::to_string(port1);
}

// For ICMP flows, generate a stream key.
// For echo requests/replies, include the ICMP identifier. For others, include type/code.
std::string generateIcmpStreamKey(const std::string &ip1, const std::string &ip2,
                                  int icmp_type, int icmp_code, uint16_t id = 0, bool useId = false) {
    std::string base;
    //ip address should be interchangable
    //or should it?
    if (ip1 < ip2) {
        base = ip1 + "-" + ip2;
    } else {
        base = ip2 + "-" + ip1;
    }

    std::stringstream ss;
    if (useId)
        ss << "ICMP_" << base << "_id" << id;
    else
        ss << "ICMP_" << base << "_type" << icmp_type << "_code" << icmp_code;
    return ss.str();
}
