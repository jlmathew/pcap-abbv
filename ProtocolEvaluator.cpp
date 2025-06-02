#include <pcap.h>
#include <iostream>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <net/ethernet.h>     // For Ethernet header
#include <netinet/ip.h>       // For IPv4 header
#include <netinet/tcp.h>      // For TCP header
#include <netinet/udp.h>      // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/icmp6.h>


#include "pcap-abbv.h"
//todo add function to make cerr print or not

/* pcap only uses a local buffer for each packet, if faster processing is required, it needs to be copied.  stack is fast, heap is slow, but heap allows easier tracking and saving of packets.
Ideally, we would want to use 64 byte contingous buffer for x86 (128byte for apple M cpu), to align with memory access (to avoid an extra memory load or 2 cache misses), ideally per protocol.   What creates a mess is each protocol can be different.  Eg. 802.3 (l2) and IPv4 can both fit into 64 byte cache line, unless IP options are included,
which changes Ipv4 from 20 bytes minimum size to 60 bytes maximum size.   We could have a massive allocation, and assign within that block (most linux program heaps are about 8MB, and spawned threads are 2MB, so that could be an , but that is a lot of difficulty in design, for a packet that will be read once (and then potentially copied and stored).
The idea is to have multiple threads working on packets, where each thread aligns with a key mapping eg thread[key] and place the packets in a deque for processing (deque is more appropriate than
vector for unknown number of packets, which pop to a stack and pulled from the processing thread (fifo).

Overall, this appears to be an over design.  We need a unique lookup key (typically L3 IP (src,dst) proto (ipv4, icmpv4, ipv6,  along with L4 (proto and ports).
since this packet is already provied by pcap, even if memory may be misaligned (we would need to read it anyways to create a key, and then create allocations/alignment), lets process it early and see if
we need to create the key (using libraries to convert ints to string) if some evaluators match.

eg. if we are ONLY interested in TCP packets, we do not need to save/allocate memory for UDP.  Its not of interest.   Likewise, if its typical data transfer, we dont want to save all the packets.

so the plan is to break down the evaluators into 2 groups:
1. Those that can be immediately evaluated (hard compare, eg tcp_port=55 or over evaluators ">" "<" ==" "<> "!"
2. Those that require a key for evaluation (eg counting evaluators like if 2+ SYN's are seen, etc).

By knowing the evaluators, we can (at least) match if the protocol is worth creating a key and additional testing.   If it needs to be saved, we can do a direct copy (no need for memory alignment, as it will only be saved or not, and not reused).



the goal is to save 'packets of interest', so we will record required info (prototype, ip, ports), and convert to string, only if further evaluation is required (or if its to be saved, as its of 'interest'')

Have a vector of funcion calls at each level of protocol, if the proto is empty for each level, we dont save or process.

//for encapsulation, the filters refer to all (eg ipv4 encapuslation ipv4, it applies to both, and results are OR'd), unless filter specifies depth (egTcp:d1_<name>

*/
//https://pcapplusplus.github.io/ may be helpful

class evaluateNetProto {
public
evaluatePacket(uint8_t *packetLayer)==0;

};

class evaluateNet8023Proto :: public evaluateNetProto {};
class evaluateNetIpv4Proto :: public evaluateNetProto {};
class evaluateNetIpv6Proto :: public evaluateNetProto {};
class evaluateNetTcpProto :: public evaluateNetProto {};
class evaluateNetIpv6Proto :: public evaluateNetProto {};


class evaluatePackets {
   //each protocol has its own object
   //parse 'interest' filter
   //parse 'save' filter

   //instantiate inputting default values

   //filter at each layer/encapsulation, and save info (proto, key metrics, link)
packetLayerHelper_t packetLayerHelper;
const u_char *packet;
u_int capLen;
std::string m_lookUpKey;
bool m_savePkt;


//first eval is always L2 from pcap, then linked list of <proto #, index into buffer, length, vector pointer to evaluation functional pointers

};

using evalFnPtr = bool(*)(const unsigned char *);
bool savePacketOfInterest(const unsigned char *);

std::vector<evalFnPtr> m_l2_8023ProtoFnEval;
std::vector<evalFnPtr> m_l3_Ipv4ProtoFnEval;
std::vector<evalFnPtr> m_l3_Icmpv4ProtoFnEval;
std::vector<evalFnPtr> m_l4_tcpProtoFnEval;
std::vector<evalFnPtr> m_l4_Icmpv6ProtoFnEval;

//key only needs most relevant info, eg do we use internal encapsulated proto or not?


//handle packet encapsulation ....
//ipv6[ipv4[tcp]] (gre?)

//map protocol # to vector of functions

std::unordered_map<uint16_t, std::vector<evalFnPtr> *> m_mapProtoToEval;



//order of IP pairs should not be important

//Get L2 to find L3
//since we have to parse packet for protocol, lets save the pointers to do it once
std::string getUniqueStreamKey(const u_char *packet, u_int capLen,  packetLayerHelper_t *packetLayerHelper) {
    // Verify that the packet is long enough for an Ethernet header.
    //otherwise, we can segfault when recast as ether_header

    packetLayerHelper->layer2Ptr=packet;

    if (capLen < sizeof(struct ether_header)) {
        std::cerr << "Error in size is less than ethernet header minimum" << std::endl;
        return "";
    }

    //do we have other types besides ethernet L2 header to consider?
    const struct ether_header *ethHdr = reinterpret_cast<const struct ether_header *>(packet);
    //which L3 protocol we are dealing with, eg ipv4 or ipv6
    uint16_t l3ProtoType= ntohs(ethHdr->ether_type);
    if ((l3ProtoType != ETHERTYPE_IP) && (l3ProtoType != ETHERTYPE_IPV6)) { //the only L3 protocols we handle
        std::cerr << "Error in L3, neither ipv4 or ipv6" << std::endl;
        return "";
    }
    packetLayerHelper->layer3Proto=l3ProtoType;

    return generateStreamL3Key(packet+sizeof(struct ether_header), capLen, l3ProtoType, packetLayerHelper);
}

//Parse L3 portion of key due to Ipv4 or Ipv6
std::string generateStreamL3Key (const u_char  *ipPacket, u_int capLen, uint16_t l3Prototype, packetLayerHelper_t *packetLayerHelper) {
    //prep variables for ipv4/6 later on
    std::string streamL3Key;
    std::string protocolInfo;
    packetLayerHelper->layer3Ptr=ipPacket;

    // Convert IP addresses to strings.
    char srcIp[INET6_ADDRSTRLEN], dstIp[INET6_ADDRSTRLEN];  //big enough for boht ipv4 and ipv6


    //we now point to ipv4 or ipv6 packet
    uint16_t ipHeaderOptionLength=0;
    const struct ip *ipv4Hdr=nullptr;
    const struct ip6_hdr *ipv6Hdr=nullptr;
    uint16_t proto=0;
    const u_char *l4Layer=nullptr;
    bool srcFirst;

    if (l3Prototype==ETHERTYPE_IP) {
        if (capLen < sizeof(struct ether_header) + sizeof(struct ip)) {
            std::cerr << "Error in size is less than ipv4 header minimum" << std::endl;
            return "";
        }
        ipv4Hdr = reinterpret_cast<const struct ip *>(ipPacket);
        if (nullptr == inet_ntop(AF_INET, &(ipv4Hdr->ip_src), srcIp, INET_ADDRSTRLEN) ) {
            std::cerr << "Error converting source IPv4 address" << std::endl;
            return "";
        }
        if (nullptr == inet_ntop(AF_INET, &(ipv4Hdr->ip_dst), dstIp, INET_ADDRSTRLEN)) {
            std::cerr << "Error converting destination IPv4 address" << std::endl;
            return "";  //need to return empty string
        }
        l4Layer = ipPacket+sizeof(struct iphdr);
        proto = ipv4Hdr->ip_p;
        ipHeaderOptionLength = ipv4Hdr->ip_hl * 4; //options
        streamL3Key="ip4_";
        //create strings of characters for comparison
        std::string srcIpStr(srcIp);
        std::string dstIpStr(dstIp);
        if (srcIpStr >=dstIpStr) {
            streamL3Key.append(srcIpStr).append(":").append(dstIpStr);
            srcFirst=true;
        } else {
            streamL3Key.append(dstIpStr).append(":").append(srcIpStr);
            srcFirst=false;
        }
    } else if (l3Prototype==ETHERTYPE_IPV6) {
        if (capLen < sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
            std::cerr << "Error in size is less than ipv4 minimum" << std::endl;
            return "";
        }
        ipv6Hdr = reinterpret_cast<const struct ip6_hdr*>(ipPacket);
        // Convert IPv6 binary to string
        if (inet_ntop(AF_INET6, &(ipv6Hdr->ip6_src), srcIp, INET6_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting source IPv6 address" << std::endl;
            return "";
        }
        if (inet_ntop(AF_INET6,&(ipv6Hdr->ip6_dst), dstIp, INET6_ADDRSTRLEN) == nullptr) {
            std::cerr << "Error converting destination IPv6 address" << std::endl;
            return "";
        }
        // IPv6 has fixed header length of 40 bytes; options are handled as extension headers

        l4Layer = ipPacket+sizeof(struct ip6_hdr); //point to tcp/udp
        proto=ipv6Hdr->ip6_nxt;
        streamL3Key="ip6";
        if (srcIp >= dstIp) {
            streamL3Key.append(srcIp).append(":").append(dstIp);
            srcFirst = true;
        } else {
            streamL3Key.append(dstIp).append(":").append(srcIp);
            srcFirst = false;
        }
    } else { //unsupported
        std::cerr << "Unsupport L3 protocol " << l3Prototype << std::endl;
        return "";
    }

    //we need to pass if the L3/IP layer is src first or dest first, as the ports are part of the addr (for L4)
    //ergo Ip1:port1-IP2:port2 are pairs, and ip1:port2-ip2:port1 are not the same stream.
    packetLayerHelper->layer4Proto=proto;
    packetLayerHelper->layer4Ptr=l4Layer;
    return l4KeyParsing(l4Layer, proto, streamL3Key, capLen-ipHeaderOptionLength, srcFirst, packetLayerHelper);
}

//parse L4
std::string l4KeyParsing(const u_char *l4Hdr, uint16_t proto, const std::string &l3Key, u_int capLen, bool srcFirst, packetLayerHelper_t *packetLayerHelper ) {
// Based on the IP protocol, parse further.
//assume IPv4/6 as L3, so TCP, UDP, and ICMP are valid
    std::string streamL4Key(l3Key);
    if (proto == IPPROTO_TCP) {
        // Ensure that there is sufficient data for the TCP header.
        if (capLen < sizeof(struct tcphdr)) {
            std::cerr << "Error in buffer size for TCP header " << std::endl;
            return "";
        }
        const struct tcphdr *tcpHdr = reinterpret_cast<const struct tcphdr *>(l4Hdr);
        uint16_t srcPort = ntohs(tcpHdr->th_sport);
        uint16_t dstPort = ntohs(tcpHdr->th_dport);
        streamL4Key.append("_TCP").append(generateStreamTcpUdpKey(srcPort, dstPort,srcFirst));
        //protocolInfo = "TCP" + getTcpFlags(tcp_hdr);
    } else if (proto == IPPROTO_UDP) {
        // Ensure that there is sufficient data for the UDP header.
        if ( capLen < sizeof(struct udphdr)) {
            std::cerr << "Error in buffer size for UDP header " << std::endl;
            return  "";
        }
        const struct udphdr *udp_hdr = reinterpret_cast<const struct udphdr *>(l4Hdr);
        uint16_t srcPort = ntohs(udp_hdr->uh_sport);
        uint16_t dstPort = ntohs(udp_hdr->uh_dport);
        streamL4Key.append("UDP").append(generateStreamTcpUdpKey(srcPort, dstPort, srcFirst));
        //protocolInfo = "UDP" + getUdpInfo(udp_hdr);
    } else if (proto == IPPROTO_ICMP) {
        // Ensure that there is sufficient data for the ICMP header.

        if (capLen < sizeof(struct ether_header) +  sizeof(struct icmp)) {
            std::cerr << "Error in buffer size for ICMP  header " << std::endl;
            return "";
        }
        const struct icmp *icmp_hdr = reinterpret_cast<const struct icmp *>(l4Hdr);
        // For echo request/reply, include the identifier in the key.
        //FIXME need to append ICMP string
        streamL4Key.append("ICMP4");
        if (icmp_hdr->icmp_type == ICMP_ECHO || icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
            streamL4Key = generateIcmp4StreamKey(icmp_hdr->icmp_type, icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_id), true);
        } else {
            streamL4Key = generateIcmp4StreamKey(icmp_hdr->icmp_type, icmp_hdr->icmp_code);
        }

    } else if (proto == IPPROTO_ICMPV6  ) {
        //TODO later
        const struct icmp6_hdr *icmp6Header = reinterpret_cast<const struct icmp6_hdr *>(l4Hdr);

        std::stringstream ss;
        ss << "_t" << static_cast<int>(icmp6Header->icmp6_type) << "_c" << static_cast<int>(icmp6Header->icmp6_code);
        streamL4Key.append("ICMP6").append(ss.str());
    } else {
        // Skip any protocols other than TCP/UDP/ICMP.
        return "";
    }   //decide based upon protocol
    return streamL4Key;
}

std::string generateStreamTcpUdpKey(uint16_t srcPort, uint16_t dstPort, bool srcFirst) {
    if (srcFirst) {
        return ":" + std::to_string(srcPort) + "-" + std::to_string(dstPort);
    } else {
        return ":" + std::to_string(dstPort) + "-" + std::to_string(srcPort);
    }
}

// For ICMP flows, generate a stream key.
// For echo requests/replies, include the ICMP identifier. For others, include type/code.
std::string generateIcmp4StreamKey(int icmp_type, int icmp_code, uint16_t id, bool useId) {
    std::string base;

    std::stringstream ss;
    if (useId) {
        ss <<  base << "_id" << id;
    } else {
        ss << "_t" << icmp_type << "_c" << icmp_code;
    }
    return ss.str();
}
