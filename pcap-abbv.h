#ifndef __PCAP_ABBV_H_
#define __PCAP_ABBV_H_

//standard library includes
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

#include <cctype>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint> // Recommended for portable integer types
#include <cstdio>
#include <cstdlib>
#include <unistd.h> // For STDIN_FILENO

//packet header includes
#include <arpa/inet.h>
#include <net/ethernet.h>     // For Ethernet header
#include <netinet/ip.h>       // For IPv4 header
#include <netinet/tcp.h>      // For TCP header
#include <netinet/udp.h>      // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header

//requires apt install libcap-dev
#include <pcap.h>

//if threads are needed
#include <pthread.h>






//class definition
struct packetLayerHelper_t {
    int layer2Proto=0;
    uint16_t layer3Proto=0;
    uint16_t layer4Proto=0;
    const uint8_t *layer2Ptr=nullptr;
    const uint8_t *layer3Ptr=nullptr;
    const uint8_t *layer4Ptr=nullptr;
    //other protocols, if used
    const uint8_t *tlsPtr=nullptr; //for TLS, post L4
    const uint8_t *layer5Ptr=nullptr; //no real protocol value for it, but in case on non TLS

};

struct CapturedPacket_t {
    //PcapRecordHeader recordHeader;
    pcap_pkthdr *pktHdrInfo; //time, length of packet
    std::vector<uint8_t> data;
    std::string lookUpName;
    packetLayerHelper_t *layerHelper;
};

struct Options_t {
    int input;

    std::string fileName;
    enum inputType {
        STREAMINPUT,
        INVALID,
        FILEINPUT,

    };

};



// For in-memory storage: define a structure for a captured packet.

std::string getUniqueStreamKey(const u_char *packetData, u_int capLen, packetLayerHelper_t*);
std::string generateStreamTcpUdpKey(uint16_t port1,
                                    uint16_t port2, bool srcFirst);
std::string l4KeyParsing(const u_char *l4Hdr, uint16_t proto, const std::string &l3Key, u_int capLen, bool srcFirst, packetLayerHelper_t *);
std::string generateIcmp4StreamKey(int icmp_type, int icmp_code, uint16_t id = 0, bool useId = false);

std::string generateStreamL3Key (const u_char  *ipPacket, u_int capLen, uint16_t l3Prototype, packetLayerHelper_t *);

namespace Errors {
// Define an enum within the namespace
enum PcapErrorType {
    NOERROR,
    BAD_FILEDESCRIPTOR_OPEN,
    BAD_FILE_OPEN,
    INVALID_PCAP_INPUT_OPTION,
    FAILURE

};

}

#endif
