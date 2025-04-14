#include <vector>
#include <string>
#include <sstream>

// For in-memory storage: define a structure for a captured packet.
std::string generateStreamIpKey (const char  *ipPacket, int capLen, uint16_t l3Prototype);
std::string getUniqueStreamKey(const struct pcap_pkthdr *packet, int capLen);
std::string generateStreamTcpUdpKey(const std::string &ip1, uint16_t port1,
                                    const std::string &ip2, uint16_t port2);
std::string generateIcmpStreamKey(const std::string &ip1, const std::string &ip2,
                                  int icmp_type, int icmp_code, uint16_t id = 0, bool useId = false);
std::string l4KeyParsing(const char  *l4Hdr, uint16_t proto, const std::string &srcIp, const std::string &destIP, int capLen);

struct CapturedPacket {
    //PcapRecordHeader recordHeader;
    std::vector<uint8_t> data;
};



struct Options {
    int input;
    FILE *streamInput;

    std::string fileName;
    enum inputType {
        STREAMINPUT,
        INVALID,
        FILEINPUT,

    };

}

namespace Errors {
// Define an enum within the namespace
enum PcapErrorType {
    INVALID,
    BAD_FILEDESCRIPTOR_OPEN,
    BAD_FILE_OPEN,
    INVALID_PCAP_INPUT_OPTION,
    EXIT_FAILURE


};
}

