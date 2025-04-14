//standard library includes
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

//packet header includes
#include <arpa/inet.h>
#include <net/ethernet.h>     // For Ethernet header
#include <netinet/ip.h>       // For IPv4 header
#include <netinet/tcp.h>      // For TCP header
#include <netinet/udp.h>      // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header

//requires apt install libcap-dev
#include <pcap.h>

//self includes
#include "pcap-abbv.h"

using namespace Errors;

//print out options if unknown
void pcap_abbv_options() {}

int main(int argc, char *argv[])
{


//process options
struct Options option;

//file or real time
    FILE *pcapInputStream = nullptr;
    if (option.input == Options::STREAMINPUT) //default is input via stdin
    {
        //-1 == undefined
        //0 == stdin
        //1 == stdout
        //2 == stderr
        //3+ other file descriptor
        if (option.streamInput >= 0)
        {
            pcapInputStream = option.streamInput;
        }
        else
        {
            std::cerr << "Error: Unable to open input stream" << option.streamInput << std::endl;
            return Errors::BAD_FILEDESCRIPTOR_OPEN;
        }

    }
    else if (option.input == Options::FILEINPUT)    // Open the file for reading, get file descriptor
    {
        pcapInputStream = fopen(option.filename, "rb");
        if (!pcapInputStream)
        {
            std::cerr << "Error: Unable to open file " << option.filename << std::endl;
            return Errors::BAD_FILE_OPEN;
        }
    }
    else
    {
        return Errors::INVALID_PCAP_INPUT_OPTION;
    }


//capture packets and process
//open file descriptor (file or stdin)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapStream = pcap_fopen_offline(pcapInputStream, errbuf);
    if (!pcap)
    {
        std::cerr << "Error opening stream: " << errbuf << std::endl;
        if (input_stream != stdin)
        {
            fclose(input_stream);
        }
        return Errors::EXIT_FAILURE;
    }

//loop over all packets
    const u_char *packetData;
    struct pcap_pkthdr *pktHeader;
    int resultTimeout=0;
    while((resultTimeout = pcap_next_ex( pcapStream, &pktHeader, &packetData)) >= 0)
    {

        if(resultTimeout == 0)
            // Timeout elapsed
            continue;

        //temp place holder
        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }

    if(res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(pcapStream));
        return -1;
    }

//ideally, we should create a thread to handle key creation, and per stream/thread for packet processing (up to n threads)
//The create key, for a unique key, is large and gigantic when ipv6 is considered.
//Marking this as a TODO, but for now, single thread processing

//Create key for packet
//needs to be defined before, otherwise redeclaring will be an error
    std::string lookupStreamKey = getUniqueStreamKey(packetData, header->len);

//add to existing or create new


//Below is done in object
//triggers to save packets of interest
//we use 2 buffers, current stream of packets (to capture 'x' packets before and 'y' packets after a tagging event), and those fragments of interest.
    tagPacketOfInterest(pcapPacket);


//trigger to save pcap


//continue to save in memory, or write to disk as temporary


//combine pcap if saved to files as temporary


//close file descriptor
// Close the pcap file
    pcap_close(pcapInputStream);
    return 0;

}
