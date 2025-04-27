//self includes
#include "pcap-abbv.h"

//using namespace Errors;

//print out options if unknown
void pcap_abbv_options() {}

//test function
void print_dlt(int dlt) {
    switch (dlt) {
        case DLT_EN10MB:
            std::cout << "Layer 2 Type: Ethernet (802.3)" << std::endl;
            break;
        case DLT_IEEE802_11:
            std::cout << "Layer 2 Type: Wi-Fi (802.11)" << std::endl;
            break;
        case DLT_LINUX_SLL:
            std::cout << "Layer 2 Type: Linux Cooked Capture" << std::endl;
            break;
        case DLT_RAW:
            std::cout << "Layer 2 Type: Raw IP packets" << std::endl;
            break;
        default:
            std::cout << "Unknown Layer 2 Type (DLT: " << dlt << ")" << std::endl;
    }
}

int main(int argc, char *argv[]) {


//process options
    struct Options_t option;

    //test, delete when done
    option.input = Options_t::FILEINPUT;
    option.fileName = "../pcap-samples/tcp-ecn-sample.pcap";

//file or real time

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapInputStream = nullptr;
    int layer2Proto=0;


    if (Options_t::STREAMINPUT == option.input) { //default is input via stdin


        pcapInputStream = pcap_fopen_offline(stdin, errbuf);


        if (nullptr == pcapInputStream) {
            std::cerr << "Error: Unable to open input stream" << errbuf << std::endl;
            return Errors::BAD_FILEDESCRIPTOR_OPEN;
        }
        layer2Proto = pcap_datalink(pcapInputStream);

    } else if (Options_t::FILEINPUT == option.input) { // Open the file for reading, get file descriptor
        pcapInputStream = pcap_open_offline(option.fileName.c_str(), errbuf);
        if (nullptr == pcapInputStream) {
            std::cerr << "Error: Unable to open file " << option.fileName << std::endl;
            return Errors::BAD_FILE_OPEN;
        }
        layer2Proto = pcap_datalink(pcapInputStream);
    } else {
        return Errors::INVALID_PCAP_INPUT_OPTION;
    }



//loop over all packets
    const u_char *packetData;
    struct pcap_pkthdr *pktHeader;
    int resultTimeout=0;


    while((resultTimeout = pcap_next_ex( pcapInputStream, &pktHeader, &packetData)) >= 0) {
        if(resultTimeout == 0)
            // Timeout elapsed
            continue;


        //Create key for packet
//needs to be defined before, otherwise redeclaring will be an error
//Create key for packet
//needs to be defined before, otherwise redeclaring will be an error
//also, since we need to recurse through layers, save values for easier parsing later

        packetLayerHelper_t *packetLayerHelper=new packetLayerHelper_t;
        packetLayerHelper->layer2Proto=layer2Proto;
        std::string lookupStreamKey = getUniqueStreamKey(packetData, pktHeader->len, packetLayerHelper);
        std::cout << "Packet stream key:" << lookupStreamKey << std::endl;
        //debug print
print_dlt(layer2Proto); std::cout << "L3:" << packetLayerHelper->layer3Proto << ", L4:" << packetLayerHelper->layer4Proto << std::endl;


//add to existing or create new

        //add to existing or create new

//Below is done in object
//triggers to save packets of interest
//we use 2 buffers, current stream of packets (to capture 'x' packets before and 'y' packets after a tagging event), and those fragments of interest.
//    tagPacketOfInterest(pcapPacket);

//        tagPacketOfInterest(packetData);







//ideally, we should create a thread to handle key creation, and per stream/thread for packet processing (up to n threads)
//The create key, for a unique key, is large and gigantic when ipv6 is considered.
//Marking this as a TODO, but for now, single thread processing




    //add to existing or create new

//Below is done in object
//triggers to save packets of interest
//we use 2 buffers, current stream of packets (to capture 'x' packets before and 'y' packets after a tagging event), and those fragments of interest.

//        tagPacketOfInterest(packetData);


//trigger to save pcap


//continue to save in memory, or write to disk as temporary





//combine pcap if saved to files as temporary
    }

//close file descriptor
// Close the pcap file
    pcap_close(pcapInputStream);
    return 0;
}
