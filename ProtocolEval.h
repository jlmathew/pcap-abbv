#include <string_view>

// example ((!A OR B AND C) AND !(D) OR (E OR F>7 OR H<0))
// -> ((!A) OR B) OR C)


//L0 global packet info
//Packet size_t
//date info

//L2_MAC
//L3_IPv4
//PKT_CNT
//L3_IPv6
//L3_ARP
//L3_RARP
//L3_ICMP
//L4_UDP
//L4_TCP
// SYN_CNT
// SYN_ONLY_CNT
// SYN_ACK_CNT
// RESET_CNT
// ACTUAL_WINDOW_SIZE_CNT
// EST_WINDOW_SIZE_CNT
// _THRESHOLD
// _windows_size
// pre/post stream count
//L5_TLS
//L5_DNS
//L7_HTTP
//L7_QUIC
//L7_NFS

//Get protocol  PER test
//Name
//SD - src to dest
//DS - dest to src
//FD - full duplex (both src<->dest streams)
//test name
//record and save format
//value (raw)
//value (bool)
//each layer has its own tests
//query name, get pointer


//query compile should use the values to determine thresholds

//threshold setting, then logic check
//setEnv<string_view>

/*
what if I want TCP RST/SYN/ACK/URGflags in either direction
OR window size < 100 bytes OR DNS packets

so, NOT, AND, OR and pointers to functions
ptr=queryTrack(objectName, function)

ptr=queryTrack(L4_TCP_SYN_ONLY_CNT)


RECORD which PacketStatistics_t
Save packet flag

Create Test Layer
Update Config  via input (capture)

*/


Class ProtocolEvalBase {
//if pktOfInterest is false, its 'save stream'
    virtual const bool * returnProtoEval(std::string_view strProtoEvalName, const bool pktOfInterest=true ) = 0;
    virtual void setProtocolValue(std::string_view strProtoName, uint32_t val) = 0;
    virtual void evaluateProtocol()=0;
//global values
    void setDefaulGlobalValue(std::string_view strGlobalName,uint32_t val);

};

//maximum packets per stream to save
//maximum time between packets
class PacketStreamEval : public ProtocolEvalBase {
   public:

   private:
   bool m_saveStream;
   uint64_t m_maxMemoryBufferSize; ///maximum to hold into memory
   std::string m_fileName;
   FILE *m_filePtr;
   uint32_t m_prePktTagCount;
   uint32_t m_postPktTagCount;


   uint64_t m_timeBetweenPktsInMs;  //how long between packets to save and consider closed


      void initFunctionMapping() {

    }


};


//Need to add code to check per src->dst, dst->src and dst<->src streams
//conditions to save packets in stream (save packets in case we save them all)
//conditions to save the stream (save all cached packets)
//condition to save the stream to file (eg post RST or FIN or timeout)
class TcpEval : public ProtocolEvalBase {
  public:
//const std::map<std::string, fn_ptr> m_fnMap = {{1,1},{4,2},{9,3},{16,4},{32,9}};

    const bool * returnProtoEval(std::string_view strProtoEvalName, const bool pktOfInterest);

  private:
    uint16_t m_srcPort;  //assume src and dst port are NOT equal, considered first port seen

    void initFunctionMapping() {

    }

    //Flags
    //Reset, prepare to close stream
    bool flagResetCountMin(uint32_t minCount);  //minimum # of RST seen before recorded
    bool flagResetCountMax(uint32_t maxCount);  //maximum # of RST to be recorded
    bool flagResetCount();
    bool flagResetSeen();
    void pktCountPreFlagReset(uint32_t preCount); //number of packets to save PRE RST
    void pktCountPostFlagRset (uint32_t postCount); //number of packets to save POST RST

    //SYN
    bool flagSynCountMin(uint32_t minCount);  //minimum # of RST seen before recorded
    bool flagSynCountMax(uint32_t maxCount);  //maximum # of RST to be recorded
    bool flagSynCount();
    bool flagSynSeen();
    void pktCountPreFlagSyn(uint32_t preCount); //number of packets to save PRE SYN
    void pktCountPostFlagSyn (uint32_t postCount); //number of packets to save POST SYN

    //SYN and ACK
    bool flagSynAckCountMin(uint32_t minCount);  //minimum # of RST seen before recorded
    bool flagSynAckCountMax(uint32_t maxCount);  //maximum # of RST to be recorded
    bool flagSynAckCount();
    bool flagSynAckSeen();
    void pktCountPreFlagSynAck(uint32_t preCount); //number of packets to save PRE SYN/ACK
    void pktCountPostFlagSynAck (uint32_t postCount); //number of packets to save POST SYN/ACK

    //FIN flags, prepare to close stream

    //ECP flags

    //keep-alive counts

    //Illegal flags (SYN with RST)

    //TCP window size




};



