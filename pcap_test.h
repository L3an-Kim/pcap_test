#ifndef PCAP_TEST_H
#define PCAP_TEST_H


struct Ether{
    char srcMAC[7];
    char destMAC[7];
    char etherType[3];
};

struct IPv4{
    char protocolIP;
    char srcIP[4];
    char destIP[4];
};

struct TCP{
    char srcPort[2];
    char destPort[2];
};
#endif // PCAP_TEST_H
