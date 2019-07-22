#include <pcap.h>
#include <stdio.h>
#include<stdint.h>
#include <arpa/inet.h>


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_MAC(uint8_t *MAC) { //배열의 첫 시작 주소를 줘야함!
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}

uint8_t find_etherType(uint8_t *Type){
    uint8_t type = *Type;
    printf("%04x\n\n",ntohs(type));
    return type;
}

void print_IP(uint8_t *IP) {
    printf("%u.%u.%u.%u\n", IP[0], IP[1], IP[2], IP[3]);
}

void find_protocolID(uint8_t *ID){
    uint8_t protocolID = ID[0];
    printf("%02x\n\n",protocolID);
}

uint8_t searchIPTotalLen(uint8_t *len){
    uint8_t ipTotalLen =  len[0] << 8 | len[1];
    return ipTotalLen;
}

void print_PORT(uint8_t *PORT) {
    uint8_t port = PORT[0] << 8 | PORT[1];
    printf("%u\n", port);
}



struct Ether{
    int srcMAC = 0;
    int destMAC = 6;
    int etherType = 12;
}Ether;

struct IPv4{
    int ipTotalLen = 16;
    int protocolIP = 23;
    int srcIP = 26;
    int destIP = 30;
}IPv4;

struct TCP{
    int srcPort = 34;
    int destPort = 36;
    int data = 56;
}TCP;



int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("\n------------\n");
    printf("%u bytes captured\n", header->caplen);

    printf("source MAC = ");
    print_MAC((uint8_t*)&packet[Ether.srcMAC]);
    printf("destination MAC = ");
    print_MAC((uint8_t*)&packet[Ether.destMAC]);
    printf("Ether Type = ");
    find_etherType((uint8_t*)&packet[Ether.etherType]);

    printf("source IP = ");
    print_IP((uint8_t*)&packet[IPv4.srcIP]);
    printf("destination IP = ");
    print_IP((uint8_t*)&packet[IPv4.destIP]);
    printf("protocol ID = ");
    find_protocolID((uint8_t*)&packet[IPv4.protocolIP]);

    printf("source PORT = ");
    print_PORT((uint8_t*)&packet[TCP.srcPort]);
    printf("destination PORT = ");
    print_PORT((uint8_t*)&packet[TCP.destPort]);

    printf("\nData = ");
    for(int i=TCP.data;i<64;i++){
    printf("%x",&packet[i]);
    }
            }
  pcap_close(handle);
  return 0;
        }
