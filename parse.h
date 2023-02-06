#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>

void Parse(char** argv);
int Check_Beacon(const u_char* data, uint16_t len);
int Capture_BeaconorData(const u_char* data, uint16_t len, char* mac);
uint16_t Capture_RadioTap(const u_char* data, int option);

enum options{
    RADIOTAP_LEN = 0,
    RADIOTAP_FIND_PRESENT_FLAG = 1,
    ENC = 4
};
