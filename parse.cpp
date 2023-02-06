#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <curses.h>
#include <unistd.h>
#include <string.h>
#include "hdr.h"
#include "parse.h"

void PrintMAC(uint8_t *mac){
    printw("|======|===================|\n");
    printw("|  TA  | %02x:%02x:%02x:%02x:%02x:%02x |\n",mac[0], mac[1],mac[2],mac[3],mac[4],mac[5]);
    printw("|------|-------------------|\n");
}
void MACtoString(char* mac, char*arg){
    sscanf(arg,"%x:%x:%x:%x:%x:%x",
            &mac[0],
            &mac[1],
            &mac[2],
            &mac[3],
            &mac[4],
            &mac[5]);
}
void Parse(char** argv){

    initscr();
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    char* mac = (char*)malloc(sizeof(char)*6);
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
       fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
       exit(-1);
    }
    struct pcap_pkthdr* header;
    const u_char* data;
    while(1){
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n",res, pcap_geterr(handle));
        }
        uint16_t RaidoTap_Len = Capture_RadioTap(data,RADIOTAP_LEN);
        int check = Check_Beacon(data,RaidoTap_Len);
        if(check == 0)
            continue;
        else{
            MACtoString(mac,argv[2]);
            Signal*signal = (Signal*)(data+22);
            if(Capture_BeaconorData(data,RaidoTap_Len,mac)){
                move(0,0);
                PrintMAC((uint8_t*)mac);
                printw("|SIGNAL|   %7d         |\n",signal->strength);
                printw("|======|===================|\n");
            }
        }
        usleep(10000);
        refresh();
    }
    free(mac);
}

uint16_t Capture_RadioTap(const u_char* data, int option){
    RadioTap* capture = (RadioTap*)data;
    if (option == 0)
        return capture->len;
}

int Check_Beacon(const u_char* data, uint16_t len){
    Beacon* beacon = (Beacon*)(data+len);
    if (beacon->type == 0x80){
        return 1;
    }
    else
        return 0;
}
int Capture_BeaconorData(const u_char* data, uint16_t len, char* mac){
        Beacon* beacon = (Beacon*)(data+len);
        if(!(memcmp(mac,beacon->src_mac,sizeof(char)*6)))
            return 1;
        else
            return 0;

}
