#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "hdr.h"
#include "parse.h"
void usage() {
    printf("syntax: signal-strength <interface> <mac>\n");
    printf("sample: signal-strength mon0 00:11:22:33:44:55\n");
}

int main(int argc, char* argv[]){

    if (argc < 3) {
            usage();
            return -1;
    }
    Parse(argv);
}
