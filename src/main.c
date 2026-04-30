#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "../include/capture.h"
#define MAXPKT -1 //for infinity

static captureContext ctx;

int main(int argc, char *argv[]) {
    printf("Starting......\n");

    if (argc != 2) {
        printf("Please provide interface name as an argument \n");
        return 1;
    }

    const char *dev = argv[1];

    if (open_device(&ctx, dev) != 0) {
        printf("Failed to open device \n");
        return 1;
    }

    if (capture_start(&ctx, MAXPKT) != 0) {
        printf("Failed to start capturing the packets \n");
        return 1;
    }
    
    return 0;
}