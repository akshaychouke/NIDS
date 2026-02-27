#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "../include/capture.h"
#define MAXPKT -1 //for infinity

static captureContext ctx;

int main() {
    printf("Starting......\n");

    const char *dev = "enp0s3";

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