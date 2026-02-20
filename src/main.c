#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "../include/capture.h"

static captureContext ctx;

int main() {
    printf("Starting......\n");

    const char *dev = "enp0s3";

    if (open_device(&ctx, dev) != 0) {
        printf("Failed to open device \n");
        return 1;
    }
    
    return 0;
}