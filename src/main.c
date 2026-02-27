#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include "../include/capture.h"
#include "../include/printUtils.h"
#include <unistd.h>

#define MAXPKT -1 //for infinity

static void print_usage(const char *prog) {
    printf("Usage: %s [-v] [-d device]\n", prog);
    printf("  -v       verbose output (multi-line)\n");
    printf("  -d DEV   capture device (default enp0s3)\n");
}

static captureContext ctx;

int main(int argc, char *argv[]) {
    int opt;
    const char *dev = "enp0s3";
    int verbose = 0;

    while ((opt = getopt(argc, argv, "vd:h")) != -1) {
        switch(opt) {
            case 'v':
                verbose = 1;
                break;
            case 'd':
                dev = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    printf("Starting......\n");
    setPrintVerbose(verbose);

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