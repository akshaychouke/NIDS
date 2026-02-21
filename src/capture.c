#include "../include/capture.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int open_device(captureContext *ctx, const char *device) {
    if(ctx == NULL) {
        return -1;
    }

    memset(ctx, 0, sizeof(captureContext));
    char errbuf[PCAP_ERRBUF_SIZE];
    
    const char *dev = device;
    
    if (dev == NULL || strlen(dev) == 0) {
        printf("No network interface \n");
        return -1;
    }

    ctx->device = strdup(dev);
    ctx->promisc = 1;
    ctx->timout_ms = 1000;

    ctx->handle = pcap_open_live(dev, BUFSIZ, ctx->promisc, ctx->timout_ms, errbuf);

    if(ctx->handle == NULL) {
        printf("Failed to open network interface : %s \n", errbuf);
        free(ctx->device);
        return -1;
    }

    printf("Succefully opned device : %s \n", dev);
    return 0;
}

void captureHandler(u_char *args, const struct pcap_pkthdr, const u_char *packet) {
    printf("Inside the packete capture handler \n");
}

int capture_start(captureContext *ctx, int pkt_cnt) {

    if(ctx == NULL) {
        return -1;
    }

    printf("Starting to capture packets....\n");

    pcap_loop(ctx->handle, pkt_cnt, captureHandler, NULL);


    return 0;

}