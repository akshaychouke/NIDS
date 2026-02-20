#include <pcap.h>

typedef struct {
    pcap_t *handle;
    char *device;
    int promisc;
    int timout_ms;
    int packet_cnt;
} captureContext;

int open_device(captureContext *ctx, const char *dev);

int capture_start(captureContext *ctx, int pkt_cnt);
