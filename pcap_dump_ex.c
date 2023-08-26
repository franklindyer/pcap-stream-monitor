#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define INET_ADDR_BUFLEN 16

#include "pcap_flow.c"

static struct flow_manager* flow_mgr;
static FILE* live_log;
static FILE* dead_log;

static int printops = OVERWRITE_FLOWS
                      | PRINT_FLOW_IPS
                      | PRINT_FLOW_PROT
                      | PRINT_FLOW_COUNT
                      | PRINT_FLOW_DURATION;
static const char* ptformat[] = {"%-16s|", "%-16s|", "%-8s|", "%-7s|", "%-7s"};
static const char* pdformat[] = {"%-16s|", "%-16s|", "%-8s|", "%-7ld|", "%-7.1e"};

static int logops = PRINT_FLOW_IPS
                    | PRINT_FLOW_PROT
                    | PRINT_FLOW_PORTS
                    | PRINT_FLOW_COUNT
                    | PRINT_FLOW_BYTES
                    | PRINT_FLOW_DURATION;
static const char* ltformat[] = {"%s,", "%s,", "%s,", "%s,", "%s,", "%s,", "%s,", "%s"};
static const char* ldformat[] = {"%s,", "%s,", "%s,", "%d,", "%d,", "%ld,", "%ld,", "%f"};

void init_tracker(const char* live_logname, const char* dead_logname) {
  flow_mgr = new_flow_manager(1000000);
  if ((live_log = fopen(live_logname, "w+")) == NULL) {
    perror("Could not open file for listing active flows.");
    exit(1);
  }
  if ((dead_log = fopen(dead_logname, "w+")) == NULL) {
    perror("Could not open logfile for terminated flows.");
    exit(1);
  }
  printf("Initialized tracker...\n"); fflush(stdout);
}

void finalize_tracker(int sig) {
  print_flowcols(dead_log, logops, ltformat);
  print_flows(dead_log, flow_mgr->dead_head, logops, ldformat);
  print_flows(dead_log, flow_mgr->alive_head, logops, ldformat);
  if (fclose(live_log) < 0)
    perror("Could not close active flow file.");
  if (fclose(dead_log) < 0)
    perror("Could not close terminated flow logfile.");
  exit(0);
}

void pcap_callback(u_char *useless,
                   const struct pcap_pkthdr* pkthdrn,
                   const u_char* packet) {
  struct flow_id id = packet_to_flow_id(packet);
  struct flow_node *node = lookup_create_alive(flow_mgr, id);
  update_flow_data(node, packet);
  print_flowcols(live_log, printops, ptformat);
  print_flows(live_log, flow_mgr->alive_head, printops, pdformat); 
}

int main() {
  init_tracker("active_flows.txt", "inactive_flows.txt");
  signal(SIGINT, finalize_tracker);

  char *dev;
  pcap_if_t* devptr;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *descr;
  const u_char *packet;
  struct pcap_pkthdr hdr;
  struct ether_header *eptr;
  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp;

  // dev = pcap_lookupdev(errbuf);
  if (pcap_findalldevs(&devptr, errbuf) < 0 || devptr == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    exit(1);
  }
  dev = devptr->name;
  printf("Opening %s in promiscuous mode\n", dev);

  pcap_lookupnet(dev, &netp, &maskp, errbuf);

  descr = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
  if (descr == NULL) {
    printf("pcap_open_live(): %s\n", errbuf);
  }

  if (pcap_compile(descr, &fp, "ip", 0, netp) == -1) {
    printf("Error compiling filter\n");
    exit(1);
  }

  if (pcap_setfilter(descr, &fp) == -1) {
    printf("Error applying filter\n");
    exit(1);
  }

  pcap_loop(descr, -1, pcap_callback, NULL);

  return 0;

}
