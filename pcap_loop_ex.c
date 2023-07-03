#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define SIZE_ETHERNET 14  
#define INET_ADDR_BUFLEN 16 

#include "resources/pcap_structs.h"
#include "pcap_flow.c"

static struct flow_manager* flow_mgr;

void my_callback(u_char *useless,
		 const struct pcap_pkthdr* pkthdrn,
		 const u_char* packet) {
  static int count = 1;
  static char ipaddr_str[INET_ADDR_BUFLEN];
  static int printops = OVERWRITE_FLOWS
                        | PRINT_FLOW_IPS
                        | PRINT_FLOW_PROT
                        | PRINT_FLOW_COUNT
                        | PRINT_FLOW_BYTES;
  static const char* ptformat[] = {"|%-16s|", "|%-16s|", "|%-8s|", "|%-7s|", "|%-8s|"};
  static const char* pdformat[] = {"|%-16s|", "|%-16s|", "|%-8s|", "|%-7ld|", "|%-8.1e|"};
  
  /*
  const struct sniff_ip *ip;
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  inet_ntop(AF_INET, &(ip->ip_src), ipaddr_str, INET_ADDR_BUFLEN);
  */

  struct sniff_ip *ip;
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  struct flow_id id = packet_to_flow_id(ip);
  struct flow_node *node = lookup_create_alive(flow_mgr, id);
  update_flow_data(node, ip);
  print_flows(stdout, flow_mgr->alive_head, printops, ptformat, pdformat);

  count++;
}

int main() {
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *descr;
  const u_char *packet;
  struct pcap_pkthdr hdr;
  struct ether_header *eptr;
  struct bpf_program fp;
  bpf_u_int32 maskp;
  bpf_u_int32 netp;

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    exit(1);
  } else {
    printf("Opening %s in promiscuous mode\n", dev);
  }

  pcap_lookupnet(dev, &netp, &maskp, errbuf);

  descr = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
  if (descr == NULL) {
    printf("pcap_open_live(): %s\n", errbuf);
    exit(1);
  }

  if (pcap_compile(descr, &fp, "ip", 0, netp) == -1) {
    printf("Error compiling filter\n");
    exit(1);
  }

  if (pcap_setfilter(descr, &fp) == -1) {
    printf("Error applying filter\n");
    exit(1);
  }
 
 
  flow_mgr = new_flow_manager(10);
  pcap_loop(descr, -1, my_callback, NULL);
  
  return 0;
}
