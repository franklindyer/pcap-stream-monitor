#include "resources/ansi_codes.h"
#include "resources/protocols.h"
#include "resources/iglesias_features.h"

struct flow_id {
  struct timeval start;
  struct timeval recent;
  struct timeval count;

  struct in_addr ip_src;
  struct in_addr ip_dst;
  u_char ip_prot;
  u_short src_port;
  u_short dst_port;
};

struct flow_data {
  long count;
};

struct flow_node {
  features* to_track;
  struct flow_id id;
  struct flow_data data;
  struct flow_node* next;
};

/* At the moment, this function has no notion of
   cutting off flows at a certain time.          */
int compare_flows(struct flow_id fl1, struct flow_id fl2) {
  if (fl1.ip_src.s_addr != fl2.ip_src.s_addr) return 0;
  else if (fl1.ip_dst.s_addr != fl2.ip_dst.s_addr) return 0;
  else if (fl1.ip_prot ^ fl2.ip_prot) return 0;
  //  else if (fl1.src_port ^ fl2.src_port) return 0;
  //  else if (fl1.dst_port ^ fl2.dst_port) return 0;
  else return 1;
}

struct flow_node* flow_lookup(struct flow_node* flowlist, struct flow_id id) {
  if (flowlist == NULL) return NULL;
  else if (compare_flows(id, flowlist->id)) return flowlist;
  else return flow_lookup(flowlist->next, id);
}

struct flow_node* flow_insert(struct flow_node* flowlist, struct flow_id id) {
  struct flow_node* new_node = calloc(1, sizeof(struct flow_node));
  new_node->id = id;
  new_node->next = flowlist;
  new_node->data.count = 1;
  return new_node;
}

struct flow_node* flow_get(struct flow_node** flowlist, struct flow_id id) {
  struct flow_node* flow_loc = flow_lookup(*flowlist, id);
  if (flow_loc == NULL) {
    *flowlist = flow_insert(*flowlist, id);
    flow_loc = *flowlist;
  } else {
    flow_loc->data.count += 1;
  }
  return flow_loc;
}

void update_flow_data(struct flow_node* flownode, struct sniff_ip* ip) {
  return;
}

struct flow_id packet_to_flow_id(struct sniff_ip* ip_info) {
  struct flow_id id;
  id.ip_src = ip_info->ip_src;
  id.ip_dst = ip_info->ip_dst;
  id.ip_prot = ip_info->ip_p;
  return id;
}

#define OVERWRITE_FLOWS 1
#define PRINT_FLOW_SRCIP 2
#define PRINT_FLOW_DSTIP 4
#define PRINT_FLOW_IPS 6
#define PRINT_FLOW_PROT 8
#define PRINT_FLOW_SRCPORT 16
#define PRINT_FLOW_DSTPORT 32
#define PRINT_FLOW_PORTS 48
#define PRINT_FLOW_COUNT 64

void log_flows(FILE* fd, struct flow_node* flowlist, int options) {
  int num_flows = 0;
  char ipaddr_str[INET_ADDR_BUFLEN];

  if (fseek(fd, 0, SEEK_SET) < 0) perror("Could not move to beginning of logfile.");
  if (options & PRINT_FLOW_SRCIP) fprintf(fd, "%-16s  ", "Source IP");
  if (options & PRINT_FLOW_DSTIP) fprintf(fd, "%-16s  ", "Dest IP");
  if (options & PRINT_FLOW_PROT) fprintf(fd, "%-8s  ", "Protocol");
  if (options & PRINT_FLOW_COUNT) fprintf(fd, "%-7s  ", "# Pkts");
  fprintf(fd, "\n");

  while (flowlist != NULL) {
    num_flows++;
    if (options & PRINT_FLOW_SRCIP) {
      inet_ntop(AF_INET, &(flowlist->id.ip_src), ipaddr_str, INET_ADDR_BUFLEN);
      fprintf(fd, "%-16s  ", ipaddr_str);
    }

    if (options & PRINT_FLOW_DSTIP) {
      inet_ntop(AF_INET, &(flowlist->id.ip_dst), ipaddr_str, INET_ADDR_BUFLEN);
      fprintf(fd, "%-16s  ", ipaddr_str);
    }

    if (options & PRINT_FLOW_PROT) {
      fprintf(fd, "%-8s  ", getIPProtoName(flowlist->id.ip_prot));
    }

    if (options & PRINT_FLOW_COUNT) {
      fprintf(fd, "%-7ld  ", flowlist->data.count);
    }

    fprintf(fd, "\n");
    flowlist = flowlist->next;
  }

}

