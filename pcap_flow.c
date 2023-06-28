#include <time.h>
#include "resources/ansi_codes.h"
#include "resources/protocols.h"
#include "resources/features.h"

struct flow_id {
  time_t start;
  time_t recent;

  struct in_addr ip_src;
  struct in_addr ip_dst;
  u_char ip_prot;
  u_short src_port;
  u_short dst_port;
};

struct flow_data {
  long count;
  long bytes;
};

struct flow_node {
  features* to_track;
  struct flow_id id;
  struct flow_data data;
  struct flow_node* next;
};

struct flow_manager {
  double cutoff;
  struct flow_node* alive_head;
  struct flow_node* dead_head;
};

struct flow_manager* new_flow_manager(double cutoff) {
  struct flow_manager* mgr = calloc(1, sizeof(struct flow_manager));
  mgr->cutoff = cutoff;
  mgr->alive_head = NULL;
  mgr->dead_head = NULL;
  return mgr;
}

void mark_stream_dead(struct flow_manager* mgr,
                                     struct flow_node* prevnode, 
                                     struct flow_node* node) {
  if (mgr->alive_head == node) mgr->alive_head = node->next;
  else prevnode->next = node->next;
  node->next = mgr->dead_head;
  mgr->dead_head = node;
}

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

struct flow_node* lookup_alive(struct flow_manager* mgr, struct flow_id fl) {
  struct flow_node* prev = NULL;
  struct flow_node* current = mgr->alive_head;
  while (current != NULL) {
    if (compare_flows(fl, current->id)) {
      if (difftime(time(NULL), current->id.recent) > mgr->cutoff) {
        mark_stream_dead(mgr, prev, current);
        return NULL;
      }
      return current;
    }
    prev = current;
    current = current->next;
  }
  return NULL;
}

void init_flow_data(struct flow_node* flownode) {
  flownode->data.count = 0;
  flownode->data.bytes = 0;
}

void add_new_flow(struct flow_manager* mgr, struct flow_id id) {
  struct flow_node* node = calloc(1, sizeof(struct flow_node));
  node->id = id;
  node->to_track = &completeFeatureSet;
  init_flow_data(node);

  node->next = mgr->alive_head;
  mgr->alive_head = node;
}

struct flow_node* lookup_create_alive(struct flow_manager* mgr,
                                      struct flow_id id) {
  struct flow_node* result = lookup_alive(mgr, id);
  if (result == NULL) {
    add_new_flow(mgr, id);
    result = mgr->alive_head;
  }
  return result;
}

void update_flow_data(struct flow_node* flownode, struct sniff_ip* ip) {
  features* track = flownode->to_track;

  if (*track & FEAT_COUNT) flownode->data.count += 1;
  if (*track & FEAT_BYTES) flownode->data.bytes += ip->ip_len;
  return;
}

struct flow_id packet_to_flow_id(struct sniff_ip* ip_info) {
  struct flow_id id;
  id.ip_src = ip_info->ip_src;
  id.ip_dst = ip_info->ip_dst;
  id.ip_prot = ip_info->ip_p;
  id.start = time(NULL);
  id.recent = id.start;
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
#define PRINT_FLOW_BYTES 128

void log_flows(FILE* fd, struct flow_node* flowlist, int options) {
  int num_flows = 0;
  char ipaddr_str[INET_ADDR_BUFLEN];

  if (fseek(fd, 0, SEEK_SET) < 0) perror("Could not move to beginning of logfile.");
  if (options & PRINT_FLOW_SRCIP) fprintf(fd, "%-16s  ", "Source IP");
  if (options & PRINT_FLOW_DSTIP) fprintf(fd, "%-16s  ", "Dest IP");
  if (options & PRINT_FLOW_PROT) fprintf(fd, "%-8s  ", "Protocol");
  if (options & PRINT_FLOW_COUNT) fprintf(fd, "%-7s  ", "# Pkts");
  if (options & PRINT_FLOW_BYTES) fprintf(fd, "%-5s  ", "Bytes");
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

    if (options & PRINT_FLOW_BYTES) {
      fprintf(fd, "%.1e  ", (double)flowlist->data.bytes);
    }

    fprintf(fd, "\n");
    flowlist = flowlist->next;
  }

}

