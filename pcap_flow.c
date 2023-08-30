#include <time.h>
#include <unistd.h>
#include "resources/ansi_codes.h"
#include "resources/protocols.h"
#include "resources/features.h"
#include "resources/flow_time.h"
#include "resources/pcap_structs.h"

struct flow_id {
  struct timespec start;
  struct timespec recent;

  struct in_addr ip_src;
  struct in_addr ip_dst;
  u_char ip_prot;
  u_short src_port;
  u_short dst_port;
};

#define FLOWBOOL_ISFINISHED 1 << 0

struct flow_data {
  short booldat;
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
  float cutoff;                         /* Cutoff point in milliseconds */
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

int compare_flows(struct flow_id fl1, struct flow_id fl2) {
  if (fl1.ip_src.s_addr != fl2.ip_src.s_addr) return 0;
  else if (fl1.ip_dst.s_addr != fl2.ip_dst.s_addr) return 0;
  else if (fl1.ip_prot ^ fl2.ip_prot) return 0;
  else if (fl1.src_port ^ fl2.src_port) return 0;
  else if (fl1.dst_port ^ fl2.dst_port) return 0;
  else return 1;
}

struct flow_node* lookup_alive(struct flow_manager* mgr, struct flow_id fl) {
  struct flow_node* prev = NULL;
  struct flow_node* current = mgr->alive_head;
  while (current != NULL) {
    if (compare_flows(fl, current->id)) {
      if (timespec_diff(timespec_now(), current->id.recent) > mgr->cutoff) {
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

void update_flow_data(struct flow_node* flownode, const u_char* pkt) {
  const struct sniff_ip* ip = cast_packet_ip(pkt);

  timespec_get(&(flownode->id.recent), TIME_UTC);

  features* track = flownode->to_track;
  if (*track & FEAT_COUNT) flownode->data.count += 1;
  if (*track & FEAT_BYTES) flownode->data.bytes += ip->ip_len;
  return;
}

struct flow_id packet_to_flow_id(const u_char* packet) {
  const struct sniff_ip *ip_info = cast_packet_ip(packet);

  struct flow_id id;
  id.ip_src = ip_info->ip_src;
  id.ip_dst = ip_info->ip_dst;
  id.ip_prot = ip_info->ip_p;

  id.src_port = 0;
  id.dst_port = 0;
  if (id.ip_prot == TCP_PROTNUM) {
    const struct sniff_tcp* tcp_info = cast_packet_tcp(packet);
    id.src_port = ntohs(tcp_info->th_sport);
    id.dst_port = ntohs(tcp_info->th_dport);
  } else if (id.ip_prot == UDP_PROTNUM) {
    const struct sniff_udp* udp_info = cast_packet_udp(packet);
    id.src_port = ntohs(udp_info->uh_sport);
    id.dst_port = ntohs(udp_info->uh_dport);
  }

  timespec_get(&(id.start), TIME_UTC);
  timespec_get(&(id.recent), TIME_UTC);
  return id;
}

#define PRINT_FLOW_SRCIP        1 << 0
#define PRINT_FLOW_DSTIP        1 << 1
#define PRINT_FLOW_IPS          ((1 << 0) ^ (1 << 1))
#define PRINT_FLOW_PROT         1 << 2
#define PRINT_FLOW_SRCPORT      1 << 3
#define PRINT_FLOW_DSTPORT      1 << 4
#define PRINT_FLOW_PORTS        ((1 << 3) ^ (1 << 4))
#define PRINT_FLOW_COUNT        1 << 5
#define PRINT_FLOW_BYTES        1 << 6
#define PRINT_FLOW_START        1 << 7
#define PRINT_FLOW_END          1 << 8
#define PRINT_FLOW_DURATION     1 << 9
#define PRINT_FLOWBOOL_SHIFT    10

#define OVERWRITE_FLOWS         1 << 31

const char* optnames[] = {
  "srcip",
  "dstip",
  "prot",
  "srcport",
  "dstport",
  "count",
  "bytes",
  "start",
  "end",
  "dur",
  "isdone"
};

void print_flowcols(FILE* fd,
                    long options,
                    const char* tformat[]) {
  int col = 0;
  int i = 0;
  
  if (fseek(fd, 0, SEEK_SET) < 0) perror("Could not move to beginning of logfile.");

  for (i = 0; i < 31; i++) {
    if (options & (1 << i)) {
      fprintf(fd, tformat[col], optnames[i]);
      col++;
    }
  }
  fprintf(fd, "\n");
}

void print_flows(FILE* fd, 
                 struct flow_node* flowlist, 
                 long options, 
                 const char* dformat[]) {
  int num_flows = 0;
  int col = 0;
  char ipaddr_str[INET_ADDR_BUFLEN];
  
  if (options & OVERWRITE_FLOWS) {
    if (fseek(fd, 0, SEEK_SET) < 0) perror("Could not move to beginning of logfile.");
  }  

  while (flowlist != NULL) {
    col = 0;
    num_flows++;
    if (options & PRINT_FLOW_SRCIP) {
      inet_ntop(AF_INET, &(flowlist->id.ip_src), ipaddr_str, INET_ADDR_BUFLEN);
      fprintf(fd, dformat[col], ipaddr_str);
      col++;
    }

    if (options & PRINT_FLOW_DSTIP) {
      inet_ntop(AF_INET, &(flowlist->id.ip_dst), ipaddr_str, INET_ADDR_BUFLEN);
      fprintf(fd, dformat[col], ipaddr_str);
      col++;
    }

    if (options & PRINT_FLOW_PROT) {
      fprintf(fd, dformat[col], getIPProtoName(flowlist->id.ip_prot));
      col++;
    }

    if (options & PRINT_FLOW_SRCPORT) {
      fprintf(fd, dformat[col], (int)(flowlist->id.src_port));
      col++;
    }

    if (options & PRINT_FLOW_DSTPORT) {
      fprintf(fd, dformat[col], (int)(flowlist->id.dst_port));
      col++;
    }

    if (options & PRINT_FLOW_COUNT) {
      fprintf(fd, dformat[col], flowlist->data.count);
      col++;
    }

    if (options & PRINT_FLOW_BYTES) {
      fprintf(fd, dformat[col], (double)flowlist->data.bytes);
      col++;
    }

    if (options & PRINT_FLOW_DURATION) {
      fprintf(fd, dformat[col], timespec_diff(flowlist->id.recent, flowlist->id.start));
      col++;
    }

    int i;
    int shift;
    for (i = 0; i < 16; i++) {
      shift = i + PRINT_FLOWBOOL_SHIFT;
      if (options & (1 << shift)) {
        fprintf(fd, dformat[col], (flowlist->data.booldat >> shift) & 1);
        col++;
      }
    }

    fprintf(fd, "\n");
    flowlist = flowlist->next;
  }

}

void flush_deadflows(FILE* fd, 
                     struct flow_manager* mgr, 
                     long options, 
                     const char* dformat[]) {
    struct flow_node* deadhead = mgr->dead_head;
    mgr->dead_head = NULL;
    if (fork() == 0) {
        print_flows(fd, deadhead, options, dformat);
    }
}
