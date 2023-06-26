# pcap-stream-monitor
A tool written using the `libpcap` C library to capture packets and monitor stream data. Windows is not supported yet.

Currently a work in progress, but the example script `pcap_loop_ex.c` can be compiled and run as follows. To compile, use
```gcc pcap_loop_ex.c -o pcap_loop_ex -lpcap```
To run and continuously monitor active streams, try the following:
```./pcap_loop_ex > dump.txt & ./monitor dump.txt```
This may need to be run using adminitrator privileges, as it involves opening a network interface in promiscuous mode and sniffing raw traffic. 

