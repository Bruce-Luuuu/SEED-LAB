#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "header.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
	printf("got a packet!\n");
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("\tSrc: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("\tDst: %s\n", inet_ntoa(ip->iph_destip));    
	

  }
	
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp and ((dst host 10.0.2.2 && src host 10.0.2.3) or (src host 10.0.2.2 && dst host 10.0.2.3))";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

