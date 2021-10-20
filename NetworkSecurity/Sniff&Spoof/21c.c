#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "header.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
	printf("got a packet\n");
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("\tSrc: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("\tDst: %s\n", inet_ntoa(ip->iph_destip));    
	
	if(ip->iph_protocol == 6){
		struct tcpheader * tcp = (struct tcpheader *)
					(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
		
		printf("\tSrc Port: %d\n", ntohs(tcp->tcp_sport));   
		printf("\tDst Port: %d\n", ntohs(tcp->tcp_dport));    
		
		char * data = (u_char *)packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader);
		int data_size = ntohs(ip->iph_len) - sizeof(struct ipheader) - sizeof(struct tcpheader);
		if(data_size > 0){
			printf("\tPayload %d bytes:", data_size);
			int i;
			for(i=0;i<data_size;i++){
				if(isprint(*(data+i))) printf("%c",*(data+i));
				else printf("*");	
			}
			printf("\n");	
		}		
		
	}
  }
	
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp and port telnet";
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



