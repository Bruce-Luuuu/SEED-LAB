#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

#include "header.h"

/*************************************************************
  Given an IP packet, send it out using a raw socket.
**************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}


int main(){
	char buffer[1000];
	memset(buffer, 0, sizeof(buffer));
	struct ipheader * ip = (struct ipheader *)buffer;
	
	struct udpheader * udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
	char * data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
	const char * msg = "This is a spoofing UDP packet !";
	
	int data_len = strlen(msg);
	strncpy(data, msg, data_len);
	
	udp->udp_sport = htons(12345);
        udp->udp_dport = htons(9090);
        udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
	// ignore udp_sum 

	ip->iph_ver = 4;
	ip->iph_ihl = 5;
	ip->iph_ttl = 20;
	ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
	ip->iph_destip.s_addr = inet_addr("10.0.2.3");
	ip->iph_protocol = IPPROTO_UDP; // The value is 17.
	ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);

	
	send_raw_ip_packet(ip);
	return 0;
}
