/*
 *
 * Copyright (C) 2003 s0ttle (pacman@sawbox.net)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *****
 */
#include "../include/arpview.h"

void 
set_if_hwaddr( int sockfd, char* if_name, u_char_t* hwaddr )
{
    struct ifreq ifr;
    int n;

    strncpy( ifr.ifr_name, if_name, sizeof( ifr.ifr_name )-1 );

    if( ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0 )
      fatal("ioctl: hw address");

    for(n = 0; n < 6; n++)
      *( hwaddr++ ) = (u_char_t)ifr.ifr_hwaddr.sa_data[n];
}

int
parse_arppkt( u_char_t* pckt, int len )
{
    struct ethhdr* eth_hdr;
    struct arppkt* arp_hdr;
    int n;
    
    eth_hdr = (struct ethhdr*)pckt;
    arp_hdr = (struct arppkt*)(pckt + ETH_HLEN);
    
    if(arp_hdr->ar.ar_op != htons( ARPOP_REQUEST ))
      return( EXIT_FAILURE );
    
printf("---[arpview]--------------------------------------------]\n");

    printf("\n****  ETHERNET Header  ****\n\n"); 
    
    printf("  eth_dst: ");
    for(n = 0; n < 6; n++)
      printf("%02X",eth_hdr->h_dest[n]);
    
    printf("\n  eth_src: ");
    for(n = 0; n < 6; n++)
      printf("%02X", eth_hdr->h_source[n]);

    printf("\neth_proto: %04X\n", ntohs( eth_hdr->h_proto ));
    
    printf("\n**** ARP Header ****\n\n");
    
      printf("  arp_hrd: %04X\n"
             "arp_proto: %04X\n"
             "  arp_hln: %02X\n"
             "  arp_pln: %02X\n"
             "   arp_op: %04X\n",
             ntohs(arp_hdr->ar.ar_hrd), ntohs(arp_hdr->ar.ar_pro),
             arp_hdr->ar.ar_hln, arp_hdr->ar.ar_pln, 
             ntohs(arp_hdr->ar.ar_op));

    printf("  arp_sha: ");
    for(n=0; n < ETH_ALEN; n++)
      printf("%02X", arp_hdr->ar_sha[n]);
    
    printf("\n  arp_dha: ");
    for(n=0; n < ETH_ALEN; n++)
      printf("%02X", arp_hdr->ar_dha[n]);

    printf("\n  arp_sip: ");
    for(n=0; n < IPP_ALEN; n++)
      printf("%02X", arp_hdr->ar_sip[n]);

    printf(" (");
      
    for(n=0; n < IPP_ALEN; n++)
    {
      printf("%d", arp_hdr->ar_sip[n]);
      if(n < (IPP_ALEN)-1) 
        printf(".");
      else
        printf(")\n");
    }
    
    printf("  arp_dip: ");
    for(n=0; n < IPP_ALEN; n++)
      printf("%02X", arp_hdr->ar_dip[n]);

    printf(" (");
      
    for(n=0; n < IPP_ALEN; n++)
    {
      printf("%d", arp_hdr->ar_dip[n]);
      if(n < (IPP_ALEN)-1) 
        printf(".");
      else
        printf(")\n");
    }
    
    printf("\n****  Hex Dump  ****\n"); 
      
    for ( n = 0; n < len; n++ )
    {
      if ( !(n & 15) ) printf("\n%04X:  ", n);
        printf("%02X ", ((unsigned char*)pckt)[n]);
    }
    
printf("\n\nBytes: %d\n", len);
printf("----------------------------------------------------------\n");
printf("                              s0ttle - [pacman@sawbox.net]\n\n");

    return( EXIT_SUCCESS );
}

int
ether_snif( void )
{
#ifndef ETHER_MAX_LEN
#define ETHER_MAX_LEN 1514
#endif
    int len, sd, m, n;
    unsigned char buf[ETHER_MAX_LEN];
    char ifname[]="eth0"; /* hardcoded for now bleh */

    struct sockaddr_ll sll;
    struct packet_mreq mrr;

    len = sizeof( struct sockaddr_ll );

    sd = socket(PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ));
    if(sd < 0)
	  fatal("socket()");
	
	memset( &sll, 0, sizeof( sll ) );
	
    mrr.mr_ifindex = if_nametoindex( ifname );
    mrr.mr_alen = ETH_ALEN;
	mrr.mr_type =  PACKET_MR_PROMISC;

	set_if_hwaddr( sd, ifname, (u_char_t*)&mrr.mr_address );
	if((setsockopt(sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrr, sizeof( mrr ))) < 0)
	  fatal("setsockopt()");
	
    for(m = EXIT_FAILURE; m != EXIT_SUCCESS;)
    {        
	  memset(&sll, 0, sizeof( sll ));
      
      n = recvfrom(sd,buf,sizeof( buf ),
				   MSG_TRUNC,(struct sockaddr*)&sll,(void*)&len);
      if(n < 0)
	    fatal("recvfrom()");
      
      if( sll.sll_protocol == htons( ETH_P_ARP ) )        
        m = parse_arppkt(buf, n);
    }
    
    return( EXIT_SUCCESS );
}

int
main( void )
{

    return( ether_snif( ) );

}
