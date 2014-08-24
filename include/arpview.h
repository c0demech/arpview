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
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define fatal(n) { perror(n); exit( EXIT_FAILURE ); }

typedef unsigned char u_char_t;

struct arppkt
{
#define IPP_ALEN 0x4
#define ARP_PLEN 0x4    
    struct arphdr ar;
    /* variable length bullcrap not in
     * if_arp.h struct =( so solution here */
    u_char_t ar_sha[ETH_ALEN];
    u_char_t ar_sip[IPP_ALEN]; 
    u_char_t ar_dha[ETH_ALEN];
    u_char_t ar_dip[IPP_ALEN];
};

int ether_snif( void );
int parse_arppkt( u_char_t*, int );
void set_if_hwaddr( int, char*, u_char_t* );
