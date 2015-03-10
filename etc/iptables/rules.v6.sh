#!/bin/sh

# An IPv6 firewall for non-forwarding hosts
#
# Copyright (c) 2015, Sven Reissmann <sven@0x80.io>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# Definitions
#
IP6TABLES='/sbin/ip6tables'

# Open the following ports globally (any source)
# (space separated list of port numbers)
#
GLOBAL_SERVICES_UDP=""
GLOBAL_SERVICES_TCP=""

# Open the following ports for specific peers
# (space separated list in the form: SourceIP/SourceMask!DstPort)
#
SPECIFIC_SERVICES_UDP=""
SPECIFIC_SERVICES_TCP=""




# Flush existing rules
#
$IP6TABLES -F
$IP6TABLES -X 
$IP6TABLES -t mangle -F
$IP6TABLES -t mangle -X

# Standard behavior - drop everything
#
$IP6TABLES -P INPUT   DROP
$IP6TABLES -P OUTPUT  DROP
$IP6TABLES -P FORWARD DROP

# Filter all packets that have deprecated RH0 headers
#
$IP6TABLES -A INPUT   -m rt --rt-type 0 -j DROP
$IP6TABLES -A OUTPUT  -m rt --rt-type 0 -j DROP
$IP6TABLES -A FORWARD -m rt --rt-type 0 -j DROP

# Filter packets using extension headers
#
$IP6TABLES -N BlockExtHeaders
$IP6TABLES -A BlockExtHeaders -m ipv6header --header dst   --soft -j DROP
$IP6TABLES -A BlockExtHeaders -m ipv6header --header hop   --soft -j DROP
$IP6TABLES -A BlockExtHeaders -m ipv6header --header route --soft -j DROP
$IP6TABLES -A BlockExtHeaders -m ipv6header --header frag  --soft -j DROP
$IP6TABLES -A BlockExtHeaders -m ipv6header --header auth  --soft -j DROP
$IP6TABLES -A BlockExtHeaders -m ipv6header --header esp   --soft -j DROP
$IP6TABLES -A BlockExtHeaders -m ipv6header --header none  --soft -j DROP
$IP6TABLES -A BlockExtHeaders -j RETURN

# Allow dedicated ICMPv6 types
#
$IP6TABLES -N AllowICMPv6IN
$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 1 -m state --state ESTABLISHED,RELATED -j ACCEPT		# Destination unreachable
$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 2 -j ACCEPT							# Packet too big
$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 3 -m state --state ESTABLISHED,RELATED -j ACCEPT		# Time exceeded
$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 4 -m state --state ESTABLISHED,RELATED -j ACCEPT		# Parameter problem
$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 128 -m limit --limit 2/sec --limit-burst 5 -j ACCEPT	# Echo Request (protect against flood)
$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 129 -m state --state ESTABLISHED,RELATED -j ACCEPT		# Echo Reply
#$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 135 -j ACCEPT						# Neighbor Solicitation
#$IP6TABLES -A AllowICMPv6IN -p icmpv6 --icmpv6-type 136 -j ACCEPT						# Neighbor Advertisement
$IP6TABLES -A AllowICMPv6IN -p icmpv6 -j DROP									# Drop anything else

# Security
#
$IP6TABLES -N other_packets 								# Table "other_packets"
$IP6TABLES -A other_packets -p ALL -m state --state INVALID -j DROP			# Drop invalid packets
$IP6TABLES -A other_packets -p ALL -d ff02::1 -j DROP					# Drop all-nodes multicast traffic
$IP6TABLES -A other_packets -p icmpv6 -m limit --limit 2/s --limit-burst 5 -j ACCEPT	# Limit ICMP rate (2/s + burst)
$IP6TABLES -A other_packets -p ALL -j RETURN

$IP6TABLES -N service_sec								# Table "services_sec"
$IP6TABLES -A service_sec -p tcp --syn -m limit --limit 5/s -j ACCEPT			# Protect against SYN_FLOOD
$IP6TABLES -A service_sec -p tcp ! --syn -m state --state NEW -j DROP			# Drop SYN packets that do not have state NEW
$IP6TABLES -A service_sec -p tcp --tcp-flags ALL NONE -m limit --limit 1/h -j ACCEPT	# Disallow portscans
$IP6TABLES -A service_sec -p tcp --tcp-flags ALL ALL -m limit --limit 1/h -j ACCEPT	# Disallow portscans
$IP6TABLES -A service_sec -p ALL -j RETURN


# Allowed services
#
$IP6TABLES -N services									# Table "services"
for port in $GLOBAL_SERVICES_TCP ; do							# For each globally allowed TCP port:
	$IP6TABLES -A services -p tcp --dport $port -j service_sec			#   Check service_sec table for limits
	$IP6TABLES -A services -p tcp --dport $port -j ACCEPT				#   Accept the connection
done
for next in $SPECIFIC_SERVICES_TCP ; do							# For each specificly allowed TCP port:
	IFS='!' read -a arr <<< "$next"							#   Get source IP and port
	$IP6TABLES -A services -p tcp -s ${arr[0]} --dport ${arr[1]} -j ACCEPT		#   Accept the connection
done
for port in $GLOBAL_SERVICES_UDP ; do							# For each globally allowed UDP-port:
	$IP6TABLES -A services -p udp --dport $port -j service_sec			#   Check service_sec table for limits
	$IP6TABLES -A services -p udp --dport $port -j ACCEPT				#   Accept the connection
done
for next in $SPECIFIC_SERVICES_UDP ; do 						# For each specificly allowed UDP port:
        IFS='!' read -a arr <<< "$next"							#   Get source IP and port
	$IP6TABLES -A services -p udp -s ${arr[0]} --dport ${arr[1]} -j ACCEPT		#   Accept the connection
done
$IP6TABLES -A services -p ALL -j RETURN  


# INPUT
#
$IP6TABLES -A INPUT -p ALL -i lo -j ACCEPT						# Allow packets from lo interface
$IP6TABLES -A INPUT -p ALL -j BlockExtHeaders						# Block packets with extension headers
$IP6TABLES -A INPUT -p ALL -j other_packets						# Check table "other_packets" (i.e., rate limiting)
$IP6TABLES -A INPUT -p icmpv6 -j AllowICMPv6IN						# Allow specific ICMPv6 types
$IP6TABLES -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT		# Allow existing connections back in
$IP6TABLES -A INPUT -p ALL -j services							# Allow specific services in
#$IP6TABLES -A INPUT -i $LAN_IF  -j ACCEPT 						# Allow the localnet access us
#$IP6TABLES -A INPUT -s fe80::/10 -j ACCEPT 						# Allow Link-Local addresses
#$IP6TABLES -A INPUT -d ff00::/8 -j ACCEPT 						# Allow multicast
$IP6TABLES -A INPUT -p ALL -j DROP							# Drop everything else

# OUTPUT
#
$IP6TABLES -A OUTPUT -p ALL -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT		# Allow any output

# Save rules
#
/etc/init.d/ip6tables save

