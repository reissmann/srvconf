#!/bin/bash

# An IPv4 firewall for non-forwarding hosts
#
# Copyright (c) 2015 Sven Reissmann <sven@0x80.io>
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


# Read configuration
source /etc/iptables/config.v4



# Flush existing rules
#
$IPTABLES -F
$IPTABLES -X
$IPTABLES -t mangle -F
$IPTABLES -t mangle -X

# Standard behavior - drop everything
#
$IPTABLES -P INPUT   ACCEPT
$IPTABLES -P OUTPUT  ACCEPT
$IPTABLES -P FORWARD DROP

# Allow dedicated ICMP types
#
$IPTABLES -N AllowICMP
$IPTABLES -A AllowICMP -p icmp -m limit --limit 5/s --limit-burst 10 -j ACCEPT			# Limit ICMP rate (5/s + burst)
$IPTABLES -A AllowICMP -p icmp --icmp-type 0 -m state --state RELATED,ESTABLISHED -j ACCEPT	# Echo Reply
$IPTABLES -A AllowICMP -p icmp --icmp-type 8 -j ACCEPT						# Echo Request (protect against flood)
$IPTABLES -A AllowICMP -p icmp --icmp-type 3 -m state --state RELATED,ESTABLISHED -j ACCEPT	# Destination unreachable
$IPTABLES -A AllowICMP -p icmp --icmp-type 5 -m state --state RELATED,ESTABLISHED -j ACCEPT	# Redirect
$IPTABLES -A AllowICMP -p icmp --icmp-type 11 -m state --state RELATED,ESTABLISHED -j ACCEPT	# Time exceeded
$IPTABLES -A AllowICMP -p icmp --icmp-type 12 -m state --state RELATED,ESTABLISHED -j ACCEPT	# Parameter problem
$IPTABLES -A AllowICMP -p icmp --icmp-type 14 -m state --state RELATED,ESTABLISHED -j ACCEPT	# Timestamp Reply
$IPTABLES -A AllowICMP -p icmp -j DROP								# Drop anything else

# Filter "other" packets (i.e., multicast)
#
$IPTABLES -N DropOther									# Table DropOther
$IPTABLES -A DropOther -p ALL -m state --state INVALID -j DROP				# Ignore invalid packets
$IPTABLES -A DropOther -m pkttype --pkt-type broadcast -j DROP				# Ignore broadcasts
$IPTABLES -A DropOther -m pkttype --pkt-type multicast -j DROP				# Ignore multicast
$IPTABLES -A DropOther -p ALL -j RETURN

# Additional checks for open ports
#
$IPTABLES -N service_sec								# Table "services_sec"
$IPTABLES -A service_sec -p tcp --syn -m limit --limit 5/s -j ACCEPT			# Protect against SYN_FLOOD
$IPTABLES -A service_sec -p tcp ! --syn -m state --state NEW -j DROP			# Drop SYN packets that do not have state NEW
$IPTABLES -A service_sec -p tcp --tcp-flags ALL NONE -m limit --limit 1/h -j ACCEPT	# Disallow portscans
$IPTABLES -A service_sec -p tcp --tcp-flags ALL ALL -m limit --limit 1/h -j ACCEPT	# Disallow portscans
$IPTABLES -A service_sec -p ALL -j RETURN

# Trusted sources
#
$IPTABLES -N trusted
for src in $TRUSTED_SOURCES ; do							# For each trusted source
	$IPTABLES -A trusted -p ALL -s $src -j ACCEPT					#   Accept any connection
done
$IPTABLES -A trusted -p ALL -j RETURN

# Open ports
#
$IPTABLES -N services									# Table "services"
for port in $GLOBAL_SERVICES_TCP ; do							# For each allowed TCP-port:
       $IPTABLES -A services -p tcp --dport $port -j service_sec			#   Check service_sec table for limits
       $IPTABLES -A services -p tcp --dport $port -j ACCEPT				#   Accept the connection
done
for next in $SPECIFIC_SERVICES_TCP ; do							# For each specificly allowed TCP port:
        IFS='!' read -a arr <<< "$next"							#   Get source IP and port
        $IPTABLES -A services -p tcp -s ${arr[0]} --dport ${arr[1]} -j ACCEPT		#   Accept the connection
done 
for port in $GLOBAL_SERVICES_UDP ; do 							# For each allowed UDP-port:
       $IPTABLES -A services -p udp --dport $port -j service_sec			#   Check service_sec table for limits
       $IPTABLES -A services -p udp --dport $port -j ACCEPT				#   Accept the connection
done
for next in $SPECIFIC_SERVICES_UDP ; do							# For each specificly allowed UDP port:
        IFS='!' read -a arr <<< "$next"							#   Get source IP and port
        $IPTABLES -A services -p udp -s ${arr[0]} --dport ${arr[1]} -j ACCEPT		#   Accept the connection
done
$IPTABLES -A services -p ALL -j RETURN


# INPUT
#
$IPTABLES -A INPUT -p ALL -i lo -j ACCEPT						# Allow packets from lo interface
$IPTABLES -A INPUT -p ALL -j trusted							# Allow trusted sources
$IPTABLES -A INPUT -p ALL -j DropOther							# Check table DropOther
$IPTABLES -A INPUT -p icmp -j AllowICMP							# Allow specific ICMPv6 types
$IPTABLES -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT		# Allow existing connections back in
$IPTABLES -A INPUT -p ALL -j services							# Allow specific services in
$IPTABLES -A INPUT -p ALL -j DROP							# Drop everything else 

# OUTPUT
#
$IPTABLES -A OUTPUT -p ALL -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT		# Allow any output
$IPTABLES -A OUTPUT -p ALL -j DROP							# Drop everything else 


# Save rules
#
$SAVE_CMD

