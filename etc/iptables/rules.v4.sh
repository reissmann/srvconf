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


# Definitions
#
IPTABLES='/sbin/iptables'
SAVE_CMD='/etc/init.d/iptables save'

# Open the following ports globally
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
$IPTABLES -F
$IPTABLES -X
$IPTABLES -t mangle -F
$IPTABLES -t mangle -X
#iptables -t nat -F
#iptables -t nat -X

# Standard behavior - drop everything
#
$IPTABLES -P INPUT   DROP
$IPTABLES -P OUTPUT  DROP
$IPTABLES -P FORWARD DROP

# Security
#
$IPTABLES -N other_packets								# Table "other_packets"
$IPTABLES -A other_packets -p ALL -m state --state INVALID -j DROP			# Drop invalid packets
$IPTABLES -A other_packets -p icmp -m limit --limit 5/s --limit-burst 10 -j ACCEPT	# Limit ICMP rate (2/s + burst)
$IPTABLES -A other_packets -p ALL -j RETURN

$IPTABLES -N service_sec								# Table "services_sec"
$IPTABLES -A service_sec -p tcp --syn -m limit --limit 5/s -j ACCEPT			# Protect against SYN_FLOOD
$IPTABLES -A service_sec -p tcp ! --syn -m state --state NEW -j DROP			# Drop SYN packets that do not have state NEW
$IPTABLES -A service_sec -p tcp --tcp-flags ALL NONE -m limit --limit 1/h -j ACCEPT	# Disallow portscans
$IPTABLES -A service_sec -p tcp --tcp-flags ALL ALL -m limit --limit 1/h -j ACCEPT	# Disallow portscans
$IPTABLES -A service_sec -p ALL -j RETURN


# Dienste
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
$IPTABLES -A INPUT -p ALL -j other_packets						# Check table "other_packets" (i.e., rate limiting)
$IPTABLES -A INPUT -p ALL -m state --state ESTABLISHED,RELATED -j ACCEPT		# Allow existing connections back in
$IPTABLES -A INPUT -p ALL -j services							# Allow specific services in
$IPTABLES -A INPUT -p ALL -j DROP							# Drop everything else 

# OUTPUT
#
$IPTABLES -A OUTPUT -p ALL -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT		# Allow any output


# Save rules
#
$SAVE_CMD

