#!/bin/bash
###################
### BEGIN INIT INFO
###################
# Provides:          skeleton
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      N/A
# Short-Description: iptables 
# Description:
#
### END INIT INFO
#
# Author:	Iztok Starc <iztok.starc@fri.uni-lj.si>,
#
# Date:		17. 10. 2011
# Version:	v1.0
#

#############################
### USER CONFIGURABLE SECTION
#############################

# Exit immediately if a command exits with a non-zero status.
set -e

# Print commands and their arguments as they are executed
set -x

DESC="netfilter/iptables firewall on $HOSTNAME"
INET_IFACE="enp0s3" # Internet-connected interface
IPADDR=`ip addr show $INET_IFACE | grep "inet " | cut -d " " -f6 | cut -d "/" -f1`

# DNS server
NAMESERVER=`nmcli dev show $INET_IFACE | grep IP4.DNS | cut -d ":" -f2 | tail --lines=1 | tr -d '[[:space:]]'`


#################################
### END USER CONFIGURABLE SECTION
#################################

#
#	Function that starts the daemon/service.
#
d_start() {

### No forwarding
#echo 0 > /proc/sys/net/ipv4/ip_forward
### Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable broadcast echo Protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 

# Enable TCP SYN Cookie Protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance 
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
    echo 0 > $f
done
# Don't send Redirect Messages 
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
    echo 0 > $f
done

##################
### Default policy
##################

# Disable INPUT before changing iptables
iptables --policy INPUT DROP
# Disable OUTPUT before changing iptables
iptables --policy OUTPUT DROP
# Disable FORWARD before changing iptables
iptables --policy FORWARD DROP


###################
### Clear old rules
###################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush
# Delete any user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
# Reset all counters to zero
iptables -Z

#########################################
### netfilter/iptables rules
#########################################

# Resources

# netfilter/iptables
#  http://book.chinaunix.net/special/ebook/Linux_Firewalls3e
#  http://iptables-tutorial.frozentux.net/iptables-tutorial.html
#  http://www.yolinux.com/TUTORIALS/LinuxTutorialIptablesNetworkGateway.html

# BASH:
#  http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html
#  http://tldp.org/LDP/abs/html/

### Allow all trafic on localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

### Stateful firewall assignments

# (1) ESTABLISH-RELATED trick: Allow all incoming packets that belong to ESTABLISHED or RELATED connections.
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# From here onwards, we can add incoming firewall exceptions using only the NEW state

# (2) Allow all outgoing packets that belong to ESTABLISHED or RELATED connections.
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# (3) Allow outgoing DNS requests to the DNS server in variable NAMESERVER
iptables -A OUTPUT -p udp -d $NAMESERVER --dport 53 -m state --state NEW -j ACCEPT

# (4) Allow outgoing SSH connections to remote SSH servers
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# (5) Allow incoming connections to local SSH server
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# (6) Allow outgoing HTTP requests
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# (7) Allow incoming HTTP requests destined to local HTTP server
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# (8) Allow outgoing HTTPS requests
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# (9) Allow incoming HTTPS requests destined to local HTTP server
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# (10) Allow outgoing ping requests
iptables -A OUTPUT -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT

# (11) Allow incoming ping requests
iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT

# (12) Compress rules 4-9 into two iptables commands using "-m multiport" and "--ports" switches.
iptables -A OUTPUT -p tcp -m multiport --dports 22,80,443 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 22,80,443 -m state --state NEW -j ACCEPT

### FORWARDING RULES

# Do NAT for internet-bound traffic
iptables -t nat -A POSTROUTING -o $INET_IFACE -j MASQUERADE

# (13) Allow routing of packets that belong to ESTABLISHED or RELATED connections.
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# (14) Forward pings
iptables -A FORWARD -p icmp --icmp-type echo-request -m state --state NEW  -j ACCEPT

# (15) Forward DNS requests from subnets to Internet and permit in corresponding responses
iptables -A FORWARD -o $INET_IFACE -p udp -m multiport --ports 53 -m state --state NEW -j ACCEPT

# (16) Forward HTTP, HTTPS and SSH traffic from client_subnet to Internet and to server_subnet
iptables -A FORWARD -p tcp -m multiport --dports 22,80,443 -m state --state NEW -j ACCEPT

}

#
#	Function that stops the daemon/service.
#
d_stop() {
##################
### Default policy
##################

# Disable INPUT before changing iptables
iptables --policy INPUT DROP
# Disable OUTPUT before changing iptables
iptables --policy OUTPUT DROP
# Disable FORWARD before changing iptables
iptables --policy FORWARD DROP

###################
### Clear old rules
###################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush
# Delete any user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
# Reset all counters to zero
iptables -Z

####################
### Set up new rules
####################
# Disable INPUT
iptables --policy INPUT DROP
# Disable OUTPUT
iptables --policy OUTPUT DROP
# Disable FORWARD
iptables --policy FORWARD DROP
}

d_reset() {
##################
### Default policy
##################

# Disable INPUT before changing iptables
iptables --policy INPUT DROP
# Disable OUTPUT before changing iptables
iptables --policy OUTPUT DROP
# Disable FORWARD before changing iptables
iptables --policy FORWARD DROP

###################
### Clear old rules
###################

# Remove any existing rules from all chains
iptables --flush
iptables -t nat --flush
iptables -t mangle --flush
# Delete any user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
# Reset all counters to zero
iptables -Z

####################
### Set up new rules
####################
# Enable INPUT
iptables --policy INPUT ACCEPT
# Enable OUTPUT
iptables --policy OUTPUT ACCEPT
# Enable FORWARD
iptables --policy FORWARD ACCEPT
}

case "$1" in
  start)
	echo -n "Starting $DESC"
	d_start
	echo "."
	;;
  stop)
	echo -n "Stopping $DESC"
	d_stop
	echo "."
	;;
  restart|force-reload)
	echo -n "Restarting $DESC"
	d_start
	echo "."
	;;
  reset)
	echo -n "Reset $DESC"
        d_reset
        echo "."
        ;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|reset|restart|force-reload}" >&2
	exit 3
	;;
esac

exit 0