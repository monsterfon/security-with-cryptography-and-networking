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
echo 0 > /proc/sys/net/ipv4/ip_forward
### Enable forwarding
# echo 1 > /proc/sys/net/ipv4/ip_forward

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

#################################
### Allow DNS lookups as a client
### (1) Allow access to a particular DNS server.
### The IP address of the DNS server is given in variable NAMESERVER


iptables -A OUTPUT -o $INET_IFACE -p udp -d $NAMESERVER --dport 53 -j ACCEPT
iptables -A INPUT  -i $INET_IFACE -p udp -s $NAMESERVER --sport 53 -j ACCEPT

################
### SSH
### (2) Allow outgoing SSH connections
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT  -p tcp ! --syn --sport 22 -j ACCEPT

### (3) Allow incoming SSH connections
iptables -A INPUT  -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

################
### HTTP settings
### (4) TODO: Allow outgoing HTTP connections
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT  -p tcp ! --syn --sport 80 -j ACCEPT


### (5) TODO: Allow incoming HTTP connections
iptables -A INPUT  -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT

################
### HTTPS settings
### (6) TODO: Allow outgoing HTTPS connections
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT  -p tcp ! --syn --sport 443 -j ACCEPT


### (7) TODO: Allow incoming HTTPS connections
iptables -A INPUT  -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT

#################
### ICMP settings
### (8) TODO: Allow outgoing ping requests (and corresponding ping replies)
### Hint: use protocol icmp and set the type of the message to either request
### or reply.
iptables -A INPUT   -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT  -p icmp --icmp-type echo-reply   -j ACCEPT


### (9) TODO: Allow incoming pings but only from a specific IP address (you may decide which one)
iptables -A INPUT   -p icmp --icmp-type echo-request -s 192.168.68.82 -j ACCEPT 
iptables -A OUTPUT  -p icmp --icmp-type echo-reply                    -j ACCEPT
}

#
#   Function that stops the daemon/service.
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