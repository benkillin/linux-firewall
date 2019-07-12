#!/bin/sh
#### Iptables firewall script, blocks all and allows exceptions.
#### Author: Benkillin
#### Date: 12 June 2014 (updated 12 July 2019)

###################################################################
## Set up vars for use later in script
UNIVERSE="0.0.0.0/0"
LO_ADDR="127.0.0.1/8"
I6LO_ADDR="::1"
# NOTE: make sure there are no empty lines at the end of these files.
blocked_ips="/root/firewall/blocked_ips.txt"
blockedv6_ips="/root/firewall/blockedv6_ips.txt"
allowed_outbound="/root/firewall/allowed_outbound_ports.txt"
allowed_inbound="/root/firewall/allowed_inbound_ports.txt";
allowed_forward="/root/firewall/allowed_forward_ports.txt";
allowed_localhost="/root/firewall/allowed_localhost_ports.txt";
# if use_ipv4_with_ipv6 is false, then we will not re-use the ipv4 ports in the
# files above, but instead use these ipv6 specific rules files:
use_ipv4_with_ipv6=true; # if true these below files are ignored.
allowedv6_outbound="/root/firewall/allowedv6_outbound_ports.txt"
allowedv6_inbound="/root/firewall/allowedv6_inbound_ports.txt";
allowedv6_forward="/root/firewall/allowedv6_forward_ports.txt";
allowedv6_localhost="/root/firewall/allowedv6_localhost_ports.txt";

####################################################################
## Clear existing rules:
#/sbin/iptables -X # these are commented out as they may destroy docker, fail2ban chains
#/sbin/iptables -F
/sbin/iptables -F INPUT
/sbin/iptables -P INPUT DROP
/sbin/iptables -F OUTPUT
/sbin/iptables -P OUTPUT DROP
/sbin/iptables -F FORWARD
/sbin/iptables -P FORWARD DROP

####################################################################
# loopback interfaces are valid.
/sbin/iptables -A INPUT -i lo -s $UNIVERSE -d $UNIVERSE -j ACCEPT
/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A OUTPUT -o lo -s $UNIVERSE -d $UNIVERSE -j ACCEPT
/sbin/iptables -A OUTPUT -o lo -j ACCEPT

####################################################################
# Allow docker
#/sbin/iptables -A INPUT -i docker0 -j ACCEPT
#/sbin/iptables -A INPUT -i docker0 --dport 443 -j ACCEPT
#/sbin/iptables -A FORWARD -d 172.17.42.0/16 -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#/sbin/iptables -A FORWARD -d 172.17.42.0/16 -o docker0 -j ACCEPT
#/sbin/iptables -A FORWARD -s 172.17.42.0/16 -i docker0 -j ACCEPT
#/sbin/iptables -A FORWARD -s 0.0.0.0/0 -i docker0 -j ACCEPT
#/sbin/iptables -A OUTPUT -o docker0 -j ACCEPT

####################################################################
# allow ICMP echo request and echo reply
# allow outbound echo request:
/sbin/iptables -A OUTPUT -p icmp --icmp-type echo-request -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
# allow related inbound echo reply:
/sbin/iptables -A INPUT -p icmp --icmp-type echo-reply -m state --state ESTABLISHED,RELATED -m limit --limit 900/min -j ACCEPT

# allow inbound echo request:
/sbin/iptables -A INPUT -p icmp --icmp-type echo-request -m state --state NEW,ESTABLISHED,RELATED -m limit --limit 900/min -j ACCEPT
# allow related outbound echo reply:
/sbin/iptables -A OUTPUT -p icmp --icmp-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT

##############################
# Ban specified IP addresses
awk '{ system("/sbin/iptables -A FORWARD -d " $1 " -j DROP"); \
       system("/sbin/iptables -A INPUT -d " $1 " -j DROP"); \
       system("/sbin/iptables -A OUTPUT -d " $1 " -j DROP"); \
       system("/sbin/iptables -A FORWARD -s " $1 " -j DROP"); \
       system("/sbin/iptables -A INPUT -s " $1 " -j DROP"); \
       system("/sbin/iptables -A OUTPUT -s " $1 " -j DROP"); }' $blocked_ips;

####################################################################
# Read each line of the allowed outobund file and allow those ports
# out.
awk '{ print "/sbin/iptables -A OUTPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"; \
       print "/sbin/iptables -A INPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"; \
           print ""; \
       system("/sbin/iptables -A OUTPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"); \
       system("/sbin/iptables -A INPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"); }' $allowed_outbound;

####################################################################
# Read each line of the allowed inbound file and allow those ports
# in.
awk '{ print "/sbin/iptables -A INPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"; \
       print "/sbin/iptables -A OUTPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"; \
           print ""; \
       system("/sbin/iptables -A INPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"); \
       system("/sbin/iptables -A OUTPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"); }' $allowed_inbound;

##############
# FORWARD
awk '{ print "/sbin/iptables -A FORWARD -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"; \
       print "/sbin/iptables -A FORWARD -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"; \
           print ""; \
       system("/sbin/iptables -A FORWARD -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"); \
       system("/sbin/iptables -A FORWARD -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"); }' $allowed_forward;


#####################
# LOCALHOST ONLY
awk '{ print "/sbin/iptables -A OUTPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --sport " $2 " -j ACCEPT"; \
       print "/sbin/iptables -A OUTPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --dport " $2 " -j ACCEPT"; \
       print "/sbin/iptables -A INPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --sport " $2 " -j ACCEPT"; \
       print "/sbin/iptables -A INPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --dport " $2 " -j ACCEPT"; \
           print ""; \
       system("/sbin/iptables -A OUTPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --sport " $2 " -j ACCEPT"); \
       system("/sbin/iptables -A OUTPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --dport " $2 " -j ACCEPT"); \
       system("/sbin/iptables -A INPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --sport " $2 " -j ACCEPT"); \
       system("/sbin/iptables -A INPUT -p " $1 " -s 127.0.0.1/8 -d 127.0.0.1/8 --dport " $2 " -j ACCEPT"); }' $allowed_localhost;

### lets list what is set up:
echo "**************** IP4 TABLES:"
/sbin/iptables -L -n


###############################################
###############################################
### IP 6 Section
###############################################
# We don't need any ipv6.
/sbin/ip6tables -F
/sbin/ip6tables -X
/sbin/ip6tables -P INPUT DROP
/sbin/ip6tables -P OUTPUT DROP
/sbin/ip6tables -P FORWARD DROP

if [ "use_ipv4_with_ipv6" = false ]; then
    allowed_outbound=$allowedv6_outbound;
    allowed_inbound=$allowedv6_inbound;
    allowed_forward=$allowedv6_inbound;
    allowed_localhost=$allowedv6_localhost;
fi;

##############################
# Ban specified IP addresses
awk '{ system("/sbin/ip6tables -A FORWARD -d " $1 " -j DROP"); \
       system("/sbin/ip6tables -A INPUT -d " $1 " -j DROP"); \
       system("/sbin/ip6tables -A OUTPUT -d " $1 " -j DROP"); \
       system("/sbin/ip6tables -A FORWARD -s " $1 " -j DROP"); \
       system("/sbin/ip6tables -A INPUT -s " $1 " -j DROP"); \
       system("/sbin/ip6tables -A OUTPUT -s " $1 " -j DROP"); }' $blockedv6_ips;

####################################################################
# allow ICMPv6 echo request and echo reply
# allow outbound echo request:
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type echo-request -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
# allow related inbound echo reply:
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-reply -m state --state ESTABLISHED,RELATED -m limit --limit 900/min -j ACCEPT

# allow inbound echo request:
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -m state --state NEW,ESTABLISHED,RELATED -m limit --limit 900/min -j ACCEPT
# allow related outbound echo reply:
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT

# from https://resources.sei.cmu.edu/tools/downloads/vulnerability-analysis/assets/IPv6/ip6tables_rules.txt
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT

# Allow others ICMPv6 types but only if the hop limit field is 255.
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -m hl --hl-eq 255 -j ACCEPT
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -m hl --hl-eq 255 -j ACCEPT
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -m hl --hl-eq 255 -j ACCEPT
/sbin/ip6tables -A INPUT -p icmpv6 --icmpv6-type redirect -m hl --hl-eq 255 -j ACCEPT

# Allow ICMPv6 types that should be sent through the Internet.
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT

# Limit most NDP messages to the local network.
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type neighbour-solicitation -m hl --hl-eq 255 -j ACCEPT
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type neighbour-advertisement -m hl --hl-eq 255 -j ACCEPT
/sbin/ip6tables -A OUTPUT -p icmpv6 --icmpv6-type router-solicitation -m hl --hl-eq 255 -j ACCEPT

####################################################################
# Allowed outbound:
awk '{ print "/sbin/ip6tables -A OUTPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"; \
       print "/sbin/ip6tables -A INPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"; \
           print ""; \
       system("/sbin/ip6tables -A OUTPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"); \
       system("/sbin/ip6tables -A INPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"); }' $allowed_outbound;

####################################################################
# Allowed inbound:
awk '{ print "/sbin/ip6tables -A INPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"; \
       print "/sbin/ip6tables -A OUTPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"; \
           print ""; \
       system("/sbin/ip6tables -A INPUT -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"); \
       system("/sbin/ip6tables -A OUTPUT -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"); }' $allowed_inbound;

##############
# FORWARD
awk '{ print "/sbin/ip6tables -A FORWARD -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"; \
       print "/sbin/ip6tables -A FORWARD -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"; \
           print ""; \
       system("/sbin/ip6tables -A FORWARD -p " $1 " --sport 1024:65535 --dport " $2 " -m state --state NEW,ESTABLISHED -j ACCEPT"); \
       system("/sbin/ip6tables -A FORWARD -p " $1 " --sport " $2 " --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT"); }' $allowed_forward;

#####################
# LOCALHOST ONLY
awk '{ print "/sbin/ip6tables -A OUTPUT -p " $1 " -s ::1 -d ::1 --sport " $2 " -j ACCEPT"; \
       print "/sbin/ip6tables -A OUTPUT -p " $1 " -s ::1 -d ::1 --dport " $2 " -j ACCEPT"; \
       print "/sbin/ip6tables -A INPUT -p " $1 " -s ::1 -d ::1 --sport " $2 " -j ACCEPT"; \
       print "/sbin/ip6tables -A INPUT -p " $1 " -s ::1 -d ::1 --dport " $2 " -j ACCEPT"; \
           print ""; \
       system("/sbin/ip6tables -A OUTPUT -p " $1 " -s ::1 -d ::1 --sport " $2 " -j ACCEPT"); \
       system("/sbin/ip6tables -A OUTPUT -p " $1 " -s ::1 -d ::1 --dport " $2 " -j ACCEPT"); \
       system("/sbin/ip6tables -A INPUT -p " $1 " -s ::1 -d ::1 --sport " $2 " -j ACCEPT"); \
       system("/sbin/ip6tables -A INPUT -p " $1 " -s ::1 -d ::1 --dport " $2 " -j ACCEPT"); }' $allowed_localhost;

###############################################
# Show what's set up:
echo "********************* IP6 TABLES:"
/sbin/ip6tables -L

echo "***** restarting fail2ban to get the tables back for that"
/etc/init.d/fail2ban restart
