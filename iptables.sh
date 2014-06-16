#!/bin/sh
#### Iptables firewall script, blocks all and allows exceptions.
#### Author: Benkillin
#### Date: 12 June 2014

###################################################################
## Set up vars for use later in script
UNIVERSE="0.0.0.0/0"
LO_ADDR="127.0.0.1/8"
I6LO_ADDR="::1"
# NOTE: make sure there are no empty lines at the end of these files.
blocked_ips="/root/firewall/blocked_ips.txt"
allowed_outbound="/root/firewall/allowed_outbound_ports.txt"
allowed_inbound="/root/firewall/allowed_inbound_ports.txt";
allowed_forward="/root/firewall/allowed_forward_ports.txt";
allowed_localhost="/root/firewall/allowed_localhost_ports.txt";
####################################################################
## Clear existing rules:
/sbin/iptables -X
/sbin/iptables -F
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
/sbin/iptables -A OUTPUT -i lo -s $UNIVERSE -d $UNIVERSE -j ACCEPT
/sbin/iptables -A OUTPUT -i lo -j ACCEPT

####################################################################
# allow ICMP ping outbound
/sbin/iptables -A OUTPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A INPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT
# allow ICMP ping inbound
/sbin/iptables -A INPUT -p icmp --icmp-type 8 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A OUTPUT -p icmp --icmp-type 0 -m state --state ESTABLISHED,RELATED -j ACCEPT


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


/sbin/ip6tables -A INPUT -p tcp -s $I6LO_ADDR -d $I6LO_ADDR -j ACCEPT
/sbin/ip6tables -A OUTPUT -p tcp -s $I6LO_ADDR -d $I6LO_ADDR -j ACCEPT
/sbin/ip6tables -A INPUT -p udp -s $I6LO_ADDR -d $I6LO_ADDR -j ACCEPT
/sbin/ip6tables -A OUTPUT -p udp -s $I6LO_ADDR -d $I6LO_ADDR -j ACCEPT
###############################################
# Show what's set up:
echo "********************* IP6 TABLES:"
/sbin/ip6tables -L


echo "***** restarting fail2ban to get the tables back for that"
/etc/init.d/fail2ban restart
