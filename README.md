linux-firewall
==============
This is a host based firewall script that can also be used for iptables linux based routers.

iptables.sh is the script that reads the txt files and applies the iptables rules to the machine. This script sets up both ingress and egress filtering with a default deny, so you have to explicitly whitelist any ports you need to communicate on for both inbound traffic and outbound traffic.

undo_iptables.sh is a script that undoes all the rules and sets the iptables up so it accepts everything by default.

allowed_{inbound,outbound,forward,localhost}_ports.txt these text files specify a protocol, port, and description for what traffic is allowed through the different INPUT, OUTPUT, and FORWARD chains, in addition to specifying which traffic can communicate on localhost. NOTE: DO NOT HAVE AN EMPTY LINE AT THE END OF THESE FILES!

firewall.init.d.sh is an example init script for applying the firewall rules on bootup. To use this, execute:
# cp firewall.init.d.sh /etc/init.d/
# update-rc.d firewall defaults

