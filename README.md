linux-firewall
==============
This is a host based firewall script that can also be used for iptables linux based routers.

iptables.sh is the script that reads the txt files and applies the iptables rules to the machine. This script sets up both ingress and egress filtering with a default deny, so you have to explicitly whitelist any ports you need to communicate on for both inbound traffic and outbound traffic.

undo_iptables.sh is a script that undoes all the rules and sets the iptables up so it accepts everything by default.

allowed_{inbound,outbound,forward,localhost}_ports.txt these text files specify a protocol, port, and description for what traffic is allowed through the different INPUT, OUTPUT, and FORWARD chains, in addition to specifying which traffic can communicate on localhost. NOTE: Do not have an empty line at the end of these files.

blocked_ips.txt is a list of ip addresses that should never be allowed to communicate with the machine. Again, no blank lines at the end of the file allowed.

**For IPV6 specific rules**, you can use allowedv6_{inbound,outbound,forward,localhost}_ports.txt files and then you must also:
 - Edit iptables.sh line near the top starting with *use_ipv4_with_ipv6=true;* to be **`use_ipv4_with_ipv6=false`**;

Without this change, the ipv6 rules will be the same as the ipv4 rules for allowed ports.

firewall.init.d.sh is an example init script for applying the firewall rules on bootup. To use this, execute:
```
# cp firewall.init.d.sh /etc/init.d/
# update-rc.d firewall defaults
```

Changelog
=========

 - 12 July 2019: Added additional ipv6 support.
