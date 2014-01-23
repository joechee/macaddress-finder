Mac Address Finder (Windows)
============================

This is a small tool that I used to figure out MAC Addresses of the LAN ports
of certain routers without accessing the admin console (to grab the MAC 
addresses of routers such that it can be whitelisted by the school network).

It works by sniffing and recording the MAC addresses of the packets (ARP, 
ICMP, etc.) that are coming in, and comparing the MAC addresses to a list of
known brand types to figure out the brand of the router (to ascertain that it
is truly the device one is looking for)

Use
---

1. Install winpcap
2. Connect an ethernet cable between your machine and some other ethernet
   port
3. Run the program and select the hardware interface from your machine
4. Take note of the MAC addresses that are printed. 

Compile
-------

1. Install winpcap, mingw (not to sure if Visual Studio works)
2. Install a regex library (eg. [libgnurx](http://sourceforge.net/projects/mingw/files/Other/UserContributed/regex/mingw-regex-2.5.1/))
3. Run the makefile in mingw