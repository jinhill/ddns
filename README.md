## DDNS for Aliyun
This script can automatically add, delete and update the Aliyun DNS records.

## Features:
1) Support ipv4 and ipv6;
2) Support to automatically get the wan IP address, or get the IPv6 public address from the local interface.
3) Support one host name to resolve multiple IP addresses.
4) Supported systems: OpenWrt/Ubuntu/Debian/CentOS/Alpine/Synology DSM

## Usage:
```bash
./ddns_ali.sh [-46adhur] [-i <key id>] [-s <key secret>] [-n <dns name>] [-l <ip source>] [-t <dns type>] [-v <dns value arrays>]
./ddns_ali.sh --install/uninstall
only for Synology DSM ddns:
./ddns_ali.sh <key id> <key secret> <dns name>
	-4/6 get ipv4/6;
	-a add dns;
	-d auto detect ip and update;
	-i set key id;
	-l <0/1> set ip source, 0-wan ip, 1-local ip;
	-n set dns name;
	-u update dns;
	-r remove dns;
	-s set key secret;
	-t set dns type;
	-v set dns value arrays;
	--install/uninstall install/uninstall this script;
	-h Print help.
```