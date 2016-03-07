Usage: simple_port_scanner [target_ip_address(es)] [T:|U:][target_port(s)] [options]

Options:
-d		Debug program
-f <FILE>	Gather IP addresses from a file
-h		Display this help text
-t		Perform a traceroute on the target ip(s)
-aU		Assume that the hosts are up, do not ping

Note: IP Addresses can either be input into the command line or the -f switch can be used

The following rules apply when using * and - to * to represent IP ranges:
	1. Only one hyphenated octet per IP glob is allowed and
	2. Only asterisks are permitted after a hyphenated octet
	192.168.2-5.* is VALID
	192.168.2-5.5 is NOT VALID
	192.168.*.5 is NOT VALID"
