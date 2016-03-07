Usage: simple_port_scanner [target_ip_address(es)] [T:|U:][target_port(s)] [options]

Options:<br />
-d		Debug program<br />
-f <FILE>	Gather IP addresses from a file<br />
-h		Display this help text<br />
-t		Perform a traceroute on the target ip(s)<br />
-aU		Assume that the hosts are up, do not ping<br />

Note: IP Addresses can either be input into the command line or the -f switch can be used

The following rules apply when using * and - to * to represent IP ranges:<br />
	1. Only one hyphenated octet per IP glob is allowed and<br />
	2. Only asterisks are permitted after a hyphenated octet<br />
	192.168.2-5.* is VALID<br />
	192.168.2-5.5 is NOT VALID<br />
	192.168.*.5 is NOT VALID"<br />
