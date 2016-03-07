Usage: simple_port_scanner [target_ip_address(es)] [T:|U:][target_port(s)] [options]

<dl>          
    <dt>-d</dt>
    <dd>Debug program</dd>
             
    <dt>-f <FILE></dt>
    <dd>Gather IP addresses from a file</dd>
                 
    <dt>-h</dt>
    <dd>Display this help text</dd>
                 
    <dt>-t</dt>
    <dd>Perform a traceroute on the target ip(s)</dd>
	
	<dt>-aU</dt>
    <dd>Assume that the hosts are up, do not ping</dd>
</dl>		

Note: IP Addresses can either be input into the command line or the -f switch can be used

The following rules apply when using * and - to * to represent IP ranges:
<ol>
<li>Only one hyphenated octet per IP glob is allowed and
<li>Only asterisks are permitted after a hyphenated octet
</ol>
192.168.2-5.* is VALID<br />
192.168.2-5.5 is NOT VALID<br />
192.168.*.5 is NOT VALID<br />
