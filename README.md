This multi-threaded port scanner allows for TCP and UDP scanning at a basic level. Each port specified is checked to see if it is either open, closed, or filtered. IP addresses can be input in several different formats to specify a range (see rules below).

Usage: simple_port_scanner [target_ip_address(es)] [T:|U:][target_port(s)] [options]

Options:
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
	
	<dt>-tH <#></dt>
	<dd>Specify thread count</dd>
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
