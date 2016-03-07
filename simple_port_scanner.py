# Note: Sections of the scanning capability were inspired by code at http://resources.infosecinstitute.com/port-scanning-using-scapy/
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import sys
import netaddr
import re
from multiprocessing import Process

help_text = "Usage: simple_port_scanner [target_ip_address(es)] [T:|U:][target_port(s)] [options]\n\
Options:\n\
\t-d\t\tDebug program\n\
\t-f <FILE>\tGather IP addresses from a file\n\
\t-h\t\tDisplay this help text\n\
\t-t\t\tPerform a traceroute on the target ip(s)\n\
\t-aU\t\tAssume that the hosts are up, do not ping\n\
\n\
Note: IP Addresses can either be input into the command line or the -f switch can be used\n\
\n\
The following rules apply when using * and - to * to represent IP ranges:\n\
\t1. Only one hyphenated octet per IP glob is allowed and\n\
\t2. Only asterisks are permitted after a hyphenated octet\n\
\t192.168.2-5.* is VALID\n\
\t192.168.2-5.5 is NOT VALID\n\
\t192.168.*.5 is NOT VALID\n"

target_ips = []
active_ips = []
tcp_ports = []
udp_ports = []
ping_hosts = True
traceroute = False
debug = False
help = False
hosts_file = ""

class InvalidArgumentError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class InvalidPortError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class OutOfRangeError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def processArgs(args):

	skip_next = False

	for i in range(1, len(args)):
		current_argument = args[i]

		# Declare thost nasty global variables
		global tcp_ports
		global udp_ports
		global ping_hosts
		global traceroute
		global hosts_file
		global debug
		global help

		try:
			if skip_next:
				skip_next = False
				continue
			elif current_argument == "-h":
				help = True
				return
			elif validateIP(args[i]):
				target_ips.extend(parseIP(current_argument))
			elif current_argument.startswith("T:") and not tcp_ports:
				tcp_ports = parsePorts(current_argument[2:])
			elif current_argument.startswith("U:") and not udp_ports:
				udp_ports = parsePorts(current_argument[2:])
			elif current_argument == "-aU":
				ping_hosts = False
			elif current_argument == "-t":
				traceroute = True
			elif current_argument == "-d":
				debug = True
			elif current_argument == "-f" and len(args) >= i + 1:
				skip_next = True
				hosts_file = args[i+1]
			else:
				raise InvalidArgumentError(current_argument)
	
		except:
			raise InvalidArgumentError(current_argument)

	return True

def parseIP(ip):

	target_ips = []

	if "/" in ip:
		for addr in netaddr.IPNetwork(ip.decode('utf-8')):
			target_ips.append(str(addr))

	elif "-" in ip or "*" in ip:
		for addr in netaddr.IPGlob(ip.decode('utf-8')):
			target_ips.append(str(addr))
	else: 
		target_ips.append(str(netaddr.IPAddress(ip)))

	return target_ips

def validateIP(ip):
	try:
		parseIP(ip)
		return True
	except:
		return False

def parsePorts(ports):
	split_ports = ports.split(",")
	int_ports = set()

	for port in split_ports:
		if "-" in port:
			range_array = port.split("-")
			if len(range_array) > 2:
				raise InvalidPortError(port)
			for range_port in range(int(range_array[0]), int(range_array[1]) + 1):
				int_ports.add(checkPort(range_port))
		else:
			int_ports.add(checkPort(int(port)))

	return sorted(int_ports)


def checkPort(port):
	if port <= 0 or port > 65535:
		raise OutOfRangeError("The following port was found to be out of range: " + str(port))
	return port

def parseHostsFile(hosts_file):

	target_ips = []

	with open(hosts_file) as f:
		for line in f:
			if debug:
				print line.rstrip()
			target_ips.extend(parseIP(line.rstrip()))

	return target_ips

def pingIPs(ips):
	active_ips = []
	
	print "----------------------------------"
	print "Pinging Target IPs"
	print "----------------------------------"
	print "The following hosts are up:"

	for ip in ips:
		pingIP(ip, active_ips)
		
	print "Done.\n"

	return sorted(active_ips)

def pingIP(ip, active_ips):
	packet = scapy.IP(dst=ip, ttl=20)/scapy.ICMP()
	reply = scapy.sr1(packet, timeout=1, verbose=False)
	
	if not (reply is None):
		print ip, " is up."
		active_ips.append(ip)
	return

def scanPorts(ips, tcp_ports, udp_ports, traceroute):
	
	for ip in ips:
		print "----------------------------------"
		print ip
		print "----------------------------------\n"
		if traceroute:
			trace(ip)
		if tcp_ports:
			print "Running TCP scan:"
			port_found = False
			for port in tcp_ports:
				if debug:
					print "Scanning TCP port ", port, " on ", ip, "..."
				if scanTCPPort(ip, port):
					print "\t", port, "\tOpen"
					port_found = True

			if not port_found:
				print "\tNo TCP ports targeted were found to be open."
	
		if udp_ports:
			print "Running UDP scan:"
			port_found = False
			for port in udp_ports:
				if debug:
					print "Scanning UDP port ", port, " on ", ip, "..."
				print "\t", port, "\t", scanUDPPort(ip, port)

	print ""
	return

def trace(ip):
	print "Running traceroute:"
	for i in range(1,25):
		packet = scapy.IP(dst=ip, ttl=i)/scapy.TCP(flags="S")
		response = scapy.sr1(packet, timeout=1, verbose=0)

		if response is None:
			print "\t", i, "\tNo response"
			continue	

		print "\t", i, " ", response.src		

		if response.src == ip:
			print "\t-Trace complete-"
			break

def scanTCPPort(ip, port):
	dst_port = port
	src_port = scapy.RandShort()
	
	packet = scapy.IP(dst=ip)/scapy.TCP(sport=src_port, dport=dst_port, flags="S")
	response = scapy.sr1(packet, verbose=False, timeout=5)
			
	if response is None:
		return False
	
	elif(response.haslayer(scapy.TCP)):

		# If the packet returned had the SYN and ACK flags
		if(response.getlayer(scapy.TCP).flags == 0x12):
			# Send TCP packet back to host with ACK and RST flags
			packet = scapy.IP(dst=ip)/scapy.TCP(sport=src_port,dport=dst_port,flags=0x14)
			send_rst = scapy.sr(packet, verbose=False, timeout=5)
			return True

		# If the packet returned had the RST and ACK flags
		elif (response.getlayer(scapy.TCP).flags == 0x14):
			return False
	else:
		return False

def scanUDPPort(ip, port):
	dst_port = port
	
	packet = scapy.IP(dst=ip)/scapy.UDP(dport=dst_port)
	response = scapy.sr1(packet, verbose=False, timeout=5)
	
	if response is None:
		return "Open|Filtered"

	elif(response.haslayer(scapy.ICMP)):
		# If the response is an ICMP type 3 (port unreachable) code 3, port is closed
		if(int(response.getlayer(scapy.ICMP).type)==3 and int(response.getlayer(scapy.ICMP).code)==3):
			return "Closed"
		# If the response is an ICMP port unreachable codes 1,2,9,10,13 port is filtered
		elif(int(response.getlayer(scapy.ICMP).type)==3 and int(response.getlayer(scapy.ICMP).code) in [1,2,9,10,13]):
			return "Filtered"
	
	else:
		return "Closed"

def main():

	try: 
		# Process args and print out variables
		processArgs(sys.argv)

		if help:
			print help_text
			return

		global target_ips
		if hosts_file:
			if debug:
				print "Processing Hosts File..."
			target_ips.extend(parseHostsFile(hosts_file))
			if debug:
				print "Done processing hosts file."

		if debug:
			print "----------------------------------"
			print "Variables:"
			print "\tTarget IPs: ", target_ips
			print "\tTCP Ports: ", tcp_ports
			print "\tUDP Ports: ", udp_ports
			print "\thosts_file: ", hosts_file
			print "\tping_hosts: ", ping_hosts
			print "\ttraceroute: ", traceroute

		global active_ips
		if ping_hosts:
			active_ips = pingIPs(target_ips)
		else:
			active_ips = target_ips

		if debug:
			print "active_ips: ", active_ips

		scanPorts(active_ips, tcp_ports, udp_ports, traceroute)
		
	except InvalidArgumentError as e:
		print "InvalidArgumentError: Argument \"" + e.value + "\" is invalid!"
	except IOError as e:
		print "The hosts file \"" + hosts_file + "\" could not be opened."
	except netaddr.core.AddrFormatError as e:
		print "--------------------------------------------"
		print "There was an error while parsing your IP address(es). The error was: "
		print "\t\"", str(e).lstrip(), "\"\n"
		print "NOTE: this program uses netaddr.IPGlob for using \"-\" and \"*\" to represent IP addresses ranges." 
		print "Because of this, the following rules apply:"
		print "\t1. Only one hyphenated octet per IP glob is allowed and"
		print "\t2. Only asterisks are permitted after a hyphenated octet"
		print "\t192.168.2-5.* is VALID"
		print "\t192.168.2-5.5 is NOT VALID"
		print "\t192.168.*.5 is NOT VALID"
		print "--------------------------------------------"

if __name__ == "__main__":
    main()
