#!/usr/bin/python3.9
# originalSYN.py by LLCZ0
# v1.1.0
#
# For all have sinned,
# 	and fall short of the glory of God.
# - Romans 3:23
# 

import socket
import struct
import sys
import argparse
from time import perf_counter as timer
from random import randint
from array import array

class ArgumentParser(argparse.ArgumentParser): # just to tailor the error messages a bit more to my liking, completely aesthetic
    def error(self, message):
        print("Error: {}".format(message)) # error
        sys.exit("Try '{} --help' for more information".format(self.prog))

def argument_handler():
	parser = ArgumentParser(prog='originalSYN.py',
		usage="%(prog)s [options] target_ip ports", 
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description="OriginalSYN Scanner v1.0.1:\nPerforms a SYN scan of desired ports.\nRequires sudo/root privileges, as it uses raw sockets to perform a true syn scan",
		epilog="Examples:\n%(prog)s 192.168.1.1 8080\n%(prog)s -v -t 15 10.10.10.23 9090 9091 9092\n%(prog)s --timeout=.1 192.168.1.50 1-65535"
		)
	parser.add_argument('-v', '--verbose',
		help="Output closed/irregular responses, and non-responsive ports",
		action='store_true',
		dest='verb'
		)
	parser.add_argument('-t','--timeout',
		help="Connection timeout, in seconds. (Default=%(default)s)",
		default=0.5,
		dest='timeout',
		type=float,
		metavar='TIMEOUT'	
		)
	parser.add_argument('target_ip',
		help="IP address to scan"
		)	
	parser.add_argument('ports',
		help="Port, ports, or port range to scan",
		nargs='+',
		)

	cmd = parser.parse_args()

	# raise error if any port outside 1-65535 is submitted
	def out_of_bounds(portlist, range_flag=0):
		for port in portlist:
			if not (1 <= port <=65535):
				sys.exit("Supplied port out of range: {}\nTry 'originalSYN.py --help' for more information".format(port))
		if range_flag:
			if portlist[0] > portlist[1]:
				sys.exit("Invalid port range: {}-{}\nTry 'originalSYN.py --help' for more information".format(portlist[0], portlist[1]))

	# Determine port range, & convert to integers
	try:
		if len(cmd.ports) == 1:
			if '-' in cmd.ports[0]: # determine/set port range (spread this part out to be a litle more readable)
				ports_tmp = cmd.ports[0].split('-')
				int_ports = [int(x) for x in ports_tmp]

				out_of_bounds(int_ports, 1) # check range before breaking it out

				cmd.ports = [port for port in range(int_ports[0], int_ports[1]+1)]
			else:
				cmd.ports = [int(cmd.ports[0])]
				out_of_bounds(cmd.ports)
		else:
			cmd.ports = [int(x) for x in cmd.ports]
			out_of_bounds(cmd.ports)
	except ValueError:
		sys.exit("One or more supplied ports is invalid: {}\nTry 'originalSYN.py --help' for more information".format(' '.join(cmd.ports)))

	# ayo ip validity check
	try:
		packed = socket.inet_aton(cmd.target_ip)
		if cmd.target_ip != socket.inet_ntoa(packed):
			sys.exit("Invalid ip: {}\nTry 'originalSYN.py --help' for more information".format(cmd.target_ip))
	except OSError:
		sys.exit("Invalid ip: {}\nTry 'originalSYN.py --help' for more information".format(cmd.target_ip))
	# packs address into bytes, then unpacks it and compares to the original string
	# "192.168.1" will get padded with zeros and make it through, otherwise
  
	return cmd

def get_hostIP(): 
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as x:
	  x.settimeout(0)
	  x.connect(("200.255.255.255", 1)) 
	  ip = x.getsockname()
	return ip[0]
	# gets host ip (needed for packet creation) by connecting to unreachable address, can be anyting you desire
	# If it continuously fails for some reason, hardcode your ip in

def tcp(src_ip, src_port, dst_ip, dst_port):
	tcp_seg = struct.pack('!HHIIBBHHH', # tcp header
		src_port, 
		dst_port, 
		0,      # sequence
		0,      # acknowledgement
		5 << 4, # offest/header length (20)
		2,      # flag (SYN)
		1024,   # window size
		0,      # checksum placeholder
		0       # urgent 
		)

	ipheader = struct.pack('!4s4sHH', # ip pseudo header (needed for checksum)
		socket.inet_aton(src_ip), 
		socket.inet_aton(dst_ip), 
		socket.IPPROTO_TCP, 
		len(tcp_seg))

	# calculate checksum
	packetsum = sum(array("H", tcp_seg+ipheader)) # add all 16bit groups together
	sum16 = (packetsum >> 16) + (packetsum & 0xffff) # aything past 16bits + the 16bits
	checksum = (~sum16) & 0xffff # 16bit one's compliment of one's compliment

	# stick checksum in tcp header and return
	return tcp_seg[:16] + struct.pack("H", checksum) + tcp_seg[18:]


if __name__ == "__main__":
	args = argument_handler()

	socket.setdefaulttimeout(args.timeout)
	src_ip = get_hostIP()
	dst_ip = args.target_ip
	ports = args.ports
	count = 0

	start = timer()
	for port in ports:     # assign random high source port
		tcpsyn = tcp(src_ip, randint(20000, 65535), dst_ip, port)
		with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
			s.sendto(tcpsyn, (dst_ip, 0))
			try:
				data = s.recv(64)
			except socket.timeout:
				if args.verb:
					print("\nNo response from {}:{}".format(dst_ip, port))

			else:
				tcp_resp = struct.unpack_from("!HHIIHHHH", data, 20)
				flags = hex(tcp_resp[4] & 0b11111) # isolate the flags that matter

				if flags == '0x12': # syn
					print("Port {} is open".format(tcp_resp[0]))
					count += 1

				elif args.verb:
					if flags == '0x14': # rst, ack
						print("Port {} is closed".format(tcp_resp[0]))

					else:
						print("Port {} has flag value: {}\n(Not SYN/ACK or RST)".format(tcp_resp[0], flags))

	end = timer()

	print("{} port(s) scanned, {} found open.".format(len(args.ports), count))
	print("Completed in {}s".format(end - start))
