#!/usr/bin/python3
#
# originalSYN.py by LLCZ00
#
# For all have sinned,
# 	and fall short of the glory of God.
# - Romans 3:23
# 
_v='v1.2.1'

import socket
import struct
import sys
import argparse
from time import perf_counter as timer
from random import randint
from array import array


class LLCZ00Parser(argparse.ArgumentParser): # better error handler
    def error(self, message):
        print("Error. {}".format(message))
        sys.exit("Try '{} --help' for more information".format(self.prog))

class Validator(argparse.Action): # custom action to sort/validate target ip and ports
	def __call__(self, parser, namespace, values, option_string=None):

		if type(values) is str: # IP
			setattr(namespace, self.dest, self.ip_validate(values, parser))
		elif type(values) is list: # ports
			setattr(namespace, self.dest, self.parse_ports(values, parser))

	def ip_validate(self, ip, parser):
		try:
			packed = socket.inet_aton(ip)
			if ip != socket.inet_ntoa(packed):
				parser.error("invalid ip: {}".format(ip))
		except (OSError, socket.gaierror):
			parser.error("invalid ip: {}".format(ip))
		return ip

	def parse_ports(self, port_list, parser):
		ports_tmp = []
		for port_item in port_list:
			try:
				if '-' in port_item: # handle ranges			
					port_range = list(map(int, port_item.split('-')))

					if 1 <= port_range[0] < port_range[1] <= 65535:
						ports_tmp += [x for x in range(port_range[0], port_range[1]+1)]
					else:
						parser.error("ports out of range(1-65535), or out of order: {}".format(port_item))

				else: # handle singles
					if 1 <= int(port_item) <= 65535: 
						ports_tmp += [int(port_item)]
					else:
						parser.error("port number out of range(1-65535): {}".format(port_item))

			except ValueError:
				parser.error("invalid port number: {}".format(port_item))
		
		return list(set(ports_tmp)) # remove duplicates


def argument_handler():
	parser = LLCZ00Parser(
		prog='originalSYN.py',
		usage="%(prog)s [options] target_ip ports", 
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description="OriginalSYN Scanner {}:\nPerforms a TCP SYN scan of desired ports.\nRequires sudo/root privileges to use raw sockets".format(_v),
		epilog="Examples:\n%(prog)s 192.168.1.1 8080\n%(prog)s -v -t 15 10.10.10.23 9090 9091 9092-10000\n%(prog)s --timeout=.1 192.168.1.50 1-65535"
	)

	parser.add_argument(
		'-v', '--verbose',
		help="Output closed/irregular responses, and non-responsive ports",
		action='store_true',
		dest='verb'
	)
	parser.add_argument(
		'-t','--timeout',
		help="Connection timeout, in seconds. (Default=%(default)s)",
		default=0.5,
		dest='timeout',
		type=float,
		metavar='TIMEOUT'	
	)
	parser.add_argument(
		'target_ip',
		help="IP address to scan",
		action=Validator
	)	
	parser.add_argument(
		'ports',
		help="Port, ports, or port range to scan",
		nargs='+',
		action=Validator
	)

	return parser.parse_args()


def get_hostIP(): 
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as x:
		x.settimeout(0)
		x.connect(("200.255.255.255", 1)) 
		ip = x.getsockname()
	return ip[0]
	# gets host id by connecting to unreachable address, can be anyting
	# If it continuously fails for some reason, hardcode your ip in

def tcp(src_ip, src_port, dst_ip, dst_port): # generate tcp header
	tcp_seg = struct.pack(
		'!HHIIBBHHH', 
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

	ipheader = struct.pack(
		'!4s4sHH',
		socket.inet_aton(src_ip), 
		socket.inet_aton(dst_ip), 
		socket.IPPROTO_TCP, 
		len(tcp_seg)
	)

	# calculate checksum
	packetsum = sum(array("H", tcp_seg+ipheader)) # add all 16bit groups together
	sum16 = (packetsum >> 16) + (packetsum & 0xffff) # aything past 16bits + the 16bits
	checksum = (~sum16) & 0xffff # 16bit one's compliment of one's compliment

	
	return tcp_seg[:16] + struct.pack("H", checksum) + tcp_seg[18:]


if __name__ == "__main__":
	args = argument_handler()

	socket.setdefaulttimeout(args.timeout)
	src_ip = get_hostIP()
	dst_ip = args.target_ip
	ports = args.ports
	count = 0

	start = timer()
	for port in ports:
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
