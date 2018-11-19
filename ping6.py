# coding : utf-8
# ICMPv6.py

__author__ = "Aaron"
__time__="2018/8/2"

import socket
import struct
import time
import select

def checkSum(message):
    """
    校验
    """
    n = len(message)
    m = n % 2
    sum = 0 
    for i in range(0, n - m ,2):
        sum += (message[i]) + ((message[i+1]) << 8)#传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
    if m:
        sum += (message[-1])
    #将高于16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16) #如果还有高于16位，将继续与低16位相加

    answer = ~sum & 0xffff
    #主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer 

def rawSocket(dst_addr, icmpv6_packet):
	sendSocket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname('ipv6-icmp'))
	send_time = time.time()
	sendSocket.sendto(icmpv6_packet, socket.getaddrinfo(dst_addr, 1)[0][4])
	return send_time, sendSocket

def pseudo_header(s_addr, dst_addr, upper_packet_len, n_header = 58):
	zero = 0
	# 将冒号记法地址转换为对应的底层数据
	packed_s_addr = socket.inet_pton(socket.AF_INET6, s_addr)
	packed_dst_addr = socket.inet_pton(socket.AF_INET6, dst_addr)

	packet = packed_s_addr + packed_dst_addr + struct.pack("!2L", upper_packet_len,
	 n_header)
	return packet

def ICMPv6(checksum = 0, SequenceNumber = 0):
	Type = 128
	Code = 0
	Identifier = 0
	Data = b"Zero or more octets of arbitrary data."
	Message = struct.pack('!2B3H{0}s'.format(len(Data)), Type, Code, checksum,
														Identifier, SequenceNumber,Data )
	return Message

def echo_ping(send_time, sendsocket, data_sequence, timeout = 2):
	while True:
		started_select = time.time()
		what_ready = select.select([sendsocket], [], [], timeout)
		wait_for_time = (time.time() - started_select)
		if what_ready[0] == []: # timeout
			return -1
		time_received = time.time()
		recieved_packet, addr = sendsocket.recvfrom(1024)
		icmpHeader = recieved_packet[0:8]
		type, code, checksum, packet_id, SequenceNumber = struct.unpack(
				"!2B3H", icmpHeader
			)
		if type == 129 and SequenceNumber == data_sequence:
			return time_received - send_time
		if timeout <= 0:
			return -1

def ping(host):
	# dst_addr = socket.gethostbyaddr(host)[-1][0]
	dst_addr = host
	s_addr = socket.getaddrinfo(socket.gethostname(), 0)[0][-1][0]

	print("正在 Ping {0} [{1}] 具有 32 字节的数据:".format(host,dst_addr))

	for i in range(0, 4):
		icmpv6 = ICMPv6(SequenceNumber = i)
		ipv6_header = pseudo_header(s_addr, dst_addr, len(icmpv6))
		icmpv6_checksum = checkSum(ipv6_header + icmpv6)
		icmpv6_packet = ICMPv6(icmpv6_checksum, SequenceNumber = i)
		send_time, r_socket = rawSocket(dst_addr, icmpv6_packet)
		times = echo_ping(send_time, r_socket, i)
		if times >= 0:
			print("来自 {0} 的回复: 字节=32 时间={1}ms".format(dst_addr,int(times*1000)))
			time.sleep(0.7)
		else:
			print("请求超时")

if __name__=="__main__":
	host = "fe80::2ad3:8509:9243:ce27"
	ping(host)
