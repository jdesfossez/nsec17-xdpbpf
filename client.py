#!/usr/bin/python3

import socket

UDP_IP = "9000:470:b2b5:cafe:5054:ff:feb1:dd21"
UDP_PORT = 9001
MESSAGE = "FLAG-XdpCovertChannel__03"

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.sendto(MESSAGE.encode('utf-8'), (UDP_IP, UDP_PORT))

