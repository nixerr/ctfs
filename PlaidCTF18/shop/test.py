#!/usr/bin/python

buf = ''
for i in range(0,1024):
    buf += "%04x" % i

print len(buf)
