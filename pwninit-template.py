#!/usr/bin/env python3

from pwn import *

{bindings}

context.binary = {bin_name}

sla = lambda p, d, x: p.sendlineafter(d, x)
sa = lambda p, d, x: p.sendafter(d, x)
sl = lambda p, x: p.sendline(x)
s = lambda p, x: p.send(x)

slan = lambda p, d, n: p.sendlineafter(d, str(n).encode())
san = lambda p, d, n: p.sendafter(d, str(n).encode())
sln = lambda p, n: p.sendline(str(n).encode())
sn = lambda p, n: p.send(str(n).encode())

ru = lambda p, x: p.recvuntil(x)
rl = lambda p: p.recvline()
rc = lambda p, n: p.recv(n)
rr = lambda p, t: p.recvrepeat(timeout=t)
ra = lambda p, t: p.recvall(timeout=t)
ia = lambda p: p.interactive()

gdbscript = '''
set follow-fork-mode parent
set detach-on-fork on
continue
'''

def conn():
    if args.LOCAL:
        p = process([ld.path, {bin_name}.path], env={{"LD_PRELOAD": libc.path}})
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
        if args.DEBUG:
            context.log_level = 'debug'
        return p
    else:
        host = ""
        port = 0
        return remote(host, port)

p = conn()



ia(p)
