#!/usr/bin/env python3

from pwn import *
import os

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
rn = lambda p, n: p.recvn(n)
rr = lambda p, t: p.recvrepeat(timeout=t)
ra = lambda p, t: p.recvall(timeout=t)
ia = lambda p: p.interactive()

lg = lambda t, addr: print(t, '->', hex(addr))
binsh = lambda libc: next(libc.search(b"/bin/sh\x00"))
leak_bytes = lambda r, offset=0: u64(r.ljust(8, b"\0")) - offset
leak_hex = lambda r, offset=0: int(r, 16) - offset
leak_dec = lambda r, offset=0: int(r, 10) - offset

{bindings}

# context.terminal = ['tmux', 'splitw', '-h'] # using WSL2 so this is not needed
context.binary = {bin_name}

# Some fixes for WSL2
gdbscript = '''
cd ''' + os.getcwd() + '''
set solib-search-path .
set sysroot /

set follow-fork-mode parent
set detach-on-fork on
continue
'''

def conn():
    if args.LOCAL:
        p = process([{bin_name}.path])
        if args.GDB:
            gdb.attach(p, gdbscript=gdbscript)
        if args.DEBUG:
            context.log_level = 'debug'
        return p
    else:
        host = "localhost"
        port = 1337
        return remote(host, port)

p = conn()



ia(p)