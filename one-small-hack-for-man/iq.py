#!/usr/bin/env python3
# Solution script by amadan

from pwn import *

conn = remote('unique-permit.satellitesabove.me', 5006)
conn.recvuntil(b'Ticket please:')
conn.sendline(b'ticket{november253757uniform2:GJmpZix3C7rVJBmVCAk-hH-y5XkRSUQ3VTZQp3kRn0yKcOwKf6u1iddg80nw5fmpBw}')
reply = conn.recvuntil(b'Input samples:')
q = [l for l in reply.split(b'\n') if l.startswith(b'Bits')][0]
print(q)
q = q.split(b':')[1].replace(b' ', b'')
print(q)
print(len(q))
qpsk = {
        b'01': (-1.0, 1.0),
        b'11': (1.0, 1.0),
        b'10': (1.0, -1.0),
        b'00': (-1.0, -1.0)
}
a = [qpsk[q[i:i+2]] for i in range(0,len(q), 2)]
a = [ f'{x[0]} {x[1]}' for x in a]
a = ' '.join(a)
conn.sendline(a)
conn.interactive()
