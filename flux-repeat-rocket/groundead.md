# groundead
> you're groundead

`nc unfair-cookie.satellitesabove.me 5001`

This was a binary reversing challenge given a x86_64 unstripped binary and a remote instance to connect to.

## Initial observations
After connecting to the service and providing our ticket, we're greeted with some nice ASCII art, a message telling us the Ground Station is ONLINE and an input prompt. But all our messages are rejected.

```
Ground Station ONLINE

>help
That sequence of hex characters did not work. Try again.
ffffff
That sequence of hex characters did not work. Try again.
```

Opening up the given challenge binary in IDA shows a bunch of C++ stdlib template stuff. This is going to be "fun". Right in `main`, the binary starts three threads:

1. Receiving satellite packets
2. Processing satellite packets
3. A timer

So we'll probably have to understand the expected packet format to trigger some functionality? Scanning through the three thread handlers quickly reveals the goal:

```c
switch ( (unsigned __int64)switch_offsets + switch_offsets[cmd_type] )
{
case 0uLL:
    break;
case 1uLL:
    puts("Handling Power Telemetry");
    goto LABEL_22;
case 2uLL:
    puts("Handling Guidance Telemetry");
    goto LABEL_22;
case 3uLL:
    puts("Handling CDH Telemetry");
    goto LABEL_22;
case 4uLL:
    puts("Handling Communications Telemetry");
    goto LABEL_22;
case 5uLL:
    puts("Handling Payload Telemetry");
    goto LABEL_22;
case 6uLL:
    puts("Handling Attitude Telemetry");
    goto LABEL_22;
case 7uLL:
    puts("Handling Test Telemetry");
    goto LABEL_22;
case 8uLL:
    puts("EMERGENCY_MODE: THE SPACECRAFT IS IN EMERGENCY_MODE");
    puts("You made it!\nHere's your flag:");
    puts(flag);
    exit(0);
}
```


So we have to reach that 8th case to get our flag. The `flag` global is initialized at startup using `getenv("FLAG")`.

## Reversing
### startTimer
Starting with the shortest thread handler, the third thread sleeps for 3 minutes and then exits. `main` waits for that thread to exit and exits the whole process, so this is an elaborate watchdog `alarm` to `exit`.

### getSatellitePacketBytes
The receiving thread starts by reading 256 bytes of our input and hex-encoding every byte and decoding it again (weird flex but ok). Afterwards it verifies, that the slice `input[12:14]` equals hex `7`. If that part of our input is in fact `7`, our input is prepended with `1acffc1d`. Afterwards it loops through our input, hex decodes every two bytes and adds each of them to a global custom Queue. Then the thread sleeps for 0.5 seconds and starts all over again, waiting for our next packet.

So the input format should be a hex encoded binary package, with the seventh byte set to 7: `00000000000007`

Sending `000000000000074141` actually leads to some output:
```
>000000000000074141

Packet Version Number: 00000000
Packet Type: 00000000
Secondary Header Flag: 00000000
Application Process Identifier: 00000000
Sequence Flags: 00000000
Packet Sequence Count or Packet Name: 00000000
Packet Data Length: 00000001
```

So what's the purpose of those bytes? Let's look at the processing thread.

### processSatellitePacketBytes
The thread waits until there are some bytes in the global Queue and then proceeds to pop them from the global queue. Once it received at least 4 bytes, it compares them to `1acffc1d` and rejects the packet if that value wasn't found. So internally the start of a command is marked by this magic value. It then continues to read three uint16_t values from the queue and outputs the above debug info while only using certain bits for each part. Which bits encode which information is setup in the same place as the `flag` variable itself.

```c
flag = getenv("FLAG");
PVN = pktPrimHdrBitDefn(13, 15);
PKT_TYPE = pktPrimHdrBitDefn(12, 12);
SEC_HDR_FLAG = pktPrimHdrBitDefn(11, 11);
APID = pktPrimHdrBitDefn(0, 10);
SEQ_FLAGS = pktPrimHdrBitDefn(14, 15);
PKT_SEQ_CNT_OR_PKT_NAME = pktPrimHdrBitDefn(0, 13);
```

* First short:
  * 0-10: APID
  * 11: SEC_HDR_FLAG
  * 12: PKT_TYPE
  * 13-15: PVN

* Second short:
  * 0-13: PKT_SEQ_CNT_OR_PKT_NAME
  * 14-15: SEQ_FLAGS

* Third short:
  * packet length

Our packet is considered valid if `PVN` and `PKT_TYPE` are zero and `APID != 2047`. The other fields aren't checked, so setting them all to `0` seems fine and worked with our initial explorative testing.

After parsing the packet header the thread receives the rest of the `packet_length + 1` bytes and verifies that `SEC_HDR_FLAG` is 1. So this is the only flag we have to set, while leaving all others at zero. Since we've set the packet length to 0 it only reads one additional byte which appears to be the `cmd_type` variable used to select which command to execute in the switch!

So all we need to do now is send a packet with `cmd_type` set to 8 and we win, right? It's not that easy, since the receive thread forces the seventh byte to 7, which we now know is the `cmd_type`.

## Exploitation
The goal is to get the processing thread to process a packet with the `cmd_type` set to 8. Since the receiving thread doesn't do any validation of the packet length or format, we can just concatenate more data after our initial valid command. The processing thread will continue to parse our excess data as a new command from the global Queue, bypassing the check for the seventh byte in the receiving thread.

We only have to remember to add the magic header value `1acffc1d` before our target command packet and send both in one go. This yields the flag.

Simultaneously we found that those identifiers match up with the [Space Packet Protocol](https://public.ccsds.org/Pubs/133x0b2e1.pdf), so that's what we were looking at.

```
EMERGENCY_MODE: THE SPACECRAFT IS IN EMERGENCY_MODE
You made it!
Here's your flag:
flag{zulu36028papa2:GGE0j_JTt-lIcjCffucwuTcXej36kT6OWEyIvFQWcxBYTvdnCa2bFzXsWCbWtqFiomlqr3vTtqneSbKw6s2SW1M}
```

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./challenge')

host = args.HOST or 'unfair-cookie.satellitesabove.me'
port = int(args.PORT or 5001)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
brva 0x351A
continue
'''.format(**locals())

# -- Exploit goes here --

TICKET = 'ticket{zulu36028papa2:GMPm-aFv1thQmI7FHDDfImaonVfmYwNjhJwFJnbqAjs10ijXDH2FVENhCWb0qIxtfA}'

io = start(env={'FLAG': 'fake_flag_123'})

if not args.LOCAL:
    io.sendlineafter('Ticket please:\n', TICKET)

io.recvuntil('Ground Station ONLINE')

APID = 0
SEC_HDR_FLAG = 1
PKT_TYPE = 0
PVN = 0
PKT_SEQ_CNT_OR_PKT_NAME = 0
SEQ_FLAGS = 0
packet_len = 0

header = APID | SEC_HDR_FLAG << 11 | PKT_TYPE << 12 | PVN << 13
header = header << 16 | PKT_SEQ_CNT_OR_PKT_NAME | SEQ_FLAGS << 14
header = header << 16 | packet_len
payload = hex(header)[2:].rjust(12, "0") + "07"

payload += "1acffc1d"

payload += hex(header)[2:].rjust(12, "0") + "08"

print(payload)
io.sendlineafter('>', payload)

io.interactive()
```
