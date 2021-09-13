# Mars or Bust

We are provided with a website where you can download a rom file and submit a rom file to be run in a simulator. The simulator runs the provided firmware to perform a mars landing through several stages. The unmodified firmware works fine until the point where the lander has about 40 meters remaining at which point it shuts down the engine and crashes to the surface. The goal is to patch the firmware and perform a correct landing.

Looking at the firmware we see that it is MIPS 32-bit little endian code. We try to open it in Binary Ninja and disassemble the code at address `0x0`. This turns out to be a jump to `0xfc00400` which suggests that `0xfc00400` so we re-open the firmware with the new base address and try to disassemble again which gives a somewhat better result. However, looking further through the code we can find the initialization routine which, among other things, copies data from 0xbfc05efc to an address which probably is RAM. This suggests that the base address is actually `0xbfc00000`. We re-open the file again with the correct base address.

To speed up the reverse engineering process we build a small simulator using Unicorn engine and Python. The simulator is included at the end for reference but it doesn't implement all the functionality to actually run the ROM instead it was used to aid the static analysis. The work flow worked something like this: first we mapped the ROM at the correct base address and started executing at the entry point, we then looked at what memory it was trying to access and where in the code that access was happening. This allowed us to go to that point in the code, understand what was going on and implement a few more details of the simulator to allow it to progress the execution further.

By doing this back and forth we found out the various memory regions and found the main lander control loop in the function at `0xbfc05774`. The control loop has four general regions: first there is an initial section at `0xbfc057f4`-`0xbfc05830` where the code signals to the sensors that it wants to read data. Then in the second phase at `0xbfc05834`-`0xbfc05a18` the code copies the sensor data from the MMIO region to RAM and also stores the previous value of three sensors. In the third section at `0xbfc05a1c`-`0xbfc05c7c` the code executes the main state machine where it will perform various actions and check different conditions depending on which stage of the descent the lander is in. This includes a PID regulator for the thruster. Finally, the fourth section at `0xbfc05c80`-`0xbfc05db8` performs some final checks and possibly calls a function to communicate with the hardware of the lander.

At this point we had a lot of different ideas about what could be wrong with the code. For example, maybe the parameters of the PID regulator was off or some checks related to altitude or velocity could be wrong. Here, someone in the team had the genius idea of reading Wikipedia about the incident that this challenge is based on: https://en.wikipedia.org/wiki/Mars_Polar_Lander. In that mission, vibrations caused the lander to believe that a touchdown had occurred while still being about 40 meters above ground.

To test if this was what was happening, we tried to NOP out the code at `0xbfc05c80`-`0xbfc05d1c` and run the firmware, now the lander successfully lands but the engine is never shut down which is required for a fully successful landing but this suggests that this is the issue. Looking more carefully at this code, we see that it roughly represents the following pseudo code:

```c
if (((prev_A && A) || (prev_B && B) || (prev_C && C)) && D) {
    eject_engine = 1;
}
```

The A, B, C and D variables here are the values read in the second phase mentioned above. We now both NOP:ed out the code like above but also added the following, starting at `0xbfc05c80`

```asm
li      $v0, 1           # Load Immediate
lbu     $v1, 0x14E8-0x14C8($fp)  # Load Byte Unsigned
and     $v0, $v1
lbu     $v1, 0x14E8-0x14C5($fp)  # Load Byte Unsigned
and     $v0, $v1
lbu     $v1, 0x14E8-0x14C7($fp)  # Load Byte Unsigned
and     $v0, $v1
lbu     $v1, 0x14E8-0x14C4($fp)  # Load Byte Unsigned
and     $v0, $v1
lbu     $v1, 0x14E8-0x14C6($fp)  # Load Byte Unsigned
and     $v0, $v1
lbu     $v1, 0x14E8-0x14C3($fp)  # Load Byte Unsigned
and     $v0, $v1
lbu     $v1, 0x14E8-0x14C1($fp)  # Load Byte Unsigned
and     $v0, $v1
beqz    $v0, skip  # Branch on Zero
nop
li      $v0, 1           # Load Immediate
sb      $v0, 0x14E8-0x14BE($fp)  # Store Byte
skip:
nop
```

which instead translates to something like:

```c
if (prev_A && A && prev_B && B && prev_C && C && D) {
    eject_engine = 1;
}
```

Running this new patched firmware with the simulator results in a successful landing and a flag.


Simulator code:
```python
#!/usr/bin/env python3

from __future__ import print_function
from unicorn import *
from unicorn.mips_const import *
import struct

BASE_ADDRESS = 0xBFC00000
RAM_ADDRESS  = 0xA0000000
STACK_BASE   = 0xA0100000
DATA_ADDRESS = 0xA0180000
DATA_SIZE    = 0x80000

REG_IO_CTRL = 0xa2000008
REG_IO_DATA = 0xa200000c

DATA_DMA_PTR = 0xA01805A0

DMA_OFFSET_VEL1 = 0
DMA_OFFSET_VEL2 = 1
DMA_OFFSET_ALT1 = 2
DMA_OFFSET_ALT2 = 3

DMA_OFFSET_FLAGS = 5

DMA_OFFSET_ACK1 = 0x1018
DMA_OFFSET_ACK2 = 0x101C
DMA_OFFSET_ACK3 = 0x1020

DMA_BASE = 0xa00feb64

class Sensors(object):
    def __init__(self, altitude, velocity):
        self.altitude = altitude
        self.velocity = velocity

with open('bad.rom', 'rb') as fin:
    rom = fin.read()


def hook_mem_invalid(uc, access, address, size, value, user_data):
    pc = mu.reg_read(UC_MIPS_REG_PC)
    print(">>> Missing memory is being WRITE at 0x%x (pc=%#x), data size = %u, data value = 0x%x" % (address, pc, size, value))
    return False


def hook_mem_access(uc, access, address, size, value, user_data):
    pc = mu.reg_read(UC_MIPS_REG_PC)
    sp = mu.reg_read(UC_MIPS_REG_SP)
    if access == UC_MEM_READ and address == REG_IO_CTRL:
        mu.mem_write(REG_IO_CTRL, struct.pack('<I', 3))
        return
    
    if access == UC_MEM_WRITE and address == REG_IO_DATA:
        output_data = struct.pack('<H', value)
        print('PRINT: %c' % output_data[0])
        #print('%c' % output_data[0], end='')
        return

    if address == (DMA_BASE + DMA_OFFSET_ALT1):
        mu.mem_write(DMA_BASE + DMA_OFFSET_ALT1, struct.pack('<I', 0))
    if address == (DMA_BASE + DMA_OFFSET_ALT2):
        mu.mem_write(DMA_BASE + DMA_OFFSET_ALT2, struct.pack('<I', 0))
    if address == (DMA_BASE + DMA_OFFSET_VEL1):
        mu.mem_write(DMA_BASE + DMA_OFFSET_VEL1, struct.pack('<I', 0))
    if address == (DMA_BASE + DMA_OFFSET_VEL2):
        mu.mem_write(DMA_BASE + DMA_OFFSET_VEL2, struct.pack('<I', 0))
    if address == (DMA_BASE + DMA_OFFSET_FLAGS):
        mu.mem_write(DMA_BASE + DMA_OFFSET_FLAGS, struct.pack('<I', 0))
    

    if address == (DMA_BASE + DMA_OFFSET_ACK3):
        mu.mem_write(DMA_BASE + DMA_OFFSET_ACK3, struct.pack('<I', 1))
        #return

    #if address >= DATA_ADDRESS and address < (DATA_ADDRESS + DATA_SIZE):
    #    return

    #if address >= RAM_ADDRESS and address < STACK_BASE:
    #    return

    #if address >= BASE_ADDRESS and address < (BASE_ADDRESS + len(rom)):
    #    return

    if True:
        if access == UC_MEM_WRITE:
            print(">>> Memory is being WRITE at 0x%x (pc=%#x, sp=%#x), data size = %u, data value = 0x%x" % (address, pc, sp, size, value))
        else:   # READ
            print(">>> Memory is being READ at 0x%x (pc=%#x, sp=%#x), data size = %u" % (address, pc, sp, size))

def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

    if address == 0xBFC05804:
        dma_ptr = struct.unpack('<I', uc.mem_read(DATA_DMA_PTR, 4))[0]
        #print('DMA PTR: %#x' % dma_ptr)


try:
    sensor = Sensors(8500, 500)
    mu = Uc(UC_ARCH_MIPS, UC_MODE_32)

    mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access, user_data=sensor)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, user_data=sensor)
    mu.hook_add(UC_HOOK_CODE, hook_code, user_data=sensor)

    mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)
    mu.mem_write(BASE_ADDRESS, rom)
    
    mu.mem_map(RAM_ADDRESS, 0x2000000) # RAM
    mu.mem_map(RAM_ADDRESS + 0x2000000, 0x2000000) # MMIO
    #mu.reg_write(UC_X86_REG_ECX, 0x1234)
    mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(rom))
    print("Emulation done. Below is the CPU context")
except UcError as e:
    print("ERROR: %s" % e)
    print(dir(e))
```