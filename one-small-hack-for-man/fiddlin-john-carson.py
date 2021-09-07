from pwn import *

import orbital
import orbital.utilities
import numpy as np

p = remote("derived-lamp.satellitesabove.me", 5013)
p.sendlineafter("Ticket please:", "ticket{victor851175golf2:GOI3Uj_aVntqDHZF6uewKnUW5T90-dBdgqeVGmvBWBFrbQvuMaBlmh-z1q-hrWG8cQ}")

"""

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
Semimajor axis, a (km):
"""

p.recvuntil("Pos (km):   [")

x = float(p.recvuntil(", ", drop = True)) * 1000
y = float(p.recvuntil(", ", drop = True)) * 1000
z = float(p.recvuntil("]", drop = True)) * 1000

r = orbital.utilities.XyzVector(x, y, z)

p.recvuntil("Vel (km/s): [")

vx = float(p.recvuntil(", ", drop = True)) * 1000
vy = float(p.recvuntil(", ", drop = True)) * 1000
vz = float(p.recvuntil("]", drop = True)) * 1000

v = orbital.utilities.XyzVector(vx, vy, vz)

p.recvuntil("Time:       ")

t = p.recvline().strip()

print(r, v)

elems = orbital.elements_from_state_vector(r, v, orbital.earth_mu)

print(elems)

a = elems.a / 1000
e = elems.e
i = elems.i * 180 / 3.141592643586535
Omega = elems.raan * 180 / 3.141592643586535
omega = elems.arg_pe * 180 / 3.141592643586535
nu = elems.f * 180 / 3.141592643586535

print(a, '{:.6f}'.format(a), e, i, Omega, omega, nu)

p.sendlineafter("Semimajor axis, a (km):", '{:.6f}'.format(a))
p.sendlineafter("Eccentricity, e:", '{:.6f}'.format(e))
p.sendlineafter("Inclination, i (deg): ", '{:.6f}'.format(i))
p.sendlineafter("Right ascension of the ascending node, Ω (deg):", '{:.6f}'.format(Omega))
p.sendlineafter("Argument of perigee, ω (deg):", '{:.6f}'.format(omega))
p.sendlineafter("True anomaly, υ (deg):", '{:.6f}'.format(nu))

p.interactive()

"""
mine 6218390.177262258 0.9999970109608497 0.11790360880074084 90.22650408704392 136.97753610982627 179.99987894747676
pyor                   0.9999970109608503 0.11790360880074084 90.22650408704392 136.97753610982622 179.99987893848729
"""
