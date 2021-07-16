from pwn import *

import orbital
import orbital.utilities
import numpy as np
from astropy.time import Time

p = remote("visual-sun.satellitesabove.me", 5014)
p.sendlineafter("Ticket please:", "ticket{xray886297whiskey2:GCzqvQP7x2wez8DKue95Dz5QhRkzNpVx8R_8Rbe8asTZZLNzi4wSaFBRA5WLl_aIpw}")


#p.interactive()

"""

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
Your spacecraft from the first Kepler challenge is in a GEO transfer elems.
Determine the maneuver (time and Δv vector) required to put the spacecraft into GEO-strationary elems: a=42164+/-10km, e<0.001, i<1deg.
Assume two-body elems dynamics and an instantaneous Δv in ICRF coordinates.
Pos (km):   [8449.401305, 9125.794363, -17.461357]
Vel (km/s): [-1.419072, 6.780149, 0.002865]
Time:       2021-06-26-19:20:00.000000-UTC

What maneuver is required?
Enter maneuver time in UTC following the example format.
Time: 2021-06-26-00:00:00.000-UTCTime: 
"""

p.recvuntil("Pos (km):   [")

x = float(p.recvuntil(", ", drop = True)) * 1000
y = float(p.recvuntil(", ", drop = True)) * 1000
z = float(p.recvuntil("]", drop = True)) * 1000

r = orbital.utilities.XyzVector(x, y, z)

print("CURRENT DISTANCE: ", (r.x**2 + r.y**2 + r.z**2)**.5)

p.recvuntil("Vel (km/s): [")

vx = float(p.recvuntil(", ", drop = True)) * 1000
vy = float(p.recvuntil(", ", drop = True)) * 1000
vz = float(p.recvuntil("]", drop = True)) * 1000

v = orbital.utilities.XyzVector(vx, vy, vz)

p.recvuntil("Time:       ")

tstr = p.recvline().strip().decode().replace("2021-06-26-", "2021-06-26T").replace("-UTC", "")
print(tstr)
t = Time(tstr, format='isot', scale='utc')
print(t)

elems = orbital.elements_from_state_vector(r, v, orbital.earth_mu)

orbit = orbital.KeplerianElements(elems.a, elems.e, elems.i, elems.raan, elems.arg_pe, orbital.utilities.mean_anomaly_from_true(elems.e, elems.f), orbital.bodies.earth, t)

maneuver = orbital.Maneuver.set_pericenter_radius_to(42130000) # fiddled with this a lot to get them both right; i dunno why the pyorbital maneuvers don't ctually do what you tell them

print(maneuver.operations)

from astropy.time import TimeDelta
dt = TimeDelta(maneuver.operations[0].time_delta(orbit), format='sec')


boof_time = t + dt

orbit.apply_maneuver(maneuver.operations[0])

print("\n\n\n -------------- RIGHT BEFORE BOOF -------------")

print(orbit)

boof_deltav = maneuver.operations[1].velocity_delta(orbit)

orbit.apply_maneuver(maneuver.operations[1])

print("\n\n\n -------------- AFTER BOOF -------------")
print(orbit)

print("TIME: ", boof_time)
print("DELTAV: ", boof_deltav)

p.sendlineafter("Time: ", str(boof_time).replace("T","-")+"-UTC")
p.sendlineafter("v_x", '{:.6f}'.format(boof_deltav[0]/1000))
p.sendlineafter("v_y", '{:.6f}'.format(boof_deltav[1]/1000))
p.sendlineafter("v_z", '{:.6f}'.format(boof_deltav[2]/1000))

p.interactive()
