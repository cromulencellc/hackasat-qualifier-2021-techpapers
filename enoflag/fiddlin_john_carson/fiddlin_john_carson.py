# requirements: pip3 install astropy poliastro
from astropy import units as u

from poliastro.bodies import Earth
from poliastro.twobody import Orbit
from astropy import time


r = [8449.401305, 9125.794363, -17.461357] * u.km
v = [-1.419072, 6.780149, 0.002865] * u.km / u.s
epoch = time.Time("2021-06-26 19:20:00")

orb = Orbit.from_vectors(Earth, r, v, epoch=epoch)

print('a: ', orb.a)
print('e: ', orb.ecc)
print('i: ', orb.inc.to(u.deg))
print('\u03A9: ', orb.raan.to(u.deg))
print('\u03C9: ', orb.argp.to(u.deg))
print('v: ', orb.nu.to(u.deg))