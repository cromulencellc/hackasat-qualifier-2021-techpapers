from pwn import *
from skyfield.api import load, EarthSatellite, wgs84
from skyfield.positionlib import ICRF
from astropy import units as u
from astropy.time import Time
import numpy as np
from scipy.spatial.transform import Rotation as R

ts = load.timescale()

spinny = EarthSatellite(
	"1 75001F 21750A   21177.00000000  .00000000  00000-0  00000-0 0   51",
	"2 75001  98.0875 274.0660 0000000   0.0000 359.9920 14.57890000 1100",
	"Spinny", ts
)

stations = {
"BANGALOR": wgs84.latlon(	13.0344, 	77.5116, 	823),
"GRIMSTAD": wgs84.latlon(	58.33, 		8.35,		211),
"SVALBARD": wgs84.latlon(	78.2307, 	15.3897, 	497),
"TROLLSAT": wgs84.latlon(	-72.0117, 	2.53838, 	1400),
"TROMSO": 	wgs84.latlon(	69.6625, 	18.9408, 	134)
}

at = Time("2021-06-26T00:00:00")
t = ts.from_astropy(at)

antenna_dir = np.array([1, 0, 0])

def format_time(t):
	s = str(t)
	s = s.replace("T", "-")
	s = s.replace(".000", "-UTC")
	return s

def can_transmit(spinny, station, t):
	sp = station.at(t).position.km
	pos = spinny.at(t).position.km
	alt, _, _ = (spinny - station).at(t).altaz()
	if alt.degrees <= 0: # Below horizon
		return False, None, None

	needed_dir = sp - pos
	needed_dir /= np.linalg.norm(needed_dir)

	dotp = np.dot(needed_dir, antenna_dir)
	if dotp > 0.71:	# Approx cos(45deg)
		#print(f"{sp=} {pos=} {needed_dir=} {antenna_dir=} {dotp=}")
		return True, needed_dir, np.arccos(dotp) * 180 / 3.1415
	return False, None, None

k = True
for i in range(12 * 60 * 60):
	#print(at, antenna_dir)

	t = ts.from_astropy(at)

	visible = any(can_transmit(spinny, stations[s], t)[0] for s in stations)
	
	if visible:
		k = True
		print(format_time(at), end=' ')

		for s in stations:
			sp = stations[s].at(t).position.km

			can, dir, ang = can_transmit(spinny, stations[s], t)
			if can:
				print(s, end=' ')

		print("")
	else:
		if k:
			k = False
			print("")

	antenna_dir = R.from_euler("zyx", [.1, .1, .1], degrees=True).apply(antenna_dir)

	at += 1 * u.s
