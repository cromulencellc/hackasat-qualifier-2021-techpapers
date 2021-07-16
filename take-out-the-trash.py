from pwn import *
from skyfield.api import load
from astropy import units as u
from astropy.time import Time
from numpy.linalg import norm

satellites = load.tle_file("sats.tle")
enemies = load.tle_file("spacejunk.tle")

ts = load.timescale()
at = Time("2021-06-26T00:00:00.000")

num_kills = 0

r = remote("hard-coal.satellitesabove.me", 5007)
r.sendlineafter("Ticket please:", "ticket{hotel209537alpha2:GMaegL5BJcR0KeSWHZqvFFejCJefVHDxSM787BBYWRSNkMoz7lYiRFOFAoPGMNIIYw}")


def pewpew(sat, enemy, t):
	sp = sat.at(t).position.km
	ep = enemy.at(t).position.km
	dp = ep - sp

	dist = norm(dp)

	dp /= dist

	# https://stackoverflow.com/a/1171995
	# https://www.wolframalpha.com/input/?i=cross+product+%5Bx%2C+y%2C+z%5D+with+%5B0%2C+0%2C+1%5D
	qx = -dp[1]
	qy = dp[0]
	qz = 0
	qw = norm(dp) + dp[2]
	q_len = norm([qx, qy, qz, qw])
	qx /= q_len
	qy /= q_len
	qz /= q_len
	qw /= q_len

	utc = at.value
	ymd, hms = utc.split("T")
	y, m, d = ymd.split("-")
	h, mi, s = hms.split(":")
	s = s.split(".")[0]
	assert m == "06"
	assert y == "2021"

	formatted = "2021" + str(151 + int(d, 10)) + "." + h + mi + s

	print(f"{formatted} {sat.name.upper()} FIRE {qx} {qy} {qz} {qw} {dist}")
	r.sendlineafter(":", f"{formatted} {sat.name.upper()} FIRE {qx} {qy} {qz} {qw} {dist}")


while enemies:
	t = ts.from_astropy(at)

	pp = False
	for sat in satellites:
		for enemy in enemies:
			sp = sat.at(t).position.km
			ep = enemy.at(t).position.km
			dp = ep - sp
			dist = norm(dp)
			if dist < 100:
				pewpew(sat, enemy, t)
				pp = enemy
				break
		if pp:
			enemies.remove(pp)
			num_kills += 1
			break

	at += 60 * u.s

	if num_kills > 51:
		break

r.sendline("\n")

r.stream()
