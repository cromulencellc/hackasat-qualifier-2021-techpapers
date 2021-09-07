from pwn import *
import numpy as np
import matplotlib.pyplot as plt

host = 'main-fleet.satellitesabove.me'
port = 5005
ticket = b'ticket{oscar327641mike2:GOUhxzNuzkMRrhhbiFJFe7TfARIjwqP1zeYcdvB0lPs95fvPOyBoJoPXRwlFmOUR0Q}'

r = remote(host, port)
data = r.recvuntil(b'Ticket please:')
r.sendline(ticket)

data = r.recvuntil(b'(Format answers as a single float):')
solar_const = 0.1361
R = 10
eff = 0.1
P = solar_const * eff
V = np.sqrt(P * R)

r.sendline(str(V))

print("VMAX:", V)

r.recvuntil("The final answer should be a unit vector")

# Dummy command so we get the prompt
r.sendline("r:5.7,5.7,5.7")
print(r.recvuntil("Z-Axis"))

def measure(rot):
    r.sendlineafter(">", "r:"+",".join(str(q) for q in rot))
    r.recvuntil("><")
    r.recvuntil(":")
    xp = float(r.recvline())
    r.recvuntil(":")
    yp = float(r.recvline())
    r.recvuntil(":")
    zp = float(r.recvline())
    r.recvuntil(":")
    xm = float(r.recvline())
    r.recvuntil(":")
    ym = float(r.recvline())
    r.recvuntil(":")
    zm = float(r.recvline())

    return xp / V, yp / V, zp / V, xm / V, ym / V, zm / V


m0 = measure([1,0,0, 0,1,0, 0,0,1])
m1 = measure([0,0,1, 1,0,0, 0,1,0]) # X->Z->Y->X
m2 = measure([0,1,0, 0,0,1, 1,0,0]) # X->Y->Z->X

# Sun direction
sxp = m0[0]
sxm = m0[3]
syp = m0[1]
sym = m0[4]
szp = m0[2]
szm = m0[5]

print(m0)
print(m1)
print(m2)

bad = None

# Y and Z sensors agree
if m0[1] == m1[2] != m2[0] and m1[1] == m2[2] != m0[0] and m2[1] == m0[2] != m1[0]:
    print("Bad X+!")
    bad = 'X+'
    sxp = m1[1]
    assert sxm == 0

# X and Z sensors agree
if m0[0] == m2[2] != m1[1] and m1[0] == m0[2] != m2[1] and m2[0] == m1[2] != m0[1]:
    print("Bad Y+!")
    bad = 'Y+'
    syp = m2[0]
    assert sym == 0

# X and Y sensors agree
if m0[0] == m1[1] != m2[2] and m1[0] == m2[1] != m0[2] and m2[0] == m0[1] != m1[2]:
    print("Bad Z+!")
    bad = 'Z+'
    szp = m1[0]
    assert szm == 0

sx = sxp if sxp != 0 else -sxm
sy = syp if syp != 0 else -sym
sz = szp if szp != 0 else -szm

assert sx > 0 and sy > 0 and sz > 0

print(sx, sy, sz, sx**2+sy**2+sz**2)

sun_exposure_matrix = [ # For each of the permutations, which component of the sun's direction interacts with which component of the panel's normal
    [sx, sy, sz],
    [sz, sx, sy],
    [sy, sz, sx]
]

b = None

if bad == 'X+':
    b = np.linalg.solve(sun_exposure_matrix, [m0[0], m1[0], m2[0]])

if bad == 'Y+': 
    b = np.linalg.solve(sun_exposure_matrix, [m0[1], m1[1], m2[1]])

if bad == 'Z+':
    b = np.linalg.solve(sun_exposure_matrix, [m0[2], m1[2], m2[2]])

print(b, np.linalg.norm(b))

r.sendline(f"s:{b[0]},{b[1]},{b[2]}")

r.interactive()

